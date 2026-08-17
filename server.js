#!/usr/bin/env node
/**
 * BurningHouse Auth — единый сервис авторизации для проектов на burninghouse.ru.
 *
 * Чистый Node.js, без внешних зависимостей и без npm install
 * (SQLite — встроенный модуль node:sqlite, требует Node 24+).
 *
 * Схема входа — упрощённый OAuth2 authorization code + PKCE:
 *
 *   сервис → GET /authorize?client_id&redirect_uri&state&code_challenge
 *          → форма логина (или сразу редирект, если на auth-домене уже есть кука)
 *          → возврат на redirect_uri?code=…&state=…
 *   сервис → POST /oauth/token (code + code_verifier) → access-JWT + refresh
 *          → дальше access проверяется сервисом ЛОКАЛЬНО по /.well-known/jwks.json,
 *            без сетевого запроса сюда на каждый чих.
 *
 * Запуск:            node server.js
 * Команды CLI:       node server.js help
 *
 * Переменные окружения — см. lib/config.js и README-deploy.md.
 */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const cfg = require("./lib/config");
const H = require("./lib/http");
const store = require("./lib/store");
const keys = require("./lib/keys");
const tokens = require("./lib/tokens");
const pwlib = require("./lib/passwords");
const mailer = require("./lib/mailer");
const mailTpl = require("./lib/emailTemplates");
const { db } = require("./lib/db");
const { checkAdminKey, createAdminLog } = require("./admin-internal");

const adminLog = createAdminLog(db);

const ROOT = __dirname;
const APP_HTML = path.join(ROOT, "index.html");

/* ---------- CLI ---------- */
if (process.argv[2]) {
  require("./lib/cli").run(process.argv.slice(2));
  return;
}

/* ---------- первичный сид ---------- */
keys.activeKey(); // при первом запуске создаст ключ подписи

// Клиенты можно завести заранее через env, чтобы docker compose up поднимал
// рабочую связку без ручных команд. Формат: JSON-массив
// [{"client_id":"finance","name":"Мои финансы","redirect_uris":[...],"origins":[...]}]
if (process.env.SEED_CLIENTS) {
  try {
    for (const c of JSON.parse(process.env.SEED_CLIENTS)) {
      store.upsertClient(c.client_id, c.name || c.client_id, c.redirect_uris || [], c.origins || []);
      console.log(`Клиент зарегистрирован: ${c.client_id}`);
    }
    store.invalidateOrigins();
  } catch (e) {
    console.error("SEED_CLIENTS: не удалось разобрать —", e.message);
  }
}

if (store.countUsers() === 0 && process.env.AUTH_USER && process.env.AUTH_PASS) {
  const err = pwlib.validateCreds(process.env.AUTH_USER, process.env.AUTH_PASS);
  if (err) console.error("AUTH_USER/AUTH_PASS: " + err);
  else {
    store.createUser(process.env.AUTH_USER, process.env.AUTH_PASS);
    console.log("Создан первый пользователь из AUTH_USER/AUTH_PASS: " + process.env.AUTH_USER.toLowerCase());
  }
}

/* ---------- лимиты ---------- */
const loginLimiter = H.createLimiter({ max: cfg.LOGIN_MAX_ATTEMPTS, windowMs: cfg.LOGIN_WINDOW });
const tokenLimiter = H.createLimiter({ max: 120, windowMs: 60 * 1000 });
const forgotLimiter = H.createLimiter({ max: 5, windowMs: 15 * 60 * 1000 });

setInterval(() => store.purgeExpired(), 60 * 60 * 1000).unref();

/* ---------- вспомогательное ---------- */

function serveApp(res, code = 200) {
  try {
    const body = fs.readFileSync(APP_HTML);
    res.writeHead(code, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(body);
  } catch {
    res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("index.html не найден рядом с server.js");
  }
}

/** Ошибку параметров /authorize НЕЛЬЗЯ редиректить обратно — показываем страницу. */
function errorPage(res, code, title, detail) {
  res.writeHead(code, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(`<!doctype html><meta charset="utf-8"><title>${H.escapeHtml(title)}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:15vh auto;padding:0 1.5rem;color:#1b1b1f;background:#fdfcff}
h1{font-size:1.4rem}code{background:#eceef4;padding:.1em .35em;border-radius:.25em}
@media(prefers-color-scheme:dark){body{background:#131316;color:#e5e1e6}code{background:#2a2a30}}</style>
<h1>${H.escapeHtml(title)}</h1><p>${H.escapeHtml(detail)}</p>`);
}

/**
 * Разбор и валидация параметров авторизации. Источник (query или тело POST)
 * не важен — правила одни и те же, форме на слово не верим.
 */
function parseAuthorizeParams(src) {
  const get = k => String((typeof src.get === "function" ? src.get(k) : src[k]) || "");
  const clientId = get("client_id");
  if (!clientId) return { error: "no_client", detail: "Не указан client_id." };

  const client = store.getClient(clientId);
  if (!client) return { error: "unknown_client", detail: `Сервис «${clientId}» не зарегистрирован в auth.` };

  const redirectUri = get("redirect_uri");
  if (!store.redirectAllowed(client, redirectUri)) {
    return { error: "bad_redirect", detail: "redirect_uri не совпадает ни с одним зарегистрированным для этого сервиса." };
  }

  const codeChallenge = get("code_challenge");
  const method = get("code_challenge_method");
  if (!codeChallenge || method !== "S256") {
    return { error: "bad_pkce", detail: "Требуется code_challenge с code_challenge_method=S256." };
  }

  return { ok: true, client, redirectUri, state: get("state"), codeChallenge };
}

function buildRedirect(redirectUri, code, state) {
  const u = new URL(redirectUri);
  u.searchParams.set("code", code);
  if (state) u.searchParams.set("state", state);
  return u.toString();
}

function ssoFromRequest(req) {
  const row = store.getSso(H.cookies(req)[cfg.COOKIE_NAME]);
  if (row) store.touchSso(row);
  return row;
}

/** Пользователь запроса: сначала Bearer access-токен, иначе SSO-кука (страницы самого auth). */
function authenticate(req) {
  const t = H.bearer(req);
  if (t) {
    const p = tokens.verifyAccess(t);
    if (!p) return null;
    const u = store.getUserById(p.sub);
    return u && !u.disabled ? { user: u, via: "token", sid: p.sid } : null;
  }
  const sso = ssoFromRequest(req);
  if (!sso) return null;
  const u = store.getUserById(sso.user_id);
  return u && !u.disabled ? { user: u, via: "cookie", ssoId: sso.id } : null;
}

/** Общая часть логина и регистрации: кука + либо код авторизации, либо возврат на аккаунт. */
function completeLogin(req, res, user, params) {
  const ssoId = store.createSso(user.id, { userAgent: H.userAgent(req), ip: H.clientIp(req) });
  H.setCookie(res, cfg.COOKIE_NAME, ssoId, { maxAge: cfg.SSO_TTL });

  if (!params) return H.json(res, 200, { ok: true, redirect: "/", user: store.publicUser(user) });

  const code = store.createCode({
    userId: user.id,
    clientId: params.client.client_id,
    redirectUri: params.redirectUri,
    codeChallenge: params.codeChallenge,
    ssoId,
  });
  return H.json(res, 200, { ok: true, redirect: buildRedirect(params.redirectUri, code, params.state), user: store.publicUser(user) });
}

/** Общая точка отправки письма подтверждения — регистрация, смена/добавление
 *  почты в кабинете и повторная отправка дёргают одно и то же. */
function sendVerificationEmail(userId, email) {
  const token = store.createEmailVerification(userId, email);
  const link = `${cfg.ISSUER}/verify-email?token=${token}`;
  const mail = mailTpl.emailVerify({ link });
  mailer.send({ to: email, subject: mail.subject, html: mail.html, text: mail.text });
}

/* ---------- маршруты ---------- */

// /api/friends — только сам список (GET), не мутации: другому сервису (Trip
// и т.п.) можно предложить друзей из BurningHouse по чужому access-токену,
// но добавлять/принимать/удалять — только с самого auth-домена (см. ниже,
// эти пути под /api/friends/... своего "$" нарочно не получают).
const CORS_PATHS = /^(\/oauth\/|\/api\/userinfo$|\/api\/friends$|\/\.well-known\/)/;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, cfg.ISSUER);
  const p = url.pathname;
  const method = req.method;

  // CORS — только для эндпоинтов, к которым ходят фронты других сервисов.
  if (CORS_PATHS.test(p)) {
    if (!H.cors(req, res, store.allowedOrigins())) return H.json(res, 403, { error: "origin_not_allowed" });
    if (method === "OPTIONS") { res.writeHead(204); return res.end(); }
  }

  try {
    /* --- служебное --- */

    if (p === "/api/health") return H.json(res, 200, { ok: true });

    if (p === "/.well-known/jwks.json" && method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=3600" });
      return res.end(JSON.stringify(keys.jwks()));
    }

    if (p === "/.well-known/openid-configuration" && method === "GET") {
      return H.json(res, 200, {
        issuer: cfg.ISSUER,
        authorization_endpoint: cfg.ISSUER + "/authorize",
        token_endpoint: cfg.ISSUER + "/oauth/token",
        revocation_endpoint: cfg.ISSUER + "/oauth/revoke",
        userinfo_endpoint: cfg.ISSUER + "/api/userinfo",
        end_session_endpoint: cfg.ISSUER + "/logout",
        jwks_uri: cfg.ISSUER + "/.well-known/jwks.json",
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: ["EdDSA"],
      });
    }

    /* --- SSO: страница авторизации --- */

    if (p === "/authorize" && method === "GET") {
      const params = parseAuthorizeParams(url.searchParams);
      if (!params.ok) return errorPage(res, 400, "Некорректный запрос авторизации", params.detail);

      const sso = ssoFromRequest(req);
      const user = sso ? store.getUserById(sso.user_id) : null;
      // Без почты — сначала мягкое окошко «добавьте и подтвердите», а не молчаливый
      // редирект: без него человек так и не узнает, что почты у него нет, пока
      // не понадобится восстановить пароль. Пропустить можно — email_prompt_dismissed
      // не даёт спросить повторно в течение той же SSO-сессии.
      if (user && !user.disabled && (user.email || sso.email_prompt_dismissed) && url.searchParams.get("prompt") !== "login") {
        // Уже вошёл на auth-домене — это и есть SSO: пароль второй раз не спрашиваем.
        const code = store.createCode({
          userId: user.id,
          clientId: params.client.client_id,
          redirectUri: params.redirectUri,
          codeChallenge: params.codeChallenge,
          ssoId: sso.id,
        });
        res.writeHead(302, { Location: buildRedirect(params.redirectUri, code, params.state), "Cache-Control": "no-store" });
        return res.end();
      }
      return serveApp(res); // форма логина; параметры страница возьмёт из своего же URL
    }

    if ((p === "/api/authorize/login" || p === "/api/authorize/register") && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const body = await H.readParams(req);

      // Параметры сервиса необязательны: можно логиниться прямо на auth-домене.
      let params = null;
      if (body.client_id) {
        const parsed = parseAuthorizeParams(body);
        if (!parsed.ok) return H.json(res, 400, { error: parsed.error, message: parsed.detail });
        params = parsed;
      }

      const username = pwlib.normalizeUsername(body.username);
      const limitKey = H.clientIp(req) + "|" + username;
      if (loginLimiter.hit(limitKey)) return H.json(res, 429, { error: "too_many_attempts", message: "Слишком много попыток. Попробуйте через 15 минут." });

      if (p === "/api/authorize/login") {
        // Логин ИЛИ почта — так же принимает и «Забыли пароль?» ниже.
        const user = store.checkPassword(store.getUserByIdentifier(body.username), String(body.password || ""));
        if (!user) return H.json(res, 401, { error: "bad_credentials", message: "Неверный логин или пароль" });
        loginLimiter.reset(limitKey);
        return completeLogin(req, res, user, params);
      }

      // регистрация
      if (cfg.REGISTER_CLOSED) return H.json(res, 403, { error: "register_closed", message: "Регистрация закрыта" });
      if (cfg.REGISTER_CODE && body.code !== cfg.REGISTER_CODE) return H.json(res, 401, { error: "bad_code", message: "Неверный код приглашения" });

      const err = pwlib.validateCreds(body.username, body.password);
      if (err) return H.json(res, 400, { error: "invalid", message: err });
      const email = pwlib.normalizeEmail(body.email);
      // Обязательна для новых аккаунтов — без неё некуда слать ссылку сброса
      // пароля (см. /api/authorize/forgot ниже). У аккаунтов, заведённых до
      // этого требования (или через CLI adduser), почты может не быть — им
      // сброс по ссылке недоступен, пока не добавят её в кабинете.
      if (!email) return H.json(res, 400, { error: "invalid", message: "Укажите почту" });
      const emailErr = pwlib.validateEmail(email);
      if (emailErr) return H.json(res, 400, { error: "invalid", message: emailErr });
      if (store.getUserByName(username)) return H.json(res, 409, { error: "user_exists", message: "Такой логин уже занят" });
      if (email && store.getUserByEmail(email)) return H.json(res, 409, { error: "email_exists", message: "Эта почта уже привязана к другому аккаунту" });

      const phone = pwlib.normalizePhone(body.phone);
      const phoneErr = pwlib.validatePhone(phone);
      if (phoneErr) return H.json(res, 400, { error: "invalid", message: phoneErr });
      if (phone && store.getUserByPhone(phone)) return H.json(res, 409, { error: "phone_exists", message: "Этот телефон уже привязан к другому аккаунту" });

      const displayName = pwlib.normalizeDisplayName(body.displayName);
      const user = store.createUser(username, body.password, email, displayName, !!body.showDisplayName, phone, !!body.sharePhone);
      sendVerificationEmail(user.id, email);
      loginLimiter.reset(limitKey);
      return completeLogin(req, res, user, params);
    }

    // Запрос ссылки сброса. Ответ ВСЕГДА одинаковый, нашёлся аккаунт или нет
    // (и есть ли у него почта) — иначе форма превращается в способ проверить,
    // кто зарегистрирован. Настоящая причина неудачи — только в логах сервера.
    if (p === "/api/authorize/forgot" && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      if (forgotLimiter.hit(H.clientIp(req))) return H.json(res, 429, { error: "too_many_attempts", message: "Слишком много попыток. Попробуйте позже." });
      const body = await H.readParams(req);

      const user = store.getUserByIdentifier(body.username);
      // email_verified — иначе кто угодно мог бы вписать чужой адрес в
      // непроверенное поле и получать чужие ссылки восстановления.
      if (user && !user.disabled && user.email && user.email_verified) {
        const token = store.createPasswordReset(user.id);
        const link = `${cfg.ISSUER}/reset?token=${token}`;
        const mail = mailTpl.passwordReset({ link });
        mailer.send({ to: user.email, subject: mail.subject, html: mail.html, text: mail.text });
      }
      return H.json(res, 200, { ok: true });
    }

    // Сама смена пароля по токену из письма — личность подтверждает токен,
    // текущий пароль знать не нужно (в этом и смысл сброса).
    if (p === "/api/authorize/reset" && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const body = await H.readParams(req);

      const r = store.consumePasswordReset(body.token);
      if (r.error) return H.json(res, 400, { error: r.error, message: "Ссылка недействительна или уже использована" });

      const err = pwlib.validatePassword(body.password);
      if (err) return H.json(res, 400, { error: "invalid", message: err });

      store.setPassword(r.userId, body.password);
      // В отличие от смены пароля из кабинета (там остаётся текущее
      // устройство — человек и так знал старый пароль), здесь неизвестно,
      // какое устройство «своё»: гасим всё, включая браузерную SSO-куку —
      // так же, как logout-all в CLI.
      store.revokeAllSessions(r.userId, "password-reset");
      for (const s of store.listSso(r.userId)) store.revokeSso(s.id);
      store.markResetUsed(r.tokenHash);
      return H.json(res, 200, { ok: true });
    }

    if (p === "/logout") {
      const sso = ssoFromRequest(req);
      if (sso) store.revokeSso(sso.id);
      H.setCookie(res, cfg.COOKIE_NAME, "", { clear: true });

      // Куда вернуть — только на origin зарегистрированного сервиса или к нам же.
      const back = url.searchParams.get("post_logout_redirect_uri") || "";
      let target = "/";
      if (back) {
        try {
          const u = new URL(back);
          if (store.allowedOrigins().has(u.origin) || u.origin === cfg.ISSUER) target = u.toString();
        } catch { /* оставляем "/" */ }
      }
      if (method === "POST") return H.json(res, 200, { ok: true, redirect: target });
      res.writeHead(302, { Location: target, "Cache-Control": "no-store" });
      return res.end();
    }

    /* --- обмен токенов --- */

    if (p === "/oauth/token" && method === "POST") {
      if (tokenLimiter.hit(H.clientIp(req))) return H.json(res, 429, { error: "slow_down" });
      const body = await H.readParams(req);
      const grant = String(body.grant_type || "");

      if (grant === "authorization_code") {
        const client = store.getClient(body.client_id);
        if (!client) return H.json(res, 400, { error: "invalid_client" });

        const r = store.consumeCode(String(body.code || ""), {
          clientId: client.client_id,
          redirectUri: String(body.redirect_uri || ""),
          codeVerifier: String(body.code_verifier || ""),
        });
        if (r.error) return H.json(res, 400, { error: r.error });

        const user = store.getUserById(r.code.user_id);
        if (!user || user.disabled) return H.json(res, 400, { error: "invalid_grant" });

        const session = store.createSession({
          userId: user.id,
          clientId: client.client_id,
          ssoId: r.code.sso_id,
          userAgent: H.userAgent(req),
          ip: H.clientIp(req),
        });
        store.markCodeUsed(r.code.code_hash, session.id);

        return H.json(res, 200, {
          token_type: "Bearer",
          access_token: tokens.issueAccess(user, client.client_id, session.id),
          expires_in: Math.floor(cfg.ACCESS_TTL / 1000),
          refresh_token: session.refresh,
          user: store.publicUser(user),
        });
      }

      if (grant === "refresh_token") {
        const r = store.rotateRefresh(String(body.refresh_token || ""));
        if (r.error) {
          const code = r.error === "refresh_reused" ? 401 : 401;
          return H.json(res, code, { error: r.error });
        }
        const user = store.getUserById(r.session.user_id);
        if (!user || user.disabled) {
          store.revokeSession(r.session.id, "user-disabled");
          return H.json(res, 401, { error: "invalid_grant" });
        }
        return H.json(res, 200, {
          token_type: "Bearer",
          access_token: tokens.issueAccess(user, r.session.client_id, r.session.id),
          expires_in: Math.floor(cfg.ACCESS_TTL / 1000),
          refresh_token: r.refresh,
          user: store.publicUser(user),
        });
      }

      return H.json(res, 400, { error: "unsupported_grant_type" });
    }

    if (p === "/oauth/revoke" && method === "POST") {
      const body = await H.readParams(req);
      store.revokeByRefresh(String(body.refresh_token || ""));
      return H.json(res, 200, { ok: true }); // намеренно всегда ok: не подсказываем, существовал ли токен
    }

    /* --- аккаунт --- */

    if (p === "/api/userinfo" && method === "GET") {
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      return H.json(res, 200, store.publicUser(auth.user));
    }

    // Название сервиса для заголовка формы («Вход в „Мои финансы“»). id клиента и так
    // виден в адресной строке — секрета тут нет.
    if (p === "/api/client" && method === "GET") {
      const c = store.getClient(url.searchParams.get("client_id"));
      if (!c) return H.json(res, 404, { error: "unknown_client" });
      return H.json(res, 200, { client_id: c.client_id, name: c.name });
    }

    // Кто вошёл в браузере — этим страница аккаунта решает, что показывать.
    // profile отдаём ТОЛЬКО здесь, не в publicUser(): этот эндпоинт — всегда
    // про самого себя (аутентификация уже проверена выше), а publicUser() уходит
    // в том числе другим сервисам, и сырое имя им видно быть не должно, пока
    // владелец сам не включил показ (см. computedName в lib/store.js).
    if (p === "/api/session" && method === "GET") {
      const auth = authenticate(req);
      if (!auth) return H.json(res, 200, { authenticated: false, registerClosed: cfg.REGISTER_CLOSED, registerCode: !!cfg.REGISTER_CODE });
      return H.json(res, 200, { authenticated: true, user: store.publicUser(auth.user), profile: store.ownProfile(auth.user) });
    }

    if (p === "/api/account/password" && method === "PUT") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const body = await H.readParams(req);

      if (loginLimiter.hit(H.clientIp(req) + "|pw|" + auth.user.username)) return H.json(res, 429, { error: "too_many_attempts" });
      if (!store.checkPassword(auth.user, String(body.currentPassword || "")))
        return H.json(res, 401, { error: "bad_credentials", message: "Неверный текущий пароль" });

      const err = pwlib.validateCreds(auth.user.username, body.newPassword);
      if (err) return H.json(res, 400, { error: "invalid", message: err });

      store.setPassword(auth.user.id, body.newPassword);
      // Смена пароля выкидывает все прочие устройства, текущее остаётся.
      store.revokeOtherSessions(auth.user.id, auth.sid || "", "password-change");
      return H.json(res, 200, { ok: true });
    }

    if (p === "/api/account/email" && method === "PUT") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const body = await H.readParams(req);

      // Пароль спрашиваем только при СМЕНЕ уже привязанной почты — если её
      // ещё нет, добавить в первый раз не опаснее, чем указать при регистрации
      // (там пароль тоже не переспрашивают). Именно этим пользуется мягкое
      // окошко «добавьте почту» при входе в сервис — см. /authorize выше.
      if (auth.user.email && !store.checkPassword(auth.user, String(body.password || "")))
        return H.json(res, 401, { error: "bad_credentials", message: "Неверный пароль" });

      const email = pwlib.normalizeEmail(body.email);
      const err = pwlib.validateEmail(email);
      if (err) return H.json(res, 400, { error: "invalid", message: err });
      const taken = email && store.getUserByEmail(email);
      if (taken && taken.id !== auth.user.id) return H.json(res, 409, { error: "email_exists", message: "Эта почта уже привязана к другому аккаунту" });

      store.setEmail(auth.user.id, email);
      if (email) sendVerificationEmail(auth.user.id, email);
      return H.json(res, 200, { ok: true, email });
    }

    // Повторная отправка письма — на случай, если первое затерялось (спам,
    // опечатка в момент отправки уже исключена: письмо шло на ту же почту).
    if (p === "/api/account/email/resend" && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      if (!auth.user.email) return H.json(res, 400, { error: "no_email", message: "Сначала укажите почту" });
      if (auth.user.email_verified) return H.json(res, 200, { ok: true }); // уже подтверждена — присылать нечего
      sendVerificationEmail(auth.user.id, auth.user.email);
      return H.json(res, 200, { ok: true });
    }

    // Подтверждение по ссылке — токен сам удостоверяет личность, авторизация
    // на сайте не нужна (письмо могли открыть на другом устройстве).
    if (p === "/api/account/email/confirm" && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const body = await H.readParams(req);
      const r = store.consumeEmailVerification(body.token);
      if (r.error) return H.json(res, 400, { error: r.error, message: "Ссылка недействительна или уже использована" });

      const user = store.getUserById(r.userId);
      // Почта на аккаунте могла смениться уже ПОСЛЕ отправки этого письма —
      // тогда токен относится к адресу, которого на аккаунте больше нет.
      if (!user || user.email !== r.email) return H.json(res, 400, { error: "email_changed", message: "Почта на аккаунте с тех пор изменилась — запросите ссылку заново" });

      store.markEmailVerified(user.id);
      store.markVerifyUsed(r.tokenHash);
      return H.json(res, 200, { ok: true });
    }

    // «Пропустить» на окошке добавления почты — не показывать его снова в
    // рамках этой же SSO-сессии (см. /authorize выше).
    if (p === "/api/account/email/dismiss" && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth || auth.via !== "cookie") return H.json(res, 401, { error: "unauthorized" });
      store.dismissEmailPrompt(auth.ssoId);
      return H.json(res, 200, { ok: true });
    }

    // Телефон — задел под будущую интеграцию с СБП, поэтому в отличие от
    // имени меняется, как почта, с подтверждением текущим паролем: это уже
    // не косметика, а платёжно-значимые данные.
    if (p === "/api/account/phone" && method === "PUT") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const body = await H.readParams(req);

      if (!store.checkPassword(auth.user, String(body.password || "")))
        return H.json(res, 401, { error: "bad_credentials", message: "Неверный пароль" });

      const phone = pwlib.normalizePhone(body.phone);
      const err = pwlib.validatePhone(phone);
      if (err) return H.json(res, 400, { error: "invalid", message: err });
      const taken = phone && store.getUserByPhone(phone);
      if (taken && taken.id !== auth.user.id) return H.json(res, 409, { error: "phone_exists", message: "Этот телефон уже привязан к другому аккаунту" });

      store.setPhone(auth.user.id, phone, !!body.sharePhone);
      // shared — то, что реально уйдёт сервисам (null, если делиться выключили
      // или номер стёрли), а не сырое значение из body — фронт должен видеть
      // именно результат применения флага, а не то, что просто отправил.
      const shared = store.publicUser(store.getUserById(auth.user.id)).phone;
      return H.json(res, 200, { ok: true, phone, shared });
    }

    // Имя — некритичная косметика (в отличие от пароля/почты никого никуда не
    // пускает и не служит контактом), поэтому в отличие от них меняется без
    // подтверждения текущим паролем.
    if (p === "/api/account/profile" && method === "PUT") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const body = await H.readParams(req);

      const displayName = pwlib.normalizeDisplayName(body.displayName);
      store.setProfile(auth.user.id, displayName, !!body.showDisplayName);
      // Отдаём готовое к показу имя сразу, чтобы фронт обновил "Вы вошли как…"
      // без повторного похода за /api/session.
      const name = store.publicUser(store.getUserById(auth.user.id)).name;
      return H.json(res, 200, { ok: true, name });
    }

    if (p === "/api/account/sessions" && method === "GET") {
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const clients = Object.fromEntries(store.listClients().map(c => [c.client_id, c.name]));
      return H.json(res, 200, {
        current: { sid: auth.sid || null, ssoId: auth.ssoId || null },
        browsers: store.listSso(auth.user.id).map(s => ({
          id: s.id, kind: "browser", createdAt: s.created_at, lastSeen: s.last_seen, userAgent: s.user_agent,
        })),
        apps: store.listSessions(auth.user.id).map(s => ({
          id: s.id, kind: "app", clientId: s.client_id, clientName: clients[s.client_id] || s.client_id,
          createdAt: s.created_at, lastSeen: s.last_seen, userAgent: s.user_agent,
        })),
      });
    }

    const sessionMatch = p.match(/^\/api\/account\/sessions\/([\w-]+)$/);
    if (sessionMatch && method === "DELETE") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const id = sessionMatch[1];

      const app = store.getSession(id);
      if (app && app.user_id === auth.user.id) { store.revokeSession(id, "user-revoked"); return H.json(res, 200, { ok: true }); }
      const sso = store.getSso(id);
      if (sso && sso.user_id === auth.user.id) {
        store.revokeSso(id);
        if (auth.ssoId === id) H.setCookie(res, cfg.COOKIE_NAME, "", { clear: true });
        return H.json(res, 200, { ok: true });
      }
      return H.json(res, 404, { error: "not_found" });
    }

    if (p === "/api/account/sessions" && method === "DELETE") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      store.revokeAllSessions(auth.user.id, "user-revoked-all");
      return H.json(res, 200, { ok: true });
    }

    // Удаление аккаунта — безвозвратно. Пароль повторно не спрашиваем (сессия
    // уже аутентифицирована), подтверждение — набрать свой логин вручную,
    // как GitHub просит набрать имя репозитория перед удалением: не секрет,
    // а страховка от клика мимо на уставшую голову.
    if (p === "/api/account" && method === "DELETE") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const body = await H.readParams(req);

      if (pwlib.normalizeUsername(body.username) !== auth.user.username)
        return H.json(res, 400, { error: "invalid", message: "Логин введён неверно" });

      store.deleteUser(auth.user.id);
      H.setCookie(res, cfg.COOKIE_NAME, "", { clear: true });
      return H.json(res, 200, { ok: true });
    }

    /* --- друзья --- */

    const FRIEND_ERR = {
      self: "Нельзя добавить в друзья самого себя",
      already_friends: "Вы уже друзья",
      already_requested: "Заявка уже отправлена",
      not_found: "Заявка не найдена",
      cant_accept_own: "Нельзя принять собственную заявку",
    };

    // GET, не мутация — единственный путь из /api/friends/*, доступный другим
    // сервисам по Bearer-токену (см. CORS_PATHS выше), не только с cookie.
    if (p === "/api/friends" && method === "GET") {
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      return H.json(res, 200, {
        friends: store.listFriends(auth.user.id),
        incoming: store.listIncomingRequests(auth.user.id),
        outgoing: store.listOutgoingRequests(auth.user.id),
        inviteLink: `${cfg.ISSUER}/friends/invite?token=${store.getOrCreateInviteToken(auth.user.id)}`,
      });
    }

    if (p === "/api/friends/request" && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const body = await H.readParams(req);

      const target = store.getUserByName(pwlib.normalizeUsername(body.username));
      if (!target || target.disabled) return H.json(res, 404, { error: "not_found", message: "Такого логина нет" });

      const r = store.sendFriendRequest(auth.user.id, target.id);
      if (r.error) return H.json(res, 409, { error: r.error, message: FRIEND_ERR[r.error] || "Не удалось отправить заявку" });
      return H.json(res, 200, { ok: true, accepted: !!r.accepted });
    }

    if (p === "/api/friends/invite/regenerate" && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });

      const token = store.regenerateInviteToken(auth.user.id);
      return H.json(res, 200, { ok: true, inviteLink: `${cfg.ISSUER}/friends/invite?token=${token}` });
    }

    // Переход по чужой персональной ссылке — сразу дружба, без отдельного
    // подтверждения (см. чат: «перешёл и вошёл — сразу друг», как в Trip).
    if (p === "/api/friends/invite/accept" && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });
      const body = await H.readParams(req);

      const owner = store.getUserByInviteToken(body.token);
      if (!owner || owner.disabled) return H.json(res, 404, { error: "not_found", message: "Ссылка недействительна" });

      const r = store.acceptFriendInvite(auth.user.id, owner.id);
      if (r.error && r.error !== "already_friends") return H.json(res, 409, { error: r.error, message: FRIEND_ERR[r.error] });
      return H.json(res, 200, {
        ok: true, already: r.error === "already_friends",
        friend: { username: owner.username, name: owner.display_name || owner.username },
      });
    }

    // /accept идёт РАНЬШЕ общего /api/friends/:id — иначе не различить
    // /api/friends/<id>/accept и просто /api/friends/<id>.
    const friendAcceptMatch = p.match(/^\/api\/friends\/([\w-]+)\/accept$/);
    if (friendAcceptMatch && method === "POST") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });

      const r = store.acceptFriendRequest(friendAcceptMatch[1], auth.user.id);
      if (r.error) return H.json(res, 404, { error: r.error, message: FRIEND_ERR[r.error] || "Заявка не найдена" });
      return H.json(res, 200, { ok: true });
    }

    // Одна ручка на «отклонить входящую», «отменить исходящую» и «удалить из
    // друзей» — везде физически одна и та же строка связи, см. store.js.
    const friendMatch = p.match(/^\/api\/friends\/([\w-]+)$/);
    if (friendMatch && method === "DELETE") {
      if (!H.sameOrigin(req)) return H.json(res, 403, { error: "bad_origin" });
      const auth = authenticate(req);
      if (!auth) return H.json(res, 401, { error: "unauthorized" });

      const removed = store.removeFriendship(friendMatch[1], auth.user.id);
      if (!removed) return H.json(res, 404, { error: "not_found" });
      return H.json(res, 200, { ok: true });
    }

    /* --- внутренние ручки для Admin: server-to-server, проверка общим
       ключом (см. admin-internal.js), а не SSO-токеном пользователя --- */

    if (p === "/internal/stats" && method === "GET") {
      if (!checkAdminKey(req)) return H.json(res, 403, { error: "forbidden" });
      const now = Date.now();
      return H.json(res, 200, {
        ok: true,
        users: store.countUsers(),
        admins: store.countAdmins(),
        clients: store.listClients().length,
        activeSessions: store.countActiveSessions(),
        activeBrowsers: store.countActiveSso(),
        newUsers24h: store.countUsersSince(now - 24 * 60 * 60 * 1000),
        newUsers7d: store.countUsersSince(now - 7 * 24 * 60 * 60 * 1000),
      });
    }

    if (p === "/internal/users" && method === "GET") {
      if (!checkAdminKey(req)) return H.json(res, 403, { error: "forbidden" });
      return H.json(res, 200, {
        users: store.listUsers().map(u => ({
          id: u.id, username: u.username, email: u.email || null,
          createdAt: u.created_at, disabled: !!u.disabled, admin: !!u.is_admin,
        })),
      });
    }

    const userAdminMatch = p.match(/^\/internal\/users\/([\w-]+)\/admin$/);
    if (userAdminMatch && method === "POST") {
      if (!checkAdminKey(req)) return H.json(res, 403, { error: "forbidden" });
      const u = store.getUserById(userAdminMatch[1]);
      if (!u) return H.json(res, 404, { error: "not_found" });
      const body = await H.readParams(req);
      store.setAdmin(u.id, !!body.on);
      adminLog.info(`${body.on ? "Выдан" : "Отозван"} доступ в Admin`, { username: u.username });
      return H.json(res, 200, { ok: true });
    }

    const userDisabledMatch = p.match(/^\/internal\/users\/([\w-]+)\/disabled$/);
    if (userDisabledMatch && method === "POST") {
      if (!checkAdminKey(req)) return H.json(res, 403, { error: "forbidden" });
      const u = store.getUserById(userDisabledMatch[1]);
      if (!u) return H.json(res, 404, { error: "not_found" });
      const body = await H.readParams(req);
      store.setDisabled(u.id, !!body.on);
      // Блокировка входа сама сессии не гасит (как в CLI) — для Admin это
      // нежелательный сюрприз, поэтому здесь, в отличие от CLI, гасим сразу.
      if (body.on) store.revokeAllSessions(u.id, "admin-disabled");
      adminLog.warn(`${body.on ? "Заблокирован" : "Разблокирован"} вход`, { username: u.username });
      return H.json(res, 200, { ok: true });
    }

    const userLogoutMatch = p.match(/^\/internal\/users\/([\w-]+)\/logout-all$/);
    if (userLogoutMatch && method === "POST") {
      if (!checkAdminKey(req)) return H.json(res, 403, { error: "forbidden" });
      const u = store.getUserById(userLogoutMatch[1]);
      if (!u) return H.json(res, 404, { error: "not_found" });
      store.revokeAllSessions(u.id, "admin");
      for (const s of store.listSso(u.id)) store.revokeSso(s.id);
      adminLog.info("Принудительный выход из всех устройств", { username: u.username });
      return H.json(res, 200, { ok: true });
    }

    // Удаление аккаунта из Admin — безвозвратно, каскад по FK (см. lib/db.js)
    // сам уносит сессии/коды/сбросы пароля. Финансовые/бытовые данные в других
    // сервисах не трогает: они завязаны на user_id, а не на существование
    // записи в Auth, и это уборка отдельного порядка, не эта ручка.
    const userDeleteMatch = p.match(/^\/internal\/users\/([\w-]+)$/);
    if (userDeleteMatch && method === "DELETE") {
      if (!checkAdminKey(req)) return H.json(res, 403, { error: "forbidden" });
      const u = store.getUserById(userDeleteMatch[1]);
      if (!u) return H.json(res, 404, { error: "not_found" });
      store.deleteUser(u.id);
      adminLog.warn("Аккаунт удалён", { username: u.username, id: u.id });
      return H.json(res, 200, { ok: true });
    }

    if (p === "/internal/logs" && method === "GET") {
      if (!checkAdminKey(req)) return H.json(res, 403, { error: "forbidden" });
      const since = url.searchParams.get("since");
      const limit = url.searchParams.get("limit");
      return H.json(res, 200, {
        logs: adminLog.recent({ since: since ? Number(since) : undefined, limit: limit ? Number(limit) : undefined }),
      });
    }

    /* --- статика и страница --- */

    if (method === "GET") {
      if (H.serveStatic(res, p, ROOT)) return;
      if (p === "/" || p === "/index.html" || p === "/reset" || p === "/verify-email" || p === "/friends/invite") return serveApp(res);
      return errorPage(res, 404, "Страница не найдена", "Проверьте адрес.");
    }

    return H.json(res, 405, { error: "method_not_allowed" });
  } catch (e) {
    console.error("Необработанная ошибка:", e);
    adminLog.error("Необработанная ошибка", { path: p, method, message: e.message });
    if (!res.headersSent) return H.json(res, 500, { error: "server_error" });
    res.end();
  }
});

server.listen(cfg.PORT, cfg.HOST, () => {
  console.log(`BurningHouse Auth: http://${cfg.HOST}:${cfg.PORT}  (issuer: ${cfg.ISSUER})`);
  if (store.listClients().length === 0) {
    console.log("[!] Не зарегистрировано ни одного сервиса. Заведите: node server.js client-add <id> <название> <redirect-uri> <origin>");
  }
});
