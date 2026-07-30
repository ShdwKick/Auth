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

/* ---------- маршруты ---------- */

const CORS_PATHS = /^(\/oauth\/|\/api\/userinfo|\/api\/account\/|\/\.well-known\/)/;

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
      if (user && !user.disabled && url.searchParams.get("prompt") !== "login") {
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
        const user = store.checkPassword(store.getUserByName(username), String(body.password || ""));
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
      const emailErr = pwlib.validateEmail(email);
      if (emailErr) return H.json(res, 400, { error: "invalid", message: emailErr });
      if (store.getUserByName(username)) return H.json(res, 409, { error: "user_exists", message: "Такой логин уже занят" });
      if (email && store.getUserByEmail(email)) return H.json(res, 409, { error: "email_exists", message: "Эта почта уже привязана к другому аккаунту" });

      const user = store.createUser(username, body.password, email);
      loginLimiter.reset(limitKey);
      return completeLogin(req, res, user, params);
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
    if (p === "/api/session" && method === "GET") {
      const auth = authenticate(req);
      if (!auth) return H.json(res, 200, { authenticated: false, registerClosed: cfg.REGISTER_CLOSED, registerCode: !!cfg.REGISTER_CODE });
      return H.json(res, 200, { authenticated: true, user: store.publicUser(auth.user) });
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

      if (!store.checkPassword(auth.user, String(body.password || "")))
        return H.json(res, 401, { error: "bad_credentials", message: "Неверный пароль" });

      const email = pwlib.normalizeEmail(body.email);
      const err = pwlib.validateEmail(email);
      if (err) return H.json(res, 400, { error: "invalid", message: err });
      const taken = email && store.getUserByEmail(email);
      if (taken && taken.id !== auth.user.id) return H.json(res, 409, { error: "email_exists", message: "Эта почта уже привязана к другому аккаунту" });

      store.setEmail(auth.user.id, email);
      return H.json(res, 200, { ok: true, email });
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

    /* --- статика и страница --- */

    if (method === "GET") {
      if (H.serveStatic(res, p, ROOT)) return;
      if (p === "/" || p === "/index.html") return serveApp(res);
      return errorPage(res, 404, "Страница не найдена", "Проверьте адрес.");
    }

    return H.json(res, 405, { error: "method_not_allowed" });
  } catch (e) {
    console.error("Необработанная ошибка:", e);
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
