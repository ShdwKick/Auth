/**
 * Проверки самого auth-сервиса: authorization code + PKCE, SSO, ротация и кража
 * refresh-токена, отзыв, CORS, лимит на перебор паролей.
 *
 * Поднимает сервис сам, на временной базе. Запуск (Node 24; на Node 22 добавьте
 * --experimental-sqlite):
 *   node test/flow.mjs
 *
 * Порт 8788 на время прогона должен быть свободен.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync, spawn } from "node:child_process";

const AUTH_DIR = path.resolve(fileURLToPath(import.meta.url), "../..");
const WORK = path.join(AUTH_DIR, "test", ".work-flow");
const BASE = "http://localhost:8788";
const CLIENT = "finance";
const REDIRECT = "http://localhost:8787/";
const PASSWORD = "secret123";
const b64u = b => Buffer.from(b).toString("base64url");

// Чужой сервис на нашем порту дал бы непонятные ошибки в середине прогона.
try {
  await fetch(BASE + "/api/health", { signal: AbortSignal.timeout(700) });
  console.error(`Порт 8788 уже занят — остановите тот сервис и повторите.`);
  process.exit(1);
} catch { /* никого нет, продолжаем */ }

fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(WORK, { recursive: true });

const env = { ...process.env, DATA_DIR: WORK };
const cli = (...a) => execFileSync(process.execPath, [...process.execArgv, "server.js", ...a], { cwd: AUTH_DIR, env, encoding: "utf8" });
cli("adduser", "danil", PASSWORD);
cli("client-add", CLIENT, "Мои финансы", REDIRECT);

const server = spawn(process.execPath, [...process.execArgv, "server.js"], {
  cwd: AUTH_DIR, stdio: "ignore",
  env: { ...env, DEV: "1", ISSUER: BASE, PORT: "8788", HOST: "127.0.0.1" },
});
process.on("exit", () => server.kill());
for (let i = 0; i < 50; i++) {
  try { if ((await fetch(BASE + "/api/health")).ok) break; } catch { }
  await new Promise(r => setTimeout(r, 200));
}

const verifier = b64u(crypto.randomBytes(32));
const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
const state = b64u(crypto.randomBytes(16));

const authorizeUrl = `${BASE}/authorize?client_id=${CLIENT}&redirect_uri=${encodeURIComponent(REDIRECT)}&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`;

function ok(name, cond, extra = "") { console.log(`${cond ? "  OK  " : " FAIL "} ${name}${extra ? " — " + extra : ""}`); if (!cond) process.exitCode = 1; }

// 1. Без куки /authorize отдаёт форму
let r = await fetch(authorizeUrl, { redirect: "manual" });
ok("/authorize без сессии отдаёт форму логина", r.status === 200 && (await r.text()).includes("loginCard"));

// 2. Логин с неверным паролем
r = await fetch(`${BASE}/api/authorize/login`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: "danil", password: "wrong", client_id: CLIENT, redirect_uri: REDIRECT, state, code_challenge: challenge, code_challenge_method: "S256" }),
});
ok("неверный пароль → 401", r.status === 401);

// 3. Логин верный
r = await fetch(`${BASE}/api/authorize/login`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: "danil", password: PASSWORD, client_id: CLIENT, redirect_uri: REDIRECT, state, code_challenge: challenge, code_challenge_method: "S256" }),
});
const login = await r.json();
const cookie = (r.headers.getSetCookie?.() || []).map(c => c.split(";")[0]).join("; ");
ok("логин → redirect с кодом", r.status === 200 && login.redirect?.includes("code="), login.redirect);
ok("логин ставит куку сессии", !!cookie, cookie);

// "danil" заведён через adduser (CLI) — почты у него нет, а без неё GET
// /authorize (используется ниже в freshSession) не редиректит молча, а
// показывает мягкое окошко «добавьте почту» (см. server.js). Пропускаем —
// проверка этого окошка не тема этого теста, он про сам механизм SSO/PKCE.
r = await fetch(`${BASE}/api/account/email/dismiss`, {
  method: "POST", headers: { "Content-Type": "application/json", Cookie: cookie, Origin: BASE },
});
ok("окошко «добавьте почту» пропущено для теста SSO", r.status === 200);

const code = new URL(login.redirect).searchParams.get("code");
ok("state вернулся тем же", new URL(login.redirect).searchParams.get("state") === state);

// 4. Обмен кода с ЧУЖИМ verifier — должно отлупить
r = await fetch(`${BASE}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "authorization_code", client_id: CLIENT, redirect_uri: REDIRECT, code, code_verifier: "not-the-verifier" }),
});
ok("PKCE: чужой code_verifier → отказ", r.status === 400, (await r.json()).error);

// 5. Обмен кода правильный
r = await fetch(`${BASE}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "authorization_code", client_id: CLIENT, redirect_uri: REDIRECT, code, code_verifier: verifier }),
});
const tok = await r.json();
ok("обмен кода → токены", r.status === 200 && !!tok.access_token && !!tok.refresh_token, JSON.stringify(tok.user));

// 6. Повторный обмен того же кода
r = await fetch(`${BASE}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "authorization_code", client_id: CLIENT, redirect_uri: REDIRECT, code, code_verifier: verifier }),
});
ok("реюз кода → отказ", r.status === 400, (await r.json()).error);

// 7. userinfo по access-токену
r = await fetch(`${BASE}/api/userinfo`, { headers: { Authorization: "Bearer " + tok.access_token } });
ok("/api/userinfo по access-токену", r.status === 200, JSON.stringify(await r.json()));

// 8. Локальная проверка токена клиентской библиотекой
const createAuthClient = (await import(pathToFileURL(path.join(AUTH_DIR, "client", "auth-client.js")).href)).default;
const client = createAuthClient({ issuer: BASE, audience: CLIENT });
const payload = await client.verify(tok.access_token);
ok("auth-client проверяет подпись локально", !!payload && payload.preferred_username === "danil", JSON.stringify(payload));
ok("auth-client отвергает подделку", !(await client.verify(tok.access_token.slice(0, -4) + "AAAA")));
const otherAud = createAuthClient({ issuer: BASE, audience: "someone-else" });
ok("auth-client отвергает чужой aud", !(await otherAud.verify(tok.access_token)));

// Сессия из шага 5 намеренно погибла на шаге 6 (реюз кода = утечка кода).
r = await fetch(`${BASE}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: tok.refresh_token }),
});
ok("реюз кода отозвал выданную по нему сессию", r.status === 401, (await r.json()).error);

// Дальше — на свежих сессиях, каждая по своему коду.
async function freshSession() {
  const v = b64u(crypto.randomBytes(32));
  const c = crypto.createHash("sha256").update(v).digest("base64url");
  const a = await fetch(`${BASE}/authorize?client_id=${CLIENT}&redirect_uri=${encodeURIComponent(REDIRECT)}&state=s&code_challenge=${c}&code_challenge_method=S256`,
    { redirect: "manual", headers: { Cookie: cookie } });
  const loc = a.headers.get("location");
  const cd = new URL(loc).searchParams.get("code");
  const t = await fetch(`${BASE}/oauth/token`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ grant_type: "authorization_code", client_id: CLIENT, redirect_uri: REDIRECT, code: cd, code_verifier: v }),
  });
  return { status: a.status, location: loc, tokens: await t.json() };
}

// 9. SSO: с той же кукой /authorize отдаёт код без ввода пароля
const sso = await freshSession();
ok("SSO: с кукой /authorize сразу редиректит с кодом", sso.status === 302 && sso.location.includes("code="), sso.location);
ok("SSO-сессия обменивается на токены", !!sso.tokens.access_token);

// 10. Ротация refresh-токена
const live = await freshSession();
r = await fetch(`${BASE}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: live.tokens.refresh_token }),
});
const tok2 = await r.json();
ok("refresh → новая пара", r.status === 200 && !!tok2.refresh_token && tok2.refresh_token !== live.tokens.refresh_token);

// 11. Реюз уже ротированного refresh — вся сессия должна погибнуть
r = await fetch(`${BASE}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: live.tokens.refresh_token }),
});
ok("реюз ротированного refresh → 401", r.status === 401, (await r.json()).error);
r = await fetch(`${BASE}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: tok2.refresh_token }),
});
ok("после кражи и свежий refresh мёртв (сессия отозвана целиком)", r.status === 401, (await r.json()).error);

// 11b. Отзыв сессии из личного кабинета
const revocable = await freshSession();
const sessions = await (await fetch(`${BASE}/api/account/sessions`, { headers: { Cookie: cookie } })).json();
const target = sessions.apps.find(a => a.id);
r = await fetch(`${BASE}/api/account/sessions/${target.id}`, { method: "DELETE", headers: { Cookie: cookie } });
ok("отзыв сессии из кабинета", r.status === 200);
r = await fetch(`${BASE}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: revocable.tokens.refresh_token }),
});
ok("после отзыва refresh не работает", r.status === 401, (await r.json()).error);

// 12. Неизвестный redirect_uri
r = await fetch(`${BASE}/authorize?client_id=${CLIENT}&redirect_uri=${encodeURIComponent("https://evil.example/")}&state=x&code_challenge=${challenge}&code_challenge_method=S256`, { redirect: "manual" });
ok("чужой redirect_uri → 400, без редиректа", r.status === 400);

// 13. Без PKCE
r = await fetch(`${BASE}/authorize?client_id=${CLIENT}&redirect_uri=${encodeURIComponent(REDIRECT)}&state=x`, { redirect: "manual" });
ok("без code_challenge → 400", r.status === 400);

// 14. CORS: чужой origin
r = await fetch(`${BASE}/oauth/token`, { method: "OPTIONS", headers: { Origin: "https://evil.example" } });
ok("CORS: незарегистрированный origin → 403", r.status === 403);
r = await fetch(`${BASE}/oauth/token`, { method: "OPTIONS", headers: { Origin: "http://localhost:8787" } });
ok("CORS: origin клиента разрешён", r.status === 204 && r.headers.get("access-control-allow-origin") === "http://localhost:8787");

// 15. Rate limit
let last = 0;
for (let i = 0; i < 13; i++) {
  const rr = await fetch(`${BASE}/api/authorize/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "ratelimit-victim", password: "nope" }),
  });
  last = rr.status;
}
ok("перебор паролей → 429", last === 429, "статус " + last);

console.log(process.exitCode ? "\nЕсть провалы." : "\nВсе проверки прошли.");
