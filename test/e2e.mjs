/**
 * Сквозная проверка связки: auth (8788) + «Мои финансы» (8787).
 * Поднимает оба сервиса сама и имитирует ровно то, что делает браузер,
 * включая переезд данных существующего пользователя Finance на user_id.
 *
 * Запуск (Node 24; на Node 22 добавьте --experimental-sqlite):
 *   node test/e2e.mjs
 *
 * Порты 8787 и 8788 на время прогона должны быть свободны. Ожидает, что репозиторий
 * «Моих финансов» лежит рядом — в ../Финансы.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { execFileSync, spawn } from "node:child_process";

const AUTH_DIR = path.resolve(fileURLToPath(import.meta.url), "../..");
const FIN_DIR = process.env.FINANCE_DIR || path.join(AUTH_DIR, "..", "Финансы");
const WORK = path.join(AUTH_DIR, "test", ".work");
const AUTH = "http://localhost:8788";
const FIN = "http://localhost:8787";

if (!fs.existsSync(path.join(FIN_DIR, "server.js"))) {
  console.error(`Не нашёл «Мои финансы» в ${FIN_DIR}. Укажите путь через FINANCE_DIR.`);
  process.exit(1);
}

// Чужой сервис на наших портах дал бы непонятные ошибки в середине прогона.
for (const [url, port] of [[AUTH, 8788], [FIN, 8787]]) {
  try {
    await fetch(url + "/api/health", { signal: AbortSignal.timeout(700) });
    console.error(`Порт ${port} уже занят — остановите тот сервис и повторите.`);
    process.exit(1);
  } catch { /* никого нет, продолжаем */ }
}

fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(WORK + "/auth", { recursive: true });
fs.mkdirSync(WORK + "/fin", { recursive: true });

let failures = 0;
function ok(name, cond, extra = "") {
  console.log(`${cond ? "  OK  " : " FAIL "} ${name}${extra ? " — " + extra : ""}`);
  if (!cond) failures++;
}
const b64u = b => Buffer.from(b).toString("base64url");
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ---------- 1. База Finance «как до переезда» ---------- */
const PASSWORD = "СтарыйПароль-2024";
const OLD_DATA = { tx: [{ id: "t1", amount: 1234.5, note: "старая запись" }], goals: [], debts: [], theme: "dark" };
{
  const db = new DatabaseSync(WORK + "/fin/store.db");
  db.exec(`CREATE TABLE users (username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL);
           CREATE TABLE states (username TEXT PRIMARY KEY, data TEXT, updated_at INTEGER NOT NULL DEFAULT 0);`);
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(PASSWORD, salt, 64).toString("hex"); // соль строкой — как в Finance
  db.prepare("INSERT INTO users VALUES (?,?,?)").run("olduser", salt, hash);
  db.prepare("INSERT INTO states VALUES (?,?,?)").run("olduser", JSON.stringify(OLD_DATA), 1700000000000);
  db.close();
}

/* ---------- 2. Настройка auth ---------- */
const authEnv = { ...process.env, DATA_DIR: WORK + "/auth" };
const authCli = (...a) => execFileSync("node", ["--experimental-sqlite", "server.js", ...a], { cwd: AUTH_DIR, env: authEnv, encoding: "utf8" });

authCli("client-add", "finance", "Мои финансы", FIN + "/");
console.log(authCli("import-finance", WORK + "/fin/store.db").trim().split("\n").slice(-3).join("\n"));

/* ---------- 3. Запуск обоих сервисов ---------- */
const procs = [];
function start(name, cwd, env, port) {
  const p = spawn("node", ["--experimental-sqlite", "server.js"], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  const log = [];
  p.stdout.on("data", d => log.push(String(d)));
  p.stderr.on("data", d => log.push(String(d)));
  procs.push({ name, p, log });
  return p;
}
const ACCESS_TTL = 3; // секунды — чтобы проверить тихое обновление токена не ожидая 15 минут
start("auth", AUTH_DIR, { ...authEnv, DEV: "1", ISSUER: AUTH, PORT: "8788", HOST: "127.0.0.1", ACCESS_TTL: String(ACCESS_TTL) });
start("finance", FIN_DIR, {
  ...process.env, DATA_DIR: WORK + "/fin", PORT: "8787", HOST: "127.0.0.1",
  AUTH_ISSUER: AUTH, AUTH_CLIENT_ID: "finance",
  AUTH_CLOCK_SKEW: "0", // чтобы проверить протухание токена, не ожидая допуска на часы
});

async function waitUp(url) {
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(url + "/api/health")).ok) return true; } catch { }
    await sleep(200);
  }
  return false;
}
ok("auth поднялся", await waitUp(AUTH));
ok("finance поднялся", await waitUp(FIN));

/* ---------- 4. Конфиг, который фронт получает от Finance ---------- */
const cfg = await (await fetch(FIN + "/api/config")).json();
ok("Finance отдаёт адрес auth", cfg.authBase === AUTH && cfg.clientId === "finance", JSON.stringify(cfg));

/* ---------- 5. Без токена данные закрыты ---------- */
ok("/api/state без токена → 401", (await fetch(FIN + "/api/state")).status === 401);

/* ---------- 6. Вход старым паролем Finance ---------- */
const verifier = b64u(crypto.randomBytes(32));
const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
const state = b64u(crypto.randomBytes(16));
const redirect = FIN + "/";

let r = await fetch(`${AUTH}/api/authorize/login`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    username: "olduser", password: PASSWORD,
    client_id: "finance", redirect_uri: redirect, state,
    code_challenge: challenge, code_challenge_method: "S256",
  }),
});
const login = await r.json();
ok("вход СТАРЫМ паролем Finance", r.status === 200 && !!login.redirect, login.message || "");
const cookie = (r.headers.getSetCookie?.() || []).map(c => c.split(";")[0]).join("; ");
const code = login.redirect && new URL(login.redirect).searchParams.get("code");
ok("возврат ведёт на Finance", login.redirect?.startsWith(redirect), login.redirect);

r = await fetch(`${AUTH}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "authorization_code", client_id: "finance", redirect_uri: redirect, code, code_verifier: verifier }),
});
let tok = await r.json();
ok("обмен кода на токены", r.status === 200 && !!tok.access_token, JSON.stringify(tok.user));

/* ---------- 7. Ленивый переезд данных ---------- */
r = await fetch(FIN + "/api/state", { headers: { Authorization: "Bearer " + tok.access_token } });
const st = await r.json();
ok("данные старого пользователя подтянулись", r.status === 200 && st.data?.tx?.[0]?.note === "старая запись", JSON.stringify(st.data?.tx));
ok("updatedAt сохранился при переезде", st.updatedAt === 1700000000000, String(st.updatedAt));

{
  const db = new DatabaseSync(WORK + "/fin/store.db", { readOnly: true });
  const v2 = db.prepare("SELECT user_id, username FROM states_v2").all();
  const old = db.prepare("SELECT username, migrated_to, data IS NOT NULL AS has_data FROM states").all();
  db.close();
  ok("строка появилась в states_v2 под user_id", v2.length === 1 && v2[0].user_id === tok.user.id, JSON.stringify(v2));
  ok("старая строка помечена перенесённой", old[0]?.migrated_to === tok.user.id, JSON.stringify(old));
  ok("старая строка НЕ удалена (резервная копия)", old[0]?.has_data === 1);
}

/* ---------- 8. Запись данных ---------- */
r = await fetch(FIN + "/api/state", {
  method: "PUT", headers: { "Content-Type": "application/json", Authorization: "Bearer " + tok.access_token },
  body: JSON.stringify({ data: { ...OLD_DATA, tx: [...OLD_DATA.tx, { id: "t2", amount: 50, note: "новая" }] } }),
});
ok("запись состояния", r.status === 200);
r = await fetch(FIN + "/api/state", { headers: { Authorization: "Bearer " + tok.access_token } });
ok("чтение возвращает записанное", (await r.json()).data.tx.length === 2);

/* ---------- 9. Протухание access-токена и тихое обновление ---------- */
await sleep((ACCESS_TTL + 2) * 1000);
r = await fetch(FIN + "/api/state", { headers: { Authorization: "Bearer " + tok.access_token } });
ok("протухший access-токен → 401", r.status === 401);

r = await fetch(`${AUTH}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "refresh_token", client_id: "finance", refresh_token: tok.refresh_token }),
});
tok = await r.json();
ok("refresh выдал свежий access", r.status === 200 && !!tok.access_token);
r = await fetch(FIN + "/api/state", { headers: { Authorization: "Bearer " + tok.access_token } });
ok("со свежим токеном данные снова доступны", r.status === 200);

/* ---------- 10. Рестарт auth не разлогинивает ---------- */
const authProc = procs.find(x => x.name === "auth");
authProc.p.kill();
await sleep(700);
start("auth2", AUTH_DIR, { ...authEnv, DEV: "1", ISSUER: AUTH, PORT: "8788", HOST: "127.0.0.1", ACCESS_TTL: String(ACCESS_TTL) });
ok("auth перезапустился", await waitUp(AUTH));

r = await fetch(`${AUTH}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "refresh_token", client_id: "finance", refresh_token: tok.refresh_token }),
});
const afterRestart = await r.json();
ok("ПОСЛЕ РЕСТАРТА auth пользователь остался залогинен", r.status === 200 && !!afterRestart.access_token, afterRestart.error || "");

r = await fetch(FIN + "/api/state", { headers: { Authorization: "Bearer " + afterRestart.access_token } });
ok("Finance принимает токен, выпущенный после рестарта", r.status === 200);

/* SSO-кука тоже пережила рестарт */
r = await fetch(`${AUTH}/authorize?client_id=finance&redirect_uri=${encodeURIComponent(redirect)}&state=s&code_challenge=${challenge}&code_challenge_method=S256`,
  { redirect: "manual", headers: { Cookie: cookie } });
ok("SSO-сессия пережила рестарт (вход без пароля)", r.status === 302 && r.headers.get("location")?.includes("code="));

/* ---------- 11. Finance не принимает чужие подписи ---------- */
const fake = crypto.generateKeyPairSync("ed25519");
const hdr = b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: "238dd0ddd64e72be" }));
const pl = b64u(JSON.stringify({ iss: AUTH, sub: tok.user.id, aud: "finance", exp: Math.floor(Date.now() / 1000) + 600 }));
const sig = b64u(crypto.sign(null, Buffer.from(hdr + "." + pl), fake.privateKey));
r = await fetch(FIN + "/api/state", { headers: { Authorization: `Bearer ${hdr}.${pl}.${sig}` } });
ok("токен, подписанный чужим ключом → 401", r.status === 401);

/* ---------- 12. Отзыв доступа из кабинета ---------- */
const sessions = await (await fetch(`${AUTH}/api/account/sessions`, { headers: { Cookie: cookie } })).json();
ok("кабинет показывает сессии", sessions.apps.length >= 1 && sessions.browsers.length >= 1,
  `сервисов: ${sessions.apps.length}, браузеров: ${sessions.browsers.length}`);
await fetch(`${AUTH}/api/account/sessions`, { method: "DELETE", headers: { Cookie: cookie } });
r = await fetch(`${AUTH}/oauth/token`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "refresh_token", client_id: "finance", refresh_token: afterRestart.refresh_token }),
});
ok("после отзыва всех доступов refresh мёртв", r.status === 401);

/* ---------- итог ---------- */
for (const { name, p } of procs) p.kill();
await sleep(300);
if (failures) {
  console.log("\n--- логи сервисов ---");
  for (const { name, log } of procs) console.log(`[${name}] ` + log.join("").split("\n").filter(l => l && !/ExperimentalWarning|trace-warnings/.test(l)).join(`\n[${name}] `));
}
console.log(failures ? `\nПровалов: ${failures}` : "\nСквозная проверка пройдена полностью.");
process.exit(failures ? 1 : 0);
