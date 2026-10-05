/**
 * Браузерный auth-client (client/auth-client-browser.js) без сети: протухший
 * токен при недоступном auth — это «нет связи», а не «нужен вход». Токены
 * целы, fetch бросает AuthOfflineError; вход теряется, только если auth сам
 * отверг refresh-токен. Сети и сервера не требует:
 *   node test/browser-client.mjs
 */
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const store = new Map();
globalThis.localStorage = { getItem: k => store.has(k) ? store.get(k) : null, setItem: (k, v) => store.set(k, String(v)), removeItem: k => store.delete(k) };
globalThis.sessionStorage = globalThis.localStorage;
globalThis.location = { origin: "http://x", href: "http://x/" };
const { createAuthClient } = require("../client/auth-client-browser.js");
const P = "t";
const auth = createAuthClient({ authBase: "http://auth", clientId: "svc", redirectUri: "http://x/", storagePrefix: P });
let fails = 0;
const ok = (name, c) => { console.log((c ? "ок   " : "FAIL ") + name); if (!c) fails++; };
const expired = () => { store.clear(); store.set(P + "_access", "OLD"); store.set(P + "_refresh", "R1"); store.set(P + "_expires", "1"); };
const tokenOk = () => new Response(JSON.stringify({ access_token: "NEW", refresh_token: "R2", expires_in: 900 }), { status: 200 });
(async () => {
  // 1. Нет сети: токен протух, refresh не доходит.
  expired();
  globalThis.fetch = async () => { throw new TypeError("Failed to fetch"); };
  let e = await auth.fetch("/api/x").catch(x => x);
  ok("нет сети → AuthOfflineError, а не «нужен вход»", e.name === "AuthOfflineError");
  ok("нет сети → токены целы", store.get(P + "_refresh") === "R1" && auth.isAuthenticated());
  ok("getAccessToken без сети → null (контракт Puzzle)", (await auth.getAccessToken()) === null);
  // 2. auth лежит (502).
  globalThis.fetch = async u => String(u).includes("/oauth/token") ? new Response("", { status: 502 }) : new Response("{}");
  e = await auth.fetch("/api/x").catch(x => x);
  ok("auth 502 → AuthOfflineError, токены целы", e.name === "AuthOfflineError" && store.get(P + "_refresh") === "R1");
  // 3. refresh отвергнут (отозвали сессию).
  globalThis.fetch = async u => String(u).includes("/oauth/token") ? new Response("{}", { status: 401 }) : new Response("{}");
  e = await auth.fetch("/api/x").catch(x => x);
  ok("refresh отвергнут → AuthRequiredError, токены стёрты", e.name === "AuthRequiredError" && !store.get(P + "_refresh"));
  // 4. Сеть вернулась.
  expired();
  globalThis.fetch = async (u, init) => String(u).includes("/oauth/token") ? tokenOk() : new Response(JSON.stringify({ auth: init.headers.get("Authorization") }));
  const r = await auth.fetch("/api/x").then(x => x.json());
  ok("сеть есть → обновил и отправил с новым токеном", r.auth === "Bearer NEW");
  ok("refresh() по-прежнему boolean", (expired(), await auth.refresh()) === true);
  console.log(fails ? `Провалено: ${fails}` : "Всё прошло.");
  process.exit(fails ? 1 : 0);
})();
