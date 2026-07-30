#!/usr/bin/env node
/**
 * Минимальный сервис, подключённый к BurningHouse Auth. Настоящий, запускаемый —
 * из него можно копировать в новый проект. Умеет ровно одно: хранить заметку,
 * привязанную к пользователю.
 *
 * Запуск:
 *   node server.js
 *
 * Переменные окружения:
 *   PORT            (по умолчанию 8789)
 *   AUTH_ISSUER     ОБЯЗАТЕЛЬНО — адрес auth-сервиса (http://localhost:8788 локально)
 *   AUTH_CLIENT_ID  (по умолчанию example)
 *   AUTH_JWKS_URL   если auth доступен серверу по другому адресу, чем браузеру
 *
 * Перед первым запуском сервис нужно зарегистрировать в auth:
 *   node server.js client-add example "Пример" http://localhost:8789/
 */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = parseInt(process.env.PORT || "8789", 10);
const HOST = process.env.HOST || "127.0.0.1";
const AUTH_ISSUER = (process.env.AUTH_ISSUER || "").replace(/\/+$/, "");
const AUTH_CLIENT_ID = process.env.AUTH_CLIENT_ID || "example";

if (!AUTH_ISSUER) {
  console.error("Не задан AUTH_ISSUER — проверять токены нечем. Пример: AUTH_ISSUER=http://localhost:8788");
  process.exit(1);
}

// В реальном проекте этот файл КОПИРУЕТСЯ в него (см. INTEGRATION.md, шаг 2).
// Здесь берём оригинал из client/, чтобы копия внутри одного репозитория не разъехалась.
const auth = require("../../client/auth-client")({
  issuer: AUTH_ISSUER,
  audience: AUTH_CLIENT_ID,
  jwksUrl: process.env.AUTH_JWKS_URL,
});
auth.warmup(); // прогреть кэш ключей, чтобы первый запрос не ждал сеть

// Хранилище: user_id → текст. Ключ — стабильный UUID из токена, НЕ логин.
const notes = new Map();

function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => { data += c; if (data.length > 64 * 1024) { reject(new Error("too large")); req.destroy(); } });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, "http://x").pathname;

  if (p === "/api/health") return json(res, 200, { ok: true });

  // Адрес auth отдаём фронту, чтобы он не был зашит в статику.
  if (p === "/api/config") {
    return json(res, 200, { authBase: AUTH_ISSUER, clientId: AUTH_CLIENT_ID });
  }

  if (p === "/api/note") {
    // Вся авторизация — вот эти две строки. Подпись проверяется локально,
    // запроса в auth-сервис здесь не происходит.
    const user = await auth.userFromRequest(req);
    if (!user) return json(res, 401, { error: "unauthorized" });

    if (req.method === "GET") {
      return json(res, 200, { text: notes.get(user.id) || "", username: user.username });
    }
    if (req.method === "PUT") {
      try {
        const body = JSON.parse(await readBody(req) || "{}");
        notes.set(user.id, String(body.text || "").slice(0, 10000));
        return json(res, 200, { ok: true });
      } catch { return json(res, 400, { error: "bad request" }); }
    }
    return json(res, 405, { error: "method not allowed" });
  }

  if (req.method === "GET") {
    // Отдаём только index.html и браузерную библиотеку — больше в примере ничего нет.
    // В реальном проекте она лежала бы в assets/ этого проекта своей копией.
    const file = p === "/assets/auth-client.js"
      ? path.join(__dirname, "..", "..", "client", "auth-client-browser.js")
      : path.join(__dirname, "index.html");
    const type = file.endsWith(".js") ? "application/javascript; charset=utf-8" : "text/html; charset=utf-8";
    try {
      res.writeHead(200, { "Content-Type": type });
      return res.end(fs.readFileSync(file));
    } catch {
      res.writeHead(500); return res.end("файл не найден");
    }
  }

  res.writeHead(404); res.end();
});

server.listen(PORT, HOST, () => {
  console.log(`Пример сервиса: http://${HOST}:${PORT}`);
  console.log(`Авторизация: ${AUTH_ISSUER} (клиент «${AUTH_CLIENT_ID}»)`);
});
