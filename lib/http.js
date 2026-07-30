"use strict";
/** Мелкие HTTP-утилиты: тело запроса, JSON-ответы, куки, CORS, статика, rate limit. */

const fs = require("fs");
const path = require("path");
const cfg = require("./config");

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function readBody(req, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let data = "", size = 0;
    req.on("data", c => {
      size += c.length;
      if (size > limit) { reject(new Error("too large")); req.destroy(); } else data += c;
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

/** Тело как объект: понимает и JSON, и form-urlencoded (эндпоинт /oauth/token принимает оба). */
async function readParams(req) {
  const raw = await readBody(req);
  const ct = String(req.headers["content-type"] || "");
  if (ct.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  try { return JSON.parse(raw || "{}"); } catch { return {}; }
}

function bearer(req) {
  const h = req.headers["authorization"] || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

function cookies(req) {
  const out = {};
  for (const part of String(req.headers["cookie"] || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function setCookie(res, name, value, { maxAge, clear = false } = {}) {
  const bits = [
    `${name}=${clear ? "" : encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (cfg.COOKIE_SECURE) bits.push("Secure");
  bits.push(clear ? "Max-Age=0" : `Max-Age=${Math.floor(maxAge / 1000)}`);
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", prev ? [].concat(prev, bits.join("; ")) : bits.join("; "));
}

function clientIp(req) {
  const fwd = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return fwd || req.socket.remoteAddress || "";
}
const userAgent = req => String(req.headers["user-agent"] || "").slice(0, 200);

/**
 * CORS для эндпоинтов, к которым фронты сервисов ходят с других доменов.
 * Никаких "*": только origin'ы зарегистрированных клиентов.
 */
function cors(req, res, allowed) {
  const origin = req.headers["origin"];
  if (!origin) return true;
  if (!allowed.has(origin)) return false;
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "600");
  res.setHeader("Vary", "Origin");
  return true;
}

/** CSRF для эндпоинтов, работающих по куке: Origin обязан совпасть с нашим. */
function sameOrigin(req) {
  const origin = req.headers["origin"];
  if (!origin) return true; // не браузерный запрос (curl, мобильный клиент)
  return origin === cfg.ISSUER || (cfg.DEV && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin));
}

const MIME = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2",
};

/** Отдаём только файлы из assets/ — база и исходники наружу недоступны. */
function serveStatic(res, pathname, rootDir) {
  if (!pathname.startsWith("/assets/")) return false;
  const assetsDir = path.join(rootDir, "assets");
  const file = path.join(rootDir, path.normalize(pathname).replace(/^([\\/])+/, ""));
  if (!file.startsWith(assetsDir + path.sep)) return false;
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return false;
  res.writeHead(200, {
    "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream",
    "Cache-Control": "public, max-age=300",
  });
  fs.createReadStream(file).pipe(res);
  return true;
}

const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/**
 * Rate limit со скользящим окном в памяти. Процесс один, состояние переживать
 * рестарт не обязано — назначение сугубо в том, чтобы гасить перебор паролей.
 */
function createLimiter({ max, windowMs }) {
  const hits = new Map(); // key -> number[] (таймстемпы)
  setInterval(() => {
    const edge = Date.now() - windowMs;
    for (const [k, arr] of hits) {
      const live = arr.filter(t => t > edge);
      if (live.length) hits.set(k, live); else hits.delete(k);
    }
  }, windowMs).unref();

  return {
    /** true — лимит исчерпан, запрос надо отбить 429-м. */
    hit(key) {
      const now = Date.now();
      const arr = (hits.get(key) || []).filter(t => t > now - windowMs);
      arr.push(now);
      hits.set(key, arr);
      return arr.length > max;
    },
    reset(key) { hits.delete(key); },
  };
}

module.exports = {
  json, readBody, readParams, bearer, cookies, setCookie,
  clientIp, userAgent, cors, sameOrigin, serveStatic, escapeHtml, createLimiter,
};
