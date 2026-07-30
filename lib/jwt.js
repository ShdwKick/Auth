"use strict";
/**
 * JWT (EdDSA) — подпись и проверка через встроенный crypto.
 * Для ed25519 алгоритм в crypto.sign/verify передаётся как null: он однозначно
 * определяется самим ключом.
 */

const crypto = require("crypto");

const b64url = obj => Buffer.from(typeof obj === "string" || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj)).toString("base64url");

function sign(payload, key) {
  const header = { alg: "EdDSA", typ: "JWT", kid: key.kid };
  const data = b64url(header) + "." + b64url(payload);
  const sig = crypto.sign(null, Buffer.from(data), crypto.createPrivateKey(key.private_pem));
  return data + "." + b64url(sig);
}

/** Разбор без проверки подписи — нужен только чтобы достать kid до выбора ключа. */
function decode(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
      payload: JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")),
      signed: parts[0] + "." + parts[1],
      signature: Buffer.from(parts[2], "base64url"),
    };
  } catch {
    return null;
  }
}

/**
 * Полная проверка. resolveKey(kid) → { public_pem } | null.
 * Возвращает payload или null — без исключений, чтобы вызывающему коду
 * не приходилось оборачивать каждую проверку в try.
 */
function verify(token, resolveKey, { issuer, audience, clockSkew = 60 } = {}) {
  const t = decode(token);
  if (!t) return null;
  if (t.header.alg !== "EdDSA" || t.header.typ !== "JWT") return null;

  const key = resolveKey(t.header.kid);
  if (!key) return null;

  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(t.signed), crypto.createPublicKey(key.public_pem), t.signature);
  } catch {
    return null;
  }
  if (!ok) return null;

  const p = t.payload;
  const now = Math.floor(Date.now() / 1000);
  if (typeof p.exp !== "number" || p.exp + clockSkew < now) return null;
  if (typeof p.nbf === "number" && p.nbf - clockSkew > now) return null;
  if (issuer && p.iss !== issuer) return null;
  if (audience && p.aud !== audience) return null;
  return p;
}

module.exports = { sign, decode, verify };
