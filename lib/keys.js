"use strict";
/**
 * Ключи подписи access-токенов: ed25519 (JWT alg=EdDSA).
 *
 * Почему ed25519, а не RSA: ключ 32 байта, подпись 64 — JWT остаётся коротким,
 * и всё считается встроенным crypto без единой зависимости.
 *
 * Ротация: rotate() заводит новый ключ и помечает старый retired_at=now. Старый
 * остаётся в JWKS ещё RETIRE_GRACE, чтобы уже выданные access-токены дожили свой
 * срок и никого не разлогинило на ровном месте.
 */

const crypto = require("crypto");
const { db } = require("./db");

const RETIRE_GRACE = 24 * 60 * 60 * 1000; // сутки — заведомо больше TTL access-токена

const stmt = {
  insert: db.prepare("INSERT INTO signing_keys (kid, private_pem, public_pem, created_at) VALUES (?, ?, ?, ?)"),
  active: db.prepare("SELECT * FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1"),
  byKid: db.prepare("SELECT * FROM signing_keys WHERE kid = ?"),
  published: db.prepare("SELECT * FROM signing_keys WHERE retired_at IS NULL OR retired_at > ? ORDER BY created_at DESC"),
  retireAll: db.prepare("UPDATE signing_keys SET retired_at = ? WHERE retired_at IS NULL"),
};

const b64url = buf => Buffer.from(buf).toString("base64url");

/** raw-часть публичного ключа: последние 32 байта SPKI-DER (заголовок ed25519 фиксированный). */
function rawPublic(publicPem) {
  const der = crypto.createPublicKey(publicPem).export({ type: "spki", format: "der" });
  return der.subarray(der.length - 32);
}

function createKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const public_pem = publicKey.export({ type: "spki", format: "pem" });
  const private_pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const kid = crypto.createHash("sha256").update(rawPublic(public_pem)).digest("hex").slice(0, 16);
  stmt.insert.run(kid, private_pem, public_pem, Date.now());
  return stmt.byKid.get(kid);
}

/** Активный ключ; при первом запуске генерируется автоматически. */
function activeKey() {
  return stmt.active.get() || createKey();
}

function rotate() {
  stmt.retireAll.run(Date.now());
  return createKey();
}

/** Публичные ключи в формате JWKS — это то, по чему сервисы проверяют подпись локально. */
function jwks() {
  const rows = stmt.published.all(Date.now() - RETIRE_GRACE);
  return {
    keys: rows.map(k => ({
      kty: "OKP",
      crv: "Ed25519",
      x: b64url(rawPublic(k.public_pem)),
      kid: k.kid,
      use: "sig",
      alg: "EdDSA",
    })),
  };
}

const byKid = kid => stmt.byKid.get(String(kid || "")) || null;

module.exports = { activeKey, createKey, rotate, jwks, byKid, RETIRE_GRACE };
