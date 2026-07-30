"use strict";
/**
 * Пароли — scrypt из встроенного crypto, без внешних зависимостей.
 *
 * Два алгоритма живут одновременно:
 *
 *   scrypt-legacy — ровно то, что делал Finance: соль передаётся в scryptSync
 *                   КАК СТРОКА (32 ASCII-символа её hex-записи), параметры
 *                   стоимости дефолтные. Нужен только чтобы импортированные
 *                   пользователи вошли своим старым паролем.
 *   scrypt-v1     — для всего нового: соль как 16 байт, N=2^15 (вчетверо дороже
 *                   дефолтного 2^14), явный maxmem — без него 128*N*r упирается
 *                   в лимит 32 МБ и scryptSync падает.
 *
 * При успешном входе legacy-хэш прозрачно переписывается в v1 (см. upgradeHash
 * в store.js), так что legacy-ветка со временем вымрет сама.
 */

const crypto = require("crypto");

const KEYLEN = 64;
const V1 = { N: 32768, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };

const ALGO_LEGACY = "scrypt-legacy";
const ALGO_V1 = "scrypt-v1";

function hashLegacy(password, saltHex) {
  return crypto.scryptSync(password, saltHex, KEYLEN).toString("hex");
}
function hashV1(password, saltHex) {
  return crypto.scryptSync(password, Buffer.from(saltHex, "hex"), KEYLEN, V1).toString("hex");
}

/** Новый пароль всегда считается по scrypt-v1. */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: hashV1(password, salt), algo: ALGO_V1 };
}

function verifyPassword(password, salt, hash, algo) {
  let computed;
  try {
    computed = algo === ALGO_LEGACY ? hashLegacy(password, salt) : hashV1(password, salt);
  } catch {
    return false;
  }
  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s.]+\.[^@\s]+$/;

function normalizeUsername(v) {
  return String(v || "").trim().toLowerCase();
}
function normalizeEmail(v) {
  const s = String(v || "").trim().toLowerCase();
  return s || null;
}
/** Общая валидация — используется и формой регистрации, и CLI adduser. */
function validateCreds(username, password) {
  if (!USERNAME_RE.test(String(username || "").trim())) return "Логин: 3–32 символа, латиница/цифры/._-";
  if (String(password || "").length < 6) return "Пароль: минимум 6 символов";
  return null;
}
function validateEmail(email) {
  if (email === null) return null;
  if (!EMAIL_RE.test(email) || email.length > 254) return "Некорректный адрес почты";
  return null;
}

module.exports = {
  ALGO_LEGACY, ALGO_V1,
  hashPassword, verifyPassword,
  normalizeUsername, normalizeEmail, validateCreds, validateEmail,
};
