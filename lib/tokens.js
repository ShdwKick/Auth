"use strict";
/** Выпуск и проверка access-токенов (то, что сервисы проверяют локально по JWKS). */

const crypto = require("crypto");
const cfg = require("./config");
const jwt = require("./jwt");
const keys = require("./keys");

function issueAccess(user, clientId, sid) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: cfg.ISSUER,
    sub: user.id,
    aud: clientId,
    preferred_username: user.username,
    sid,
    iat: now,
    nbf: now,
    exp: now + Math.floor(cfg.ACCESS_TTL / 1000),
    jti: crypto.randomUUID(),
  };
  if (user.email) payload.email = user.email;
  // Только если пользователь сам включил показ — иначе сервис получил бы
  // настоящее имя, даже когда его попросили показывать логин.
  if (user.show_display_name && user.display_name) payload.name = user.display_name;
  // Отдельное, независимое согласие — можно делиться именем и НЕ делиться
  // телефоном (или наоборот). phone_number — имя claim'а из OIDC, не наша
  // выдумка: раз name/email уже совпадают со стандартом, держим его и здесь.
  if (user.share_phone && user.phone) payload.phone_number = user.phone;
  return jwt.sign(payload, keys.activeKey());
}

/** Проверка своего же токена (для /api/userinfo и /api/account/*): aud не сверяем — он у каждого клиента свой. */
function verifyAccess(token) {
  return jwt.verify(token, keys.byKid, { issuer: cfg.ISSUER });
}

module.exports = { issueAccess, verifyAccess };
