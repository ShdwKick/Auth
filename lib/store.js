"use strict";
/**
 * Операции над данными: пользователи, клиенты, SSO-сессии, одноразовые коды,
 * refresh-сессии. Вся работа с SQL живёт здесь, HTTP-слой её не видит.
 */

const crypto = require("crypto");
const { db } = require("./db");
const cfg = require("./config");
const pw = require("./passwords");

const sha256 = v => crypto.createHash("sha256").update(String(v)).digest("hex");
const newToken = () => crypto.randomBytes(32).toString("hex");

const stmt = {
  // users
  userById: db.prepare("SELECT * FROM users WHERE id = ?"),
  userByName: db.prepare("SELECT * FROM users WHERE username = ?"),
  userByEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
  userByPhone: db.prepare("SELECT * FROM users WHERE phone = ?"),
  insertUser: db.prepare("INSERT INTO users (id, username, email, salt, hash, pwd_algo, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"),
  updatePassword: db.prepare("UPDATE users SET salt = ?, hash = ?, pwd_algo = ? WHERE id = ?"),
  updateEmail: db.prepare("UPDATE users SET email = ?, email_verified = 0 WHERE id = ?"),
  updatePhone: db.prepare("UPDATE users SET phone = ?, share_phone = ?, phone_verified = 0 WHERE id = ?"),
  updateProfile: db.prepare("UPDATE users SET display_name = ?, show_display_name = ? WHERE id = ?"),
  deleteUser: db.prepare("DELETE FROM users WHERE id = ?"),
  countUsers: db.prepare("SELECT COUNT(*) AS n FROM users"),
  countAdmins: db.prepare("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1"),
  listUsers: db.prepare("SELECT id, username, email, pwd_algo, created_at, disabled, is_admin FROM users ORDER BY username"),
  setAdmin: db.prepare("UPDATE users SET is_admin = ? WHERE id = ?"),
  setDisabled: db.prepare("UPDATE users SET disabled = ? WHERE id = ?"),

  // clients
  clientById: db.prepare("SELECT * FROM clients WHERE client_id = ?"),
  listClients: db.prepare("SELECT * FROM clients ORDER BY client_id"),
  upsertClient: db.prepare(`INSERT INTO clients (client_id, name, redirect_uris, origins, created_at) VALUES (?, ?, ?, ?, ?)
                            ON CONFLICT(client_id) DO UPDATE SET name = excluded.name, redirect_uris = excluded.redirect_uris, origins = excluded.origins`),
  deleteClient: db.prepare("DELETE FROM clients WHERE client_id = ?"),

  // sso
  insertSso: db.prepare("INSERT INTO sso_sessions (id, user_id, created_at, last_seen, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?, ?)"),
  ssoById: db.prepare("SELECT * FROM sso_sessions WHERE id = ?"),
  touchSso: db.prepare("UPDATE sso_sessions SET last_seen = ?, expires_at = ? WHERE id = ?"),
  revokeSso: db.prepare("UPDATE sso_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"),
  revokeSsoOfUser: db.prepare("UPDATE sso_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL"),
  listSso: db.prepare("SELECT * FROM sso_sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_seen DESC"),
  dismissEmailPrompt: db.prepare("UPDATE sso_sessions SET email_prompt_dismissed = 1 WHERE id = ?"),

  // codes
  insertCode: db.prepare("INSERT INTO auth_codes (code_hash, user_id, client_id, redirect_uri, code_challenge, sso_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
  codeByHash: db.prepare("SELECT * FROM auth_codes WHERE code_hash = ?"),
  useCode: db.prepare("UPDATE auth_codes SET used_at = ?, session_id = ? WHERE code_hash = ?"),
  purgeCodes: db.prepare("DELETE FROM auth_codes WHERE expires_at < ?"),

  // sessions (refresh)
  insertSession: db.prepare("INSERT INTO sessions (id, user_id, client_id, sso_id, refresh_hash, created_at, last_seen, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
  sessionById: db.prepare("SELECT * FROM sessions WHERE id = ?"),
  sessionByRefresh: db.prepare("SELECT * FROM sessions WHERE refresh_hash = ?"),
  sessionByPrev: db.prepare("SELECT * FROM sessions WHERE prev_hash = ?"),
  rotateSession: db.prepare("UPDATE sessions SET prev_hash = refresh_hash, refresh_hash = ?, last_seen = ?, expires_at = ? WHERE id = ?"),
  revokeSession: db.prepare("UPDATE sessions SET revoked_at = ?, revoked_why = ? WHERE id = ? AND revoked_at IS NULL"),
  revokeSessionsOfUser: db.prepare("UPDATE sessions SET revoked_at = ?, revoked_why = ? WHERE user_id = ? AND revoked_at IS NULL"),
  revokeSessionsOfSso: db.prepare("UPDATE sessions SET revoked_at = ?, revoked_why = ? WHERE sso_id = ? AND revoked_at IS NULL"),
  revokeOthersOfUser: db.prepare("UPDATE sessions SET revoked_at = ?, revoked_why = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL"),
  listSessions: db.prepare("SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_seen DESC"),
  purgeSessions: db.prepare("DELETE FROM sessions WHERE expires_at < ?"),
  countActiveSessions: db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL AND expires_at > ?"),
  countActiveSso: db.prepare("SELECT COUNT(*) AS n FROM sso_sessions WHERE revoked_at IS NULL AND expires_at > ?"),
  countUsersSince: db.prepare("SELECT COUNT(*) AS n FROM users WHERE created_at > ?"),

  // password resets
  insertReset: db.prepare("INSERT INTO password_resets (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"),
  resetByHash: db.prepare("SELECT * FROM password_resets WHERE token_hash = ?"),
  useReset: db.prepare("UPDATE password_resets SET used_at = ? WHERE token_hash = ?"),
  purgeResets: db.prepare("DELETE FROM password_resets WHERE expires_at < ?"),

  // email verification
  insertEverify: db.prepare("INSERT INTO email_verifications (token_hash, user_id, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"),
  everifyByHash: db.prepare("SELECT * FROM email_verifications WHERE token_hash = ?"),
  useEverify: db.prepare("UPDATE email_verifications SET used_at = ? WHERE token_hash = ?"),
  purgeEverify: db.prepare("DELETE FROM email_verifications WHERE expires_at < ?"),
  markEmailVerified: db.prepare("UPDATE users SET email_verified = 1 WHERE id = ?"),
};

/* ---------- пользователи ---------- */

function getUserById(id) { return stmt.userById.get(String(id || "")) || null; }
function getUserByName(username) { return stmt.userByName.get(pw.normalizeUsername(username)) || null; }
function getUserByEmail(email) {
  const e = pw.normalizeEmail(email);
  return e ? stmt.userByEmail.get(e) || null : null;
}
/** Логин ИЛИ почта — так работает форма входа и «Забыли пароль?». Логин не
 *  может содержать «@» (см. USERNAME_RE), так что перепутать не с чем. */
function getUserByIdentifier(v) {
  return getUserByName(v) || getUserByEmail(v);
}
/** phone — уже нормализованное значение (см. lib/passwords.js), не сырой ввод. */
function getUserByPhone(phone) {
  return phone ? stmt.userByPhone.get(phone) || null : null;
}

function createUser(username, password, email = null, displayName = null, showDisplayName = false, phone = null, sharePhone = false) {
  const name = pw.normalizeUsername(username);
  const { salt, hash, algo } = pw.hashPassword(password);
  const id = crypto.randomUUID();
  stmt.insertUser.run(id, name, pw.normalizeEmail(email), salt, hash, algo, Date.now());
  // Отдельными UPDATE, а не в самом INSERT: так insertUser (общий и для
  // importUser тоже) не меняет число параметров, а вызывающему без имени и
  // телефона ничего лишнего задавать не нужно — колонки и так NULL/0 по умолчанию.
  if (displayName) stmt.updateProfile.run(displayName, showDisplayName ? 1 : 0, id);
  if (phone) stmt.updatePhone.run(phone, sharePhone ? 1 : 0, id);
  return getUserById(id);
}

/** Импорт из Finance: хэш переносится как есть, помечается legacy-алгоритмом. */
function importUser(username, salt, hash, createdAt = Date.now()) {
  const id = crypto.randomUUID();
  stmt.insertUser.run(id, pw.normalizeUsername(username), null, salt, hash, pw.ALGO_LEGACY, createdAt);
  return getUserById(id);
}

function setPassword(userId, password) {
  const { salt, hash, algo } = pw.hashPassword(password);
  stmt.updatePassword.run(salt, hash, algo, userId);
}

function setEmail(userId, email) {
  stmt.updateEmail.run(pw.normalizeEmail(email), userId);
}

/** phone — уже нормализованное значение или null, чтобы очистить. Отдельный
 *  флаг share_phone — сюда же, а не setProfile: делиться именем и телефоном
 *  можно независимо друг от друга. */
function setPhone(userId, phone, sharePhone) {
  stmt.updatePhone.run(phone, sharePhone ? 1 : 0, userId);
}

/** displayName — уже нормализованное значение (или null, чтобы очистить). */
function setProfile(userId, displayName, showDisplayName) {
  stmt.updateProfile.run(displayName, showDisplayName ? 1 : 0, userId);
}

/** Каскад по FK (sso_sessions/sessions/auth_codes/password_resets — все
 *  ON DELETE CASCADE, см. lib/db.js) убирает всё связанное сам, одним запросом. */
function deleteUser(userId) { stmt.deleteUser.run(userId); }

/** Доступ в Admin и к /internal/* остальных сервисов — см. lib/tokens.js (claim admin). */
function setAdmin(userId, on) { stmt.setAdmin.run(on ? 1 : 0, userId); }
/** Как в CLI (disable/enable): блокировка входа сама сессии не гасит, это отдельно. */
function setDisabled(userId, on) { stmt.setDisabled.run(on ? 1 : 0, userId); }

/**
 * Проверка пароля с прозрачным апгрейдом legacy-хэша на scrypt-v1.
 * Возвращает пользователя или null.
 */
function checkPassword(user, password) {
  if (!user || user.disabled) return null;
  if (!pw.verifyPassword(password, user.salt, user.hash, user.pwd_algo)) return null;
  if (user.pwd_algo === pw.ALGO_LEGACY) {
    setPassword(user.id, password);
    return getUserById(user.id);
  }
  return user;
}

/**
 * Готовые к показу имя и телефон — только если пользователь сам включил
 * соответствующий показ. Используются везде, где сервисы отображают личность
 * пользователя или ищут получателя перевода; сырые значения (кроме самого
 * владельца аккаунта, см. ownProfile) не отдаются — иначе утекали бы любому
 * сервису, которому пользователь дал токен, даже без согласия на показ.
 * Имя и телефон включаются НЕЗАВИСИМО друг от друга — это два разных решения.
 */
const computedName = u => (u.show_display_name && u.display_name) ? u.display_name : null;
const computedPhone = u => (u.share_phone && u.phone) ? u.phone : null;

const publicUser = u => u && ({
  id: u.id, username: u.username, email: u.email || null,
  name: computedName(u), phone: computedPhone(u),
});

/** Сырые значения для формы редактирования — отдаются только владельцу аккаунта. */
const ownProfile = u => ({
  displayName: u.display_name || "",
  showDisplayName: !!u.show_display_name,
  phone: u.phone || "",
  sharePhone: !!u.share_phone,
  emailVerified: !!u.email_verified,
});

/* ---------- клиенты ---------- */

function getClient(clientId) {
  const row = stmt.clientById.get(String(clientId || ""));
  if (!row) return null;
  return {
    ...row,
    redirect_uris: JSON.parse(row.redirect_uris || "[]"),
    origins: JSON.parse(row.origins || "[]"),
  };
}
function listClients() { return stmt.listClients.all().map(r => getClient(r.client_id)); }
function upsertClient(clientId, name, redirectUris, origins) {
  stmt.upsertClient.run(String(clientId), String(name), JSON.stringify(redirectUris || []), JSON.stringify(origins || []), Date.now());
  return getClient(clientId);
}
function deleteClient(clientId) { stmt.deleteClient.run(String(clientId)); }

/** redirect_uri сверяется побайтово со списком — никаких префиксов и wildcard'ов. */
function redirectAllowed(client, redirectUri) {
  return !!client && client.redirect_uris.includes(String(redirectUri || ""));
}

/**
 * Все origin'ы всех клиентов — для CORS. Кэш живёт минуту, а не вечно: клиента
 * часто заводят командой `client-add` в отдельном процессе, и вечный кэш означал
 * бы, что новый сервис не работает до перезапуска auth.
 */
const ORIGIN_CACHE_TTL = 60 * 1000;
let originCache = null, originCacheAt = 0;
function allowedOrigins() {
  if (!originCache || Date.now() - originCacheAt > ORIGIN_CACHE_TTL) {
    originCache = new Set(listClients().flatMap(c => c.origins));
    originCacheAt = Date.now();
  }
  return originCache;
}
function invalidateOrigins() { originCache = null; }

/* ---------- SSO-сессии (кука на auth-домене) ---------- */

function createSso(userId, { userAgent = null, ip = null } = {}) {
  const id = crypto.randomUUID();
  const now = Date.now();
  stmt.insertSso.run(id, userId, now, now, now + cfg.SSO_TTL, userAgent, ip);
  return id;
}
function getSso(id) {
  const row = id ? stmt.ssoById.get(String(id)) : null;
  if (!row || row.revoked_at || row.expires_at < Date.now()) return null;
  return row;
}
/** Продлеваем не чаще раза в час — иначе запись в БД на каждый заход. */
const TOUCH_INTERVAL = 60 * 60 * 1000;
function touchSso(row) {
  const now = Date.now();
  if (now - row.last_seen < TOUCH_INTERVAL) return;
  stmt.touchSso.run(now, now + cfg.SSO_TTL, row.id);
}
function revokeSso(id, { withSessions = true } = {}) {
  const now = Date.now();
  stmt.revokeSso.run(now, id);
  if (withSessions) stmt.revokeSessionsOfSso.run(now, "sso-logout", id);
}
function listSso(userId) { return stmt.listSso.all(userId, Date.now()); }
/** Окошко «добавьте почту» пропустили — молчим до конца этой SSO-сессии. */
function dismissEmailPrompt(ssoId) { stmt.dismissEmailPrompt.run(ssoId); }

/* ---------- одноразовые коды ---------- */

function createCode({ userId, clientId, redirectUri, codeChallenge, ssoId }) {
  const code = newToken();
  const now = Date.now();
  stmt.insertCode.run(sha256(code), userId, clientId, redirectUri, codeChallenge, ssoId || null, now, now + cfg.CODE_TTL);
  return code;
}

/**
 * Обмен кода. Возвращает { ok, code } либо { error }.
 * Повторное предъявление уже использованного кода — признак перехвата:
 * гасим сессию, которая была по нему выдана.
 */
function consumeCode(code, { clientId, redirectUri, codeVerifier }) {
  const row = stmt.codeByHash.get(sha256(code));
  if (!row) return { error: "invalid_grant" };
  if (row.used_at) {
    if (row.session_id) stmt.revokeSession.run(Date.now(), "code-replay", row.session_id);
    return { error: "code_reused" };
  }
  if (row.expires_at < Date.now()) return { error: "expired_code" };
  if (row.client_id !== clientId || row.redirect_uri !== redirectUri) return { error: "invalid_grant" };

  const challenge = crypto.createHash("sha256").update(String(codeVerifier || "")).digest("base64url");
  if (challenge !== row.code_challenge) return { error: "invalid_verifier" };

  return { ok: true, code: row };
}
function markCodeUsed(codeHash, sessionId) { stmt.useCode.run(Date.now(), sessionId, codeHash); }

/* ---------- refresh-сессии ---------- */

function createSession({ userId, clientId, ssoId, userAgent = null, ip = null }) {
  const id = crypto.randomUUID();
  const refresh = newToken();
  const now = Date.now();
  stmt.insertSession.run(id, userId, clientId, ssoId || null, sha256(refresh), now, now, now + cfg.REFRESH_TTL, userAgent, ip);
  return { id, refresh };
}

/**
 * Ротация refresh-токена. Старый становится prev_hash: если его предъявят ещё раз
 * (а он одноразовый), значит токен утёк — гасим всю сессию целиком.
 */
function rotateRefresh(token) {
  const h = sha256(token);
  let row = stmt.sessionByRefresh.get(h);
  if (!row) {
    const stolen = stmt.sessionByPrev.get(h);
    if (stolen && !stolen.revoked_at) {
      stmt.revokeSession.run(Date.now(), "refresh-reuse", stolen.id);
      return { error: "refresh_reused", session: stolen };
    }
    return { error: "invalid_grant" };
  }
  if (row.revoked_at) return { error: "revoked" };
  if (row.expires_at < Date.now()) return { error: "expired" };

  const next = newToken();
  const now = Date.now();
  stmt.rotateSession.run(sha256(next), now, now + cfg.REFRESH_TTL, row.id);
  return { ok: true, session: stmt.sessionById.get(row.id), refresh: next };
}

function revokeByRefresh(token) {
  const row = stmt.sessionByRefresh.get(sha256(token)) || stmt.sessionByPrev.get(sha256(token));
  if (!row) return false;
  stmt.revokeSession.run(Date.now(), "revoked", row.id);
  return true;
}
function revokeSession(id, why = "revoked") { stmt.revokeSession.run(Date.now(), why, id); }
function revokeAllSessions(userId, why = "password-change") { stmt.revokeSessionsOfUser.run(Date.now(), why, userId); }
function revokeOtherSessions(userId, keepId, why = "password-change") { stmt.revokeOthersOfUser.run(Date.now(), why, userId, keepId); }
function getSession(id) { return stmt.sessionById.get(String(id || "")) || null; }
function listSessions(userId) { return stmt.listSessions.all(userId, Date.now()); }

/* ---------- сброс пароля по ссылке ---------- */

/** Токен — как auth_codes: хранится только sha256, живёт cfg.RESET_TOKEN_TTL, одноразовый. */
function createPasswordReset(userId) {
  const token = newToken();
  const now = Date.now();
  stmt.insertReset.run(sha256(token), userId, now, now + cfg.RESET_TOKEN_TTL);
  return token;
}
/** { ok, userId, tokenHash } либо { error }. */
function consumePasswordReset(token) {
  const hash = sha256(String(token || ""));
  const row = stmt.resetByHash.get(hash);
  if (!row) return { error: "invalid_token" };
  if (row.used_at) return { error: "used_token" };
  if (row.expires_at < Date.now()) return { error: "expired_token" };
  return { ok: true, userId: row.user_id, tokenHash: hash };
}
function markResetUsed(tokenHash) { stmt.useReset.run(Date.now(), tokenHash); }

/* ---------- подтверждение почты по ссылке ---------- */

/** email — привязан к токену, не только к user_id (см. схему в lib/db.js):
 *  если человек сменит почту до перехода по старой ссылке, токен не должен
 *  подтвердить уже другой адрес. */
function createEmailVerification(userId, email) {
  const token = newToken();
  const now = Date.now();
  stmt.insertEverify.run(sha256(token), userId, email, now, now + cfg.EMAIL_VERIFY_TTL);
  return token;
}
/** { ok, userId, email, tokenHash } либо { error }. */
function consumeEmailVerification(token) {
  const hash = sha256(String(token || ""));
  const row = stmt.everifyByHash.get(hash);
  if (!row) return { error: "invalid_token" };
  if (row.used_at) return { error: "used_token" };
  if (row.expires_at < Date.now()) return { error: "expired_token" };
  return { ok: true, userId: row.user_id, email: row.email, tokenHash: hash };
}
function markVerifyUsed(tokenHash) { stmt.useEverify.run(Date.now(), tokenHash); }
function markEmailVerified(userId) { stmt.markEmailVerified.run(userId); }

/** Разовая уборка протухших записей — вызывается по таймеру из server.js. */
function purgeExpired() {
  const now = Date.now();
  stmt.purgeCodes.run(now);
  stmt.purgeSessions.run(now - 7 * 24 * 60 * 60 * 1000);
  stmt.purgeResets.run(now - 7 * 24 * 60 * 60 * 1000);
  stmt.purgeEverify.run(now - 7 * 24 * 60 * 60 * 1000);
}

module.exports = {
  sha256,
  getUserById, getUserByName, getUserByEmail, getUserByIdentifier, getUserByPhone, createUser, importUser,
  setPassword, setEmail, setPhone, setProfile, deleteUser, checkPassword, publicUser, ownProfile,
  setAdmin, setDisabled,
  countUsers: () => stmt.countUsers.get().n,
  countAdmins: () => stmt.countAdmins.get().n,
  countActiveSessions: () => stmt.countActiveSessions.get(Date.now()).n,
  countActiveSso: () => stmt.countActiveSso.get(Date.now()).n,
  countUsersSince: ts => stmt.countUsersSince.get(ts).n,
  listUsers: () => stmt.listUsers.all(),
  getClient, listClients, upsertClient, deleteClient, redirectAllowed, allowedOrigins, invalidateOrigins,
  createSso, getSso, touchSso, revokeSso, listSso, dismissEmailPrompt,
  createCode, consumeCode, markCodeUsed,
  createSession, rotateRefresh, revokeByRefresh, revokeSession, revokeAllSessions, revokeOtherSessions,
  getSession, listSessions, purgeExpired,
  createPasswordReset, consumePasswordReset, markResetUsed,
  createEmailVerification, consumeEmailVerification, markVerifyUsed, markEmailVerified,
};
