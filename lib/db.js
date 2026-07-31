"use strict";
/**
 * Хранилище auth-сервиса — SQLite через встроенный node:sqlite (без npm-зависимостей).
 * Схема создаётся при первом запуске, дальше только дополняется (см. migrate()).
 */

const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "..", "data");
const DB_PATH = path.join(DATA_DIR, "auth.db");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode = WAL"); // конкурентные чтения не блокируют запись
db.exec("PRAGMA foreign_keys = ON");
db.exec("PRAGMA busy_timeout = 5000");

db.exec(`
  -- Аккаунты. Вход по username (как исторически в Finance), но наружу сервисам
  -- отдаётся стабильный UUID: логин теоретически можно будет сменить, id — нет.
  CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    email          TEXT UNIQUE,
    email_verified INTEGER NOT NULL DEFAULT 0,
    salt           TEXT NOT NULL,
    hash           TEXT NOT NULL,
    pwd_algo       TEXT NOT NULL,           -- 'scrypt-legacy' (импорт) | 'scrypt-v1'
    created_at     INTEGER NOT NULL,
    disabled       INTEGER NOT NULL DEFAULT 0,
    display_name       TEXT,                -- необязательное настоящее имя, отдельно от логина
    show_display_name  INTEGER NOT NULL DEFAULT 0  -- показывать его сервисам вместо логина?
  );

  -- Сервисы-потребители. redirect_uris/origins — JSON-массивы строк.
  CREATE TABLE IF NOT EXISTS clients (
    client_id      TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    redirect_uris  TEXT NOT NULL DEFAULT '[]',
    origins        TEXT NOT NULL DEFAULT '[]',
    created_at     INTEGER NOT NULL
  );

  -- Браузерная сессия на самом auth-домене (кука). Именно она делает вход
  -- сквозным: второй сервис редиректит на /authorize и получает код без пароля.
  CREATE TABLE IF NOT EXISTS sso_sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    user_agent TEXT,
    ip         TEXT
  );

  -- Одноразовые коды authorization code flow (TTL — секунды).
  CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash      TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    sso_id         TEXT,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    used_at        INTEGER,
    session_id     TEXT            -- какая сессия выдана по этому коду (для отзыва при реюзе)
  );

  -- Долгоживущие refresh-токены, по одному на связку (пользователь, сервис, устройство).
  -- Хранится sha256 от токена: утечка базы не даёт готовых токенов.
  CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id    TEXT NOT NULL,
    sso_id       TEXT,
    refresh_hash TEXT NOT NULL UNIQUE,
    prev_hash    TEXT,             -- предыдущий токен после ротации: реюз = кража
    created_at   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    revoked_why  TEXT,
    user_agent   TEXT,
    ip           TEXT
  );

  CREATE TABLE IF NOT EXISTS signing_keys (
    kid         TEXT PRIMARY KEY,
    private_pem TEXT NOT NULL,
    public_pem  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    retired_at  INTEGER
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_user     ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_prev     ON sessions(prev_hash);
  CREATE INDEX IF NOT EXISTS idx_sso_user          ON sso_sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_codes_expires     ON auth_codes(expires_at);
`);

// display_name/show_display_name добавлены после первого релиза — на уже
// существующей базе CREATE TABLE IF NOT EXISTS их не создаст. Тот же приём,
// что в Finance для миграции states: ALTER, ошибку "уже есть" молча глотаем.
try { db.exec("ALTER TABLE users ADD COLUMN display_name TEXT"); } catch { /* уже есть */ }
try { db.exec("ALTER TABLE users ADD COLUMN show_display_name INTEGER NOT NULL DEFAULT 0"); } catch { /* уже есть */ }

// db экспортируется в том числе и затем, чтобы оставаться достижимым: кэш
// модулей держит exports, а значит и саму базу. Если бы её никто не удерживал,
// V8 собрал бы объект, финализатор DatabaseSync закрыл бы соединение, и все
// подготовленные запросы посыпались бы с «statement has been finalized».
module.exports = { db, DATA_DIR, DB_PATH };
