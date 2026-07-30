"use strict";
/** Вся настройка — через переменные окружения, как в Finance. */

const num = (v, def) => (v == null || v === "" ? def : parseInt(v, 10));

const DEV = process.env.DEV === "1" || process.env.NODE_ENV === "development";

const config = {
  DEV,
  PORT: num(process.env.PORT, 8788),
  HOST: process.env.HOST || "127.0.0.1",

  // Публичный адрес сервиса. Попадает в iss токенов и в ссылки на страницах —
  // если он разъедется с реальным доменом, сервисы перестанут принимать токены.
  ISSUER: (process.env.ISSUER || "http://localhost:8788").replace(/\/+$/, ""),

  ACCESS_TTL: num(process.env.ACCESS_TTL, 15 * 60) * 1000,          // 15 минут
  REFRESH_TTL: num(process.env.REFRESH_TTL, 60 * 24 * 60 * 60) * 1000, // 60 дней, скользящий
  SSO_TTL: num(process.env.SSO_TTL, 60 * 24 * 60 * 60) * 1000,      // 60 дней
  CODE_TTL: num(process.env.CODE_TTL, 60) * 1000,                   // одноразовый код живёт минуту

  COOKIE_NAME: process.env.COOKIE_NAME || "bh_sso",
  // Secure-куку браузер не отдаст по http — на локальной разработке выключаем.
  COOKIE_SECURE: process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === "1" : !DEV,

  // Если задан — регистрация требует этот код (как REGISTER_CODE в Finance).
  REGISTER_CODE: process.env.REGISTER_CODE || "",
  // "1" — полностью закрыть саморегистрацию (аккаунты только через CLI).
  REGISTER_CLOSED: process.env.REGISTER_CLOSED === "1",

  LOGIN_MAX_ATTEMPTS: num(process.env.LOGIN_MAX_ATTEMPTS, 10),
  LOGIN_WINDOW: num(process.env.LOGIN_WINDOW, 15 * 60) * 1000,
};

module.exports = config;
