"use strict";
/**
 * Отправка почты через Resend (https://resend.com/docs/api-reference/emails/send-email).
 * Обычный HTTP API — встроенного fetch() достаточно, SMTP-клиент не нужен,
 * так и остаёмся без npm-зависимостей.
 *
 * Без RESEND_API_KEY письма просто не уходят (и это пишется в консоль вместо
 * ошибки) — иначе локальная разработка без живого аккаунта Resend была бы
 * невозможна.
 */

const cfg = require("./config");

async function send({ to, subject, html, text }) {
  if (!cfg.RESEND_API_KEY) {
    // Текст письма — тоже в лог: без ключа это единственный способ разработчику
    // локально получить ссылку сброса и вручную проверить, что дальше работает.
    console.log(`[mailer] RESEND_API_KEY не задан — письмо не отправлено. Кому: ${to}, тема: «${subject}»\n${text || ""}`);
    return { ok: false };
  }
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${cfg.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: cfg.MAIL_FROM, to, subject, html, text }),
    });
    if (!res.ok) {
      console.error(`[mailer] Resend ответил ${res.status}: ${await res.text().catch(() => "")}`);
      return { ok: false };
    }
    return { ok: true };
  } catch (e) {
    console.error("[mailer] Не удалось отправить письмо:", e.message);
    return { ok: false };
  }
}

module.exports = { send };
