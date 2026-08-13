"use strict";
/**
 * HTML/текст писем — отдельно от mailer.js (который только отправляет, не
 * знает про содержимое) и от server.js (который знает только ссылку и адрес).
 *
 * Почтовые клиенты — не браузеры: разметка таблицами вместо flex/grid (Outlook
 * их не понимает), все стили инлайн (многие клиенты вырезают <style>). Знак
 * сервиса (маленькая точка-акцент рядом с вордмарком) сознательно убран —
 * SVG в письмах не рендерится в доброй половине клиентов, а тащить ради
 * одной точки растровую картинку (свои проблемы с блокировкой внешних
 * изображений или раздутым весом data:-URI) того не стоит. Пламя остаётся
 * только полосой сверху — она чистый CSS-цвет, без зависимости от шрифта,
 * картинки или SVG, и рендерится одинаково везде.
 *
 * Тёмной темы у писем сознательно нет: поддержка prefers-color-scheme в
 * почтовых клиентах в лучшем случае частичная, а часть (Outlook.com, Windows
 * Mail) переизобретает цвета сама поверх любых стилей — надёжнее спроектировать
 * одну версию, которая читается везде, чем гнаться за тёмной, которая местами
 * сломается.
 */

const { escapeHtml } = require("./http");

/** Общий каркас — карточка с полосой пламени, вордмарком, заголовком, кнопкой
 *  и сноской. Конкретные письма только подставляют текст и ссылку. */
function shell({ preheader, heading, intro, buttonLabel, link, footNote }) {
  const safeLink = escapeHtml(link);
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#fff6ec;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">${escapeHtml(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#fff6ec;">
<tr><td align="center" style="padding:32px 16px;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#ffffff;border-radius:20px;border:1px solid #ece5d8;">
<tr><td style="height:4px;line-height:4px;font-size:0;background:#c2410c;border-radius:20px 20px 0 0;">&nbsp;</td></tr>
<tr><td style="padding:32px 36px 4px;">
  <div style="font-size:16px;font-weight:700;letter-spacing:-.01em;color:#1c1b20;">BurningHouse</div>
</td></tr>
<tr><td style="padding:22px 36px 0;">
  <h1 style="margin:0;font-size:22px;line-height:1.3;font-weight:600;color:#1c1b20;">${escapeHtml(heading)}</h1>
  <p style="margin:12px 0 0;font-size:15px;line-height:1.6;color:#46464f;">${intro}</p>
</td></tr>
<tr><td style="padding:28px 36px 4px;">
  <table role="presentation" cellpadding="0" cellspacing="0"><tr>
    <td style="border-radius:9999px;background:#5b4fe0;">
      <a href="${safeLink}" style="display:inline-block;padding:14px 34px;font-size:15px;font-weight:600;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#ffffff;text-decoration:none;border-radius:9999px;">${escapeHtml(buttonLabel)}</a>
    </td>
  </tr></table>
</td></tr>
<tr><td style="padding:18px 36px 0;">
  <p style="margin:0;font-size:13px;line-height:1.5;color:#918f9a;">
    Если кнопка не открывается, скопируйте ссылку целиком:<br>
    <a href="${safeLink}" style="color:#5b4fe0;word-break:break-all;">${safeLink}</a>
  </p>
</td></tr>
<tr><td style="padding:28px 36px 32px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="border-top:1px solid #ece5d8;padding-top:18px;">
    <p style="margin:0;font-size:13px;line-height:1.5;color:#918f9a;">${escapeHtml(footNote)}</p>
  </td></tr></table>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`;
}

function passwordReset({ link }) {
  const html = shell({
    preheader: "Ссылка действует 30 минут и работает один раз.",
    heading: "Восстановление пароля",
    intro: "Кто-то запросил новый пароль. Если это были вы — перейдите по кнопке ниже. Ссылка действует 30 минут и работает один раз.",
    buttonLabel: "Сбросить пароль",
    link,
    footNote: "Не запрашивали сброс? Просто не открывайте письмо.",
  });

  const text = `Восстановление пароля — BurningHouse

Кто-то запросил новый пароль. Если это были вы, перейдите по ссылке (действует 30 минут, работает один раз):

${link}

Не запрашивали сброс? Просто игнорируйте это письмо.`;

  return { subject: "Восстановление пароля — BurningHouse", html, text };
}

function emailVerify({ link }) {
  const html = shell({
    preheader: "Ссылка действует 24 часа.",
    heading: "Подтвердите почту",
    intro: "Этот адрес указан на аккаунте BurningHouse. Подтвердите его, чтобы на него можно было прислать письмо, если понадобится восстановить пароль.",
    buttonLabel: "Подтвердить почту",
    link,
    footNote: "Не указывали эту почту на BurningHouse? Просто не открывайте письмо.",
  });

  const text = `Подтвердите почту — BurningHouse

Этот адрес указан на аккаунте BurningHouse. Подтвердите его по ссылке (действует 24 часа):

${link}

Не указывали эту почту на BurningHouse? Просто игнорируйте это письмо.`;

  return { subject: "Подтвердите почту — BurningHouse", html, text };
}

module.exports = { passwordReset, emailVerify };
