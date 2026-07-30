"use strict";
/**
 * Страницы auth-домена: форма входа/регистрации и личный кабинет.
 *
 * Работает по куке сессии (её ставит сервер), поэтому никаких токенов здесь
 * не хранится и в localStorage ничего не кладётся.
 */

const $ = id => document.getElementById(id);
const params = new URLSearchParams(location.search);

/* Параметры запроса от сервиса: есть — значит нас позвал /authorize и после
   входа надо вернуться обратно с кодом. Нет — обычный заход на auth-домен. */
const flow = params.get("client_id") ? {
  client_id: params.get("client_id"),
  redirect_uri: params.get("redirect_uri") || "",
  state: params.get("state") || "",
  code_challenge: params.get("code_challenge") || "",
  code_challenge_method: params.get("code_challenge_method") || "",
} : null;

let mode = "login";        // login | register
let session = null;        // { authenticated, user, registerClosed, registerCode }

/* ---------- мелочи ---------- */

function snack(text) {
  const el = $("snack");
  el.textContent = text;
  el.classList.add("show");
  clearTimeout(snack.t);
  snack.t = setTimeout(() => el.classList.remove("show"), 2600);
}

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  let data = {};
  try { data = await res.json(); } catch { /* пустой ответ */ }
  return { ok: res.ok, status: res.status, data };
}

const show = (id, on) => $(id).classList.toggle("hidden", !on);

/**
 * Раскрывает/сворачивает блок, подставляя высоту замером содержимого.
 * Замер делается в момент открытия — поэтому состав полей внутри нужно
 * определить ДО вызова (например, показать или спрятать код приглашения).
 */
function revealToggle(box, open) {
  box.classList.remove("done");          // снова ограничиваем высоту, чтобы было что анимировать

  if (!open) {
    // Из height:auto переход не запустится — сначала фиксируем текущую
    // высоту числом и только следующим шагом уводим её в ноль.
    box.style.height = box.offsetHeight + "px";
    void box.offsetHeight;
    box.classList.remove("open");
    box.style.height = "0px";
    return;
  }

  box.classList.add("open");
  const h = box.firstElementChild.offsetHeight;
  // Замер мог не удаться — например, блок раскрывают, пока карточка ещё
  // скрыта. Лучше показать поля без анимации, чем оставить пользователя
  // перед пустотой, в которой не видно, что вводить.
  if (h > 0) box.style.height = h + "px";
  else { box.style.height = "auto"; box.classList.add("done"); }
}

/* По окончании раскрытия высота становится auto: фиксированное число обрезало
   бы обводку фокуса и не пережило бы изменение содержимого или ширины окна. */
document.addEventListener("transitionend", e => {
  const box = e.target;
  if (e.propertyName !== "height" || !box.classList || !box.classList.contains("open")) return;
  // Высоту снимаем ТЕМ ЖЕ способом, каким ставили: инлайновое значение
  // перебивает любое правило из таблицы стилей, и классом его не отпустить.
  box.style.height = "auto";
  box.classList.add("done");     // класс отвечает только за overflow
});

/* ---------- форма входа ---------- */

function renderLoginMode() {
  const reg = mode === "register";
  $("loginTitle").textContent = reg ? "Регистрация" : "Вход";
  $("loginSubmit").textContent = reg ? "Зарегистрироваться" : "Войти";
  $("loginToggle").textContent = reg ? "Уже есть аккаунт? Войти" : "Нет аккаунта? Зарегистрироваться";
  $("fPass").autocomplete = reg ? "new-password" : "current-password";
  // Состав полей решаем ДО раскрытия: высота считается замером, и код
  // приглашения должен быть уже на своём месте, иначе не попадёт в замер.
  show("fCodeWrap", reg && !!(session && session.registerCode));
  // Блок раскрывается целиком — по одному поля «выпрыгивали» бы вразнобой.
  revealToggle($("regFields"), reg);
  show("loginToggle", !(session && session.registerClosed));
  $("loginErr").textContent = "";
}

async function describeFlow() {
  if (!flow) return;
  const { ok, data } = await api("/api/client?client_id=" + encodeURIComponent(flow.client_id));
  if (ok && data.name) $("loginDesc").textContent = `Вход в «${data.name}» через единый аккаунт BurningHouse.`;
}

async function submitLogin(ev) {
  ev.preventDefault();
  const err = $("loginErr");
  err.textContent = "";

  const username = $("fUser").value.trim();
  const password = $("fPass").value;
  if (!username || !password) { err.textContent = "Введите логин и пароль"; return; }

  const body = { username, password, ...(flow || {}) };
  let endpoint = "/api/authorize/login";

  if (mode === "register") {
    if (password !== $("fPass2").value) { err.textContent = "Пароли не совпадают"; return; }
    const email = $("fEmail").value.trim();
    if (email) body.email = email;
    const code = $("fCode").value.trim();
    if (code) body.code = code;
    endpoint = "/api/authorize/register";
  }

  const btn = $("loginSubmit");
  btn.disabled = true;
  try {
    const { ok, data } = await api(endpoint, { method: "POST", body });
    if (!ok) { err.textContent = data.message || "Не удалось войти"; return; }
    // Сервер уже поставил куку сессии; redirect ведёт либо обратно в сервис с
    // одноразовым кодом, либо сюда же — на страницу аккаунта.
    location.replace(data.redirect || "/");
  } catch {
    err.textContent = "Не удалось подключиться к серверу";
  } finally {
    btn.disabled = false;
  }
}

/* ---------- личный кабинет ---------- */

function renderUser(user) {
  $("acAvatar").textContent = (user.username[0] || "?").toUpperCase();
  $("acName").textContent = user.username;
  $("acMail").textContent = user.email || "почта не указана";
  $("mailValue").value = user.email || "";
}

function fmtWhen(ts) {
  const d = new Date(ts);
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  const time = d.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
  return sameDay ? `сегодня в ${time}` : d.toLocaleDateString("ru-RU", { day: "numeric", month: "long" }) + `, ${time}`;
}

/* Из user-agent берём только то, что человек узнает: браузер и систему. */
function shortAgent(ua) {
  if (!ua) return "неизвестное устройство";
  const os = /Android/i.test(ua) ? "Android"
    : /iPhone|iPad|iPod/i.test(ua) ? "iOS"
    : /Windows/i.test(ua) ? "Windows"
    : /Mac OS X/i.test(ua) ? "macOS"
    : /Linux/i.test(ua) ? "Linux" : "";
  const br = /Edg\//.test(ua) ? "Edge"
    : /OPR\//.test(ua) ? "Opera"
    : /YaBrowser/.test(ua) ? "Яндекс.Браузер"
    : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome"
    : /Safari\//.test(ua) ? "Safari" : "";
  return [br, os].filter(Boolean).join(" · ") || "неизвестное устройство";
}

function sessionRow(item, isCurrent) {
  const el = document.createElement("div");
  el.className = "session";
  const title = item.kind === "browser" ? shortAgent(item.userAgent) : item.clientName;
  const desc = item.kind === "browser"
    ? `Вход на auth-домене · последний раз ${fmtWhen(item.lastSeen)}`
    : `${shortAgent(item.userAgent)} · последний раз ${fmtWhen(item.lastSeen)}`;
  el.innerHTML = `<div class="meta"><div class="title"></div><div class="desc"></div></div>`;
  el.querySelector(".title").textContent = title;
  el.querySelector(".desc").textContent = desc;

  if (isCurrent) {
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = "это устройство";
    el.querySelector(".meta .title").after(badge);
  }
  const btn = document.createElement("button");
  btn.className = "btn small danger";
  btn.type = "button";
  btn.textContent = "Отозвать";
  btn.onclick = () => revokeSession(item.id, isCurrent);
  el.append(btn);
  return el;
}

async function loadSessions() {
  const list = $("sessList");
  const { ok, data } = await api("/api/account/sessions");
  if (!ok) { list.innerHTML = '<div class="empty">Не удалось загрузить список</div>'; return; }

  list.textContent = "";
  const rows = [
    ...data.browsers.map(b => [b, b.id === data.current.ssoId]),
    ...data.apps.map(a => [a, a.id === data.current.sid]),
  ];
  if (!rows.length) { list.innerHTML = '<div class="empty">Активных сессий нет</div>'; return; }
  for (const [item, isCurrent] of rows) list.append(sessionRow(item, isCurrent));
}

async function revokeSession(id, isCurrent) {
  if (isCurrent && !confirm("Это текущее устройство — вы выйдете из аккаунта. Продолжить?")) return;
  const { ok } = await api("/api/account/sessions/" + encodeURIComponent(id), { method: "DELETE" });
  if (!ok) return snack("Не удалось отозвать");
  if (isCurrent) return location.replace("/");
  snack("Доступ отозван");
  loadSessions();
}

async function changePassword(ev) {
  ev.preventDefault();
  const err = $("pwErr");
  err.textContent = "";
  const currentPassword = $("pwCur").value, newPassword = $("pwNew").value;
  if (!currentPassword || !newPassword) { err.textContent = "Заполните все поля"; return; }
  if (newPassword !== $("pwNew2").value) { err.textContent = "Новые пароли не совпадают"; return; }

  const { ok, data } = await api("/api/account/password", { method: "PUT", body: { currentPassword, newPassword } });
  if (!ok) { err.textContent = data.message || "Не удалось сменить пароль"; return; }
  $("pwForm").reset();
  snack("Пароль изменён");
  loadSessions();
}

async function saveEmail(ev) {
  ev.preventDefault();
  const err = $("mailErr");
  err.textContent = "";
  const password = $("mailPass").value;
  if (!password) { err.textContent = "Введите текущий пароль"; return; }

  const { ok, data } = await api("/api/account/email", { method: "PUT", body: { email: $("mailValue").value.trim(), password } });
  if (!ok) { err.textContent = data.message || "Не удалось сохранить почту"; return; }
  $("mailPass").value = "";
  session.user.email = data.email;
  renderUser(session.user);
  snack("Почта сохранена");
}

async function revokeAll() {
  if (!confirm("Отозвать доступ у всех сервисов? Во все проекты придётся войти заново.")) return;
  await api("/api/account/sessions", { method: "DELETE" });
  snack("Доступы отозваны");
  loadSessions();
}

async function logout() {
  const { data } = await api("/logout", { method: "POST" });
  location.replace(data.redirect || "/");
}

/* ---------- старт ---------- */

(async function init() {
  const res = await api("/api/session");
  session = res.data || {};

  if (session.authenticated && !flow) {
    document.title = "Аккаунт — BurningHouse";
    renderUser(session.user);
    show("accountCard", true);
    loadSessions();
    return;
  }

  // Есть сессия, но нас позвал сервис с prompt=login (или /authorize отдал форму) —
  // показываем вход; уже вошедшего пользователя подставим в поле логина.
  if (session.authenticated && session.user) $("fUser").value = session.user.username;

  mode = "login";
  renderLoginMode();
  show("loginCard", true);
  describeFlow();
  setTimeout(() => $("fUser").focus(), 100);
})();

$("loginForm").addEventListener("submit", submitLogin);
$("loginToggle").addEventListener("click", () => { mode = mode === "login" ? "register" : "login"; renderLoginMode(); });
$("pwForm").addEventListener("submit", changePassword);
$("mailForm").addEventListener("submit", saveEmail);
$("revokeAll").addEventListener("click", revokeAll);
$("logoutBtn").addEventListener("click", logout);
