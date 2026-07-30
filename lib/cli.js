"use strict";
/**
 * Команды обслуживания. Запускаются на сервере внутри контейнера:
 *   docker compose exec auth node server.js <команда>
 */

const path = require("path");
const { DatabaseSync } = require("node:sqlite");
const store = require("./store");
const keys = require("./keys");
const pwlib = require("./passwords");

const HELP = `
BurningHouse Auth — команды обслуживания

  users                                     список аккаунтов
  adduser <логин> <пароль> [почта]          создать аккаунт
  passwd  <логин> <пароль>                  сменить пароль
  disable <логин> | enable <логин>          заблокировать / разблокировать вход
  logout-all <логин>                        отозвать все сессии пользователя

  clients                                   список сервисов
  client-add <id> <название> <redirect-uri> [origin]
                                            зарегистрировать сервис (можно повторно — обновит)
  client-del <id>                           удалить сервис

  rotate-key                                выпустить новый ключ подписи
                                            (старый ещё сутки остаётся в JWKS)

  import-finance <путь к store.db>          перенести пользователей из «Моих финансов»
                                            с сохранением их текущих паролей

Без команды — обычный запуск HTTP-сервера.
`;

const fail = msg => { console.error(msg); process.exit(1); };
const fmtDate = ts => new Date(ts).toISOString().slice(0, 19).replace("T", " ");

function run(argv) {
  const [cmd, ...args] = argv;

  switch (cmd) {
    case "help": case "--help": case "-h":
      console.log(HELP.trim());
      break;

    case "users": {
      const rows = store.listUsers();
      if (!rows.length) return console.log("(пусто)");
      for (const u of rows) {
        console.log([
          u.username.padEnd(20),
          u.id,
          (u.email || "—").padEnd(28),
          u.pwd_algo.padEnd(14),
          fmtDate(u.created_at),
          u.disabled ? "ЗАБЛОКИРОВАН" : "",
        ].join("  ").trimEnd());
      }
      break;
    }

    case "adduser": {
      const [login, password, email] = args;
      if (!login || !password) fail("Использование: node server.js adduser <логин> <пароль> [почта]");
      const err = pwlib.validateCreds(login, password);
      if (err) fail(err);
      if (store.getUserByName(login)) fail("Такой логин уже занят");
      const mail = pwlib.normalizeEmail(email);
      const mailErr = pwlib.validateEmail(mail);
      if (mailErr) fail(mailErr);
      if (mail && store.getUserByEmail(mail)) fail("Эта почта уже привязана к другому аккаунту");
      const u = store.createUser(login, password, mail);
      console.log(`Аккаунт создан: ${u.username} (${u.id})`);
      break;
    }

    case "passwd": {
      const [login, password] = args;
      if (!login || !password) fail("Использование: node server.js passwd <логин> <пароль>");
      const u = store.getUserByName(login);
      if (!u) fail("Пользователь не найден");
      const err = pwlib.validateCreds(u.username, password);
      if (err) fail(err);
      store.setPassword(u.id, password);
      store.revokeAllSessions(u.id, "password-reset");
      console.log(`Пароль изменён: ${u.username}. Все сессии отозваны.`);
      break;
    }

    case "disable": case "enable": {
      const [login] = args;
      if (!login) fail(`Использование: node server.js ${cmd} <логин>`);
      const u = store.getUserByName(login);
      if (!u) fail("Пользователь не найден");
      const { db } = require("./db");
      db.prepare("UPDATE users SET disabled = ? WHERE id = ?").run(cmd === "disable" ? 1 : 0, u.id);
      if (cmd === "disable") store.revokeAllSessions(u.id, "disabled");
      console.log(`${u.username}: вход ${cmd === "disable" ? "заблокирован" : "разблокирован"}`);
      break;
    }

    case "logout-all": {
      const [login] = args;
      if (!login) fail("Использование: node server.js logout-all <логин>");
      const u = store.getUserByName(login);
      if (!u) fail("Пользователь не найден");
      store.revokeAllSessions(u.id, "admin");
      for (const s of store.listSso(u.id)) store.revokeSso(s.id);
      console.log(`Все сессии ${u.username} отозваны`);
      break;
    }

    case "clients": {
      const rows = store.listClients();
      if (!rows.length) return console.log("(пусто)");
      for (const c of rows) {
        console.log(`${c.client_id}  «${c.name}»`);
        console.log(`   redirect: ${c.redirect_uris.join(", ") || "—"}`);
        console.log(`   origins:  ${c.origins.join(", ") || "—"}`);
      }
      break;
    }

    case "client-add": {
      const [id, name, redirectUri, origin] = args;
      if (!id || !name || !redirectUri) fail("Использование: node server.js client-add <id> <название> <redirect-uri> [origin]");
      let derived;
      try { derived = new URL(redirectUri).origin; } catch { fail("redirect-uri должен быть полным URL"); }
      const existing = store.getClient(id);
      const redirects = new Set(existing ? existing.redirect_uris : []);
      const origins = new Set(existing ? existing.origins : []);
      redirects.add(redirectUri);
      origins.add(origin || derived);
      const c = store.upsertClient(id, name, [...redirects], [...origins]);
      console.log(`Сервис зарегистрирован: ${c.client_id}`);
      console.log(`   redirect: ${c.redirect_uris.join(", ")}`);
      console.log(`   origins:  ${c.origins.join(", ")}`);
      break;
    }

    case "client-del": {
      const [id] = args;
      if (!id) fail("Использование: node server.js client-del <id>");
      store.deleteClient(id);
      console.log(`Сервис удалён: ${id}`);
      break;
    }

    case "rotate-key": {
      const k = keys.rotate();
      console.log(`Новый ключ подписи: ${k.kid}. Старые остаются в JWKS ещё сутки, чтобы выданные токены дожили свой срок.`);
      break;
    }

    case "import-finance": {
      const [dbPath] = args;
      if (!dbPath) fail("Использование: node server.js import-finance <путь к store.db «Моих финансов»>");
      importFinance(path.resolve(dbPath));
      break;
    }

    default:
      console.error(`Неизвестная команда: ${cmd}\n`);
      console.log(HELP.trim());
      process.exit(1);
  }
}

/**
 * Перенос пользователей из «Моих финансов».
 *
 * Пароли сохраняются как есть: хэши считались там scrypt'ом, где соль
 * передавалась КАК СТРОКА. Помечаем их pwd_algo='scrypt-legacy' — при первом
 * же входе хэш прозрачно пересчитается в scrypt-v1 (см. checkPassword).
 *
 * Финансовые данные не трогаем вовсе: Finance сам перенесёт свой states на
 * user_id при первом обращении пользователя.
 */
function importFinance(dbPath) {
  let src;
  try {
    src = new DatabaseSync(dbPath, { readOnly: true });
  } catch (e) {
    fail(`Не удалось открыть ${dbPath}: ${e.message}`);
  }

  let rows;
  try {
    rows = src.prepare("SELECT username, salt, hash FROM users ORDER BY username").all();
  } catch (e) {
    fail(`В базе нет таблицы users (${e.message}). Это точно store.db «Моих финансов»?`);
  }

  let created = 0, skipped = 0;
  const mapping = [];
  for (const r of rows) {
    const existing = store.getUserByName(r.username);
    if (existing) {
      skipped++;
      mapping.push({ username: existing.username, user_id: existing.id, status: "уже был" });
      continue;
    }
    const u = store.importUser(r.username, r.salt, r.hash);
    created++;
    mapping.push({ username: u.username, user_id: u.id, status: "создан" });
  }
  src.close();

  for (const m of mapping) console.log(`${m.username.padEnd(20)}  ${m.user_id}  ${m.status}`);
  console.log(`\nИтого: создано ${created}, пропущено (уже существовали) ${skipped}.`);
  console.log("Пароли перенесены — пользователи входят своими старыми. Finance подтянет их данные сам при первом входе.");
}

module.exports = { run };
