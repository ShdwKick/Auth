/**
 * Самая рискованная часть переезда: перенос паролей из «Моих финансов».
 * Хэш здесь считается ровно так же, как это делал их server.js (соль передаётся
 * СТРОКОЙ), импортируется — и старый пароль обязан подойти при входе.
 *
 * Запуск (Node 24; на Node 22 добавьте --experimental-sqlite):
 *   node test/legacy-passwords.mjs
 *
 * Сеть и порты не нужны: всё проверяется напрямую через lib/store.js.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { execFileSync } from "node:child_process";

const AUTH = path.resolve(fileURLToPath(import.meta.url), "../..");
const TMP = path.join(AUTH, "test", ".work-legacy");
const FIN_DB = TMP + "/store.db";
fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

// 1. Собираем базу «как у Finance» — код скопирован из его server.js дословно.
const db = new DatabaseSync(FIN_DB);
db.exec(`CREATE TABLE users (username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL);
         CREATE TABLE states (username TEXT PRIMARY KEY, data TEXT, updated_at INTEGER NOT NULL DEFAULT 0);`);

const PASSWORD = "СтарыйПароль-2024";
const salt = crypto.randomBytes(16).toString("hex");        // соль как 32-символьная hex-СТРОКА
const hash = crypto.scryptSync(PASSWORD, salt, 64).toString("hex");  // и передаётся строкой же
db.prepare("INSERT INTO users VALUES (?, ?, ?)").run("olduser", salt, hash);
db.prepare("INSERT INTO states VALUES (?, ?, ?)").run("olduser", JSON.stringify({ tx: [{ id: "1", amount: 100 }] }), Date.now());
db.close();

const env = { ...process.env, DATA_DIR: TMP + "/authdata" };
const run = (...args) => execFileSync(process.execPath, [...process.execArgv, "server.js", ...args], { cwd: AUTH, env, encoding: "utf8" });

// 2. Импортируем
console.log(run("import-finance", FIN_DB).trim());

// 3. Проверяем, что старый пароль подходит, а хэш после входа стал v1
process.env.DATA_DIR = TMP + "/authdata";
const store = await import(pathToFileURL(path.join(AUTH, "lib", "store.js")).href);

function ok(name, cond, extra = "") { console.log(`${cond ? "  OK  " : " FAIL "} ${name}${extra ? " — " + extra : ""}`); if (!cond) process.exitCode = 1; }

const before = store.default.getUserByName("olduser");
ok("пользователь импортирован", !!before, before && before.id);
ok("помечен legacy-алгоритмом", before.pwd_algo === "scrypt-legacy", before.pwd_algo);

const wrong = store.default.checkPassword(before, "не тот пароль");
ok("чужой пароль не подходит", !wrong);

const user = store.default.checkPassword(before, PASSWORD);
ok("СТАРЫЙ пароль из Finance подходит", !!user, user && user.username);

const after = store.default.getUserByName("olduser");
ok("после входа хэш переписан в scrypt-v1", after.pwd_algo === "scrypt-v1", after.pwd_algo);
ok("после апгрейда тот же пароль всё ещё подходит", !!store.default.checkPassword(after, PASSWORD));
ok("id не изменился при апгрейде", after.id === before.id);

// 4. Повторный импорт не должен плодить дубли
console.log(run("import-finance", FIN_DB).trim().split("\n").pop());
ok("повторный импорт идемпотентен", store.default.listUsers().length === 1, "аккаунтов: " + store.default.listUsers().length);

console.log(process.exitCode ? "\nЕсть провалы." : "\nПеренос паролей работает.");
