# BurningHouse Auth — развёртывание

Единый вход для всех проектов на `burninghouse.ru`: один аккаунт, одна форма логина,
сквозная сессия между поддоменами.

Живёт по тем же правилам, что и «Мои финансы»: один образ = один контейнер за nginx на
своём поддомене, без npm-зависимостей, данные в SQLite внутри docker volume.

- Домен: `auth.burninghouse.ru`
- Порт внутри: `127.0.0.1:8788`
- Образ: `shadowkick/auth:latest`
- Каталог на сервере: `~/auth`
- Данные: volume `auth-data` (аккаунты, сессии, **приватные ключи подписи**)

---

## Как устроен вход

Упрощённый OAuth2 authorization code + PKCE — то же, чем пользуются Google и GitHub,
без лишних частей стандарта.

```
1. Пользователь жмёт «Войти» в сервисе
       ↓
2. Сервис уводит его на  auth.burninghouse.ru/authorize?client_id=…&code_challenge=…
       ↓
3. Есть кука сессии на auth-домене?
       да  → сразу редирект обратно (SSO: пароль не спрашиваем)
       нет → форма логина, после входа ставится кука
       ↓
4. Возврат в сервис: …/?code=<одноразовый код>&state=…
       ↓
5. Сервис меняет код на токены: POST /oauth/token
       → access-JWT (15 минут, EdDSA) + refresh-токен (60 дней, отзываемый)
       ↓
6. Дальше сервис проверяет access-токен САМ, по публичным ключам из
   /.well-known/jwks.json — сетевого запроса в auth на каждый вызов нет.
```

Почему так, а не «спрашивать auth про каждый токен»: auth перестаёт быть узким местом и
единой точкой отказа — если он ляжет, уже выданные токены продолжат работать до 15 минут,
а сервисы не заметят. Ценой этого отзыв срабатывает не мгновенно, а на следующем
обновлении токена; для отзыва «прямо сейчас» есть ротация ключа (`rotate-key`).

---

## Первое развёртывание

### Шаг 1. DNS

A-запись `auth.burninghouse.ru` → IP сервера. Дождитесь, пока `dig auth.burninghouse.ru`
(или `nslookup`) начнёт отдавать нужный адрес — без этого certbot не пройдёт проверку.

### Шаг 2. Сертификат

```bash
sudo certbot certonly --standalone -d auth.burninghouse.ru
```

Порт 80 на время выпуска должен быть свободен. Если там уже слушает nginx —
`sudo systemctl stop nginx`, выпустить, `sudo systemctl start nginx`.

### Шаг 3. nginx

```bash
sudo cp deploy/nginx-auth-443.conf /etc/nginx/sites-available/auth
sudo ln -s /etc/nginx/sites-available/auth /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Шаг 4. Запуск контейнера

На сервере нужен только `docker-compose.prod.yml` — исходники клонировать не обязательно:

```bash
mkdir -p ~/auth && cd ~/auth
# скопировать сюда docker-compose.prod.yml под именем docker-compose.yml
docker compose pull
docker compose up -d
docker compose logs -f auth
```

Проверка: `curl -s https://auth.burninghouse.ru/api/health` → `{"ok":true}` и
`curl -s https://auth.burninghouse.ru/.well-known/jwks.json` → ключ с `"crv":"Ed25519"`.

### Шаг 5. Зарегистрировать сервисы

Каждый проект, который будет пускать людей через auth, должен быть известен по имени и
точному адресу возврата:

```bash
docker compose exec auth node server.js client-add finance "Мои финансы" https://money.burninghouse.ru/
docker compose exec auth node server.js clients      # проверить
```

`redirect_uri` сверяется побайтово — лишний или недостающий слэш и вход не сработает
(это не придирка, а защита: свободный redirect_uri означал бы, что чужой сайт может
увести к себе код авторизации).

Список сервисов можно держать и прямо в compose — переменная `SEED_CLIENTS`,
она применяется при каждом старте.

### Шаг 6. Перенос существующих пользователей «Финансов»

Делать **до** того, как открывать регистрацию людям: иначе кто-то может занять логин,
который уже занят в старой базе Finance.

```bash
# базу Finance подключаем к контейнеру auth только на чтение и только на один запуск
docker run --rm \
  -v auth-data:/app/data \
  -v moi-finansy_finance-data:/finance:ro \
  shadowkick/auth:latest \
  node server.js import-finance /finance/store.db
```

(имя тома Finance посмотрите через `docker volume ls`)

Команда выведет таблицу «логин → user_id» и сколько аккаунтов создано. Пароли
переносятся как есть: люди входят своими старыми. Финансовые данные при этом не
трогаются — Finance сам перенесёт их на новый `user_id` при первом входе каждого.

Повторный запуск безопасен: уже существующие логины пропускаются.

### Шаг 7. CI/CD

Как в «Финансах»: GitHub Actions на пуш в `master`. Нужны:

1. Отдельный SSH-ключ (не тот же, что у Finance):
   ```bash
   ssh-keygen -t ed25519 -f auth_deploy -C "github-actions auth"
   # публичную часть — в ~/.ssh/authorized_keys пользователя github на сервере
   ```
2. В GitHub Environment `MyServerEnv` этого репозитория — секреты
   `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `SSH_KEY`, `SSH_HOST`, `SSH_USER`, `SSH_PORT`.

Дальше пуш в `master` сам собирает образ и обновляет контейнер.

---

## Подключение нового сервиса

Подробный рецепт с кодом — в `AUTH-INTEGRATION.md` репозитория «Мои финансы»
(там же лежит рабочий пример). Кратко:

1. `client-add <id> "<название>" <redirect-uri>` на auth-сервере.
2. Скопировать в проект `client/auth-client.js` (сервер) и
   `client/auth-client-browser.js` (фронт) — обе без зависимостей.
3. Задать сервису `AUTH_ISSUER` и `AUTH_CLIENT_ID`.

---

## Проверки перед выкатом

В репозитории лежат три скрипта, которые поднимают всё сами и проверяют схему целиком —
включая перенос паролей и сохранение сессий после рестарта. Подробности в
[test/README.md](test/README.md):

```bash
node test/legacy-passwords.mjs
node test/flow.mjs
node test/e2e.mjs
```

---

## Команды обслуживания

```bash
docker compose exec auth node server.js help                 # весь список

docker compose exec auth node server.js users                # аккаунты
docker compose exec auth node server.js adduser <логин> <пароль> [почта]
docker compose exec auth node server.js passwd  <логин> <пароль>   # + отзовёт все сессии
docker compose exec auth node server.js disable <логин>      # заблокировать вход
docker compose exec auth node server.js logout-all <логин>   # выкинуть со всех устройств

docker compose exec auth node server.js clients              # сервисы
docker compose exec auth node server.js client-add <id> <название> <redirect-uri> [origin]

docker compose exec auth node server.js rotate-key           # новый ключ подписи
```

**`rotate-key`** — единственный способ разом обнулить все выданные access-токены
(например, если есть подозрение на утечку). Старый ключ остаётся в JWKS ещё сутки,
чтобы живые токены дожили свой срок; если нужно жёстко и сразу — выполните команду
дважды. Сервисы подхватят новый ключ сами, увидев незнакомый `kid`.

---

## Резервное копирование

Volume `auth-data` — самое ценное во всей связке: там аккаунты, сессии и приватные ключи
подписи. Его потеря разлогинит всех во всех сервисах.

```bash
docker run --rm -v auth-data:/data -v "$PWD:/backup" alpine \
  tar czf /backup/auth-$(date +%F).tar.gz -C /data .
```

---

## Переменные окружения

Полный список — в `lib/config.js`. Основные:

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `ISSUER` | `http://localhost:8788` | **Обязательно в проде.** Публичный адрес; попадает в токены как `iss` и сверяется сервисами побайтово |
| `PORT` / `HOST` | `8788` / `127.0.0.1` | Где слушать |
| `DATA_DIR` | `./data` | Где лежит `auth.db` |
| `ACCESS_TTL` | `900` (15 мин) | Срок жизни access-токена, секунды |
| `REFRESH_TTL` | 60 дней | Срок refresh-токена, скользящий |
| `SSO_TTL` | 60 дней | Срок браузерной сессии на auth-домене |
| `SEED_CLIENTS` | — | JSON-массив сервисов, применяется при старте |
| `AUTH_USER` / `AUTH_PASS` | — | Создать первый аккаунт, если база пуста |
| `REGISTER_CODE` | — | Если задан — регистрация только по этому коду |
| `REGISTER_CLOSED` | — | `1` — саморегистрация запрещена совсем |
| `LOGIN_MAX_ATTEMPTS` | `10` | Попыток входа за окно, дальше 429 |
| `DEV` | — | `1` снимает флаг Secure с куки (только для http на localhost) |

---

## Если что-то не работает

**«Сервис не зарегистрирован в auth»** на странице входа — не сделан `client-add`,
либо `client_id` в сервисе не тот.

**«redirect_uri не совпадает…»** — адрес возврата отличается от зарегистрированного.
Сверьте побайтово, включая завершающий слэш: `clients` покажет, что записано.

**Сервис отвечает 401 на все запросы.** Проверьте, что его `AUTH_ISSUER` совпадает с
`ISSUER` auth-сервиса символ в символ (`https://` против `http://`, слэш на конце —
всё считается). Разойдутся — токены будут корректными, но чужими.

**Вход проходит, но сразу выкидывает обратно.** Скорее всего, кука не доехала: в проде
она `Secure`, то есть по `http://` браузер её не отдаст. Убедитесь, что открываете
`https://`, а nginx передаёт `X-Forwarded-Proto https`.

**После рестарта все разлогинились.** Значит, потерялся volume `auth-data` — вместе с
ним ушли ключи подписи и сессии. Проверьте, что в compose не `docker compose down -v`.
