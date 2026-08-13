# BurningHouse Auth — один образ: страницы входа + API.
# Зависимостей нет (чистый Node.js, хранилище — встроенный node:sqlite).
# node:24 — минимум для стабильного node:sqlite (в 22 он ещё за флагом).

FROM node:24-alpine

WORKDIR /app

# Только то, что нужно в рантайме
COPY server.js ./
COPY admin-internal.js ./
COPY index.html ./
COPY lib/ ./lib/
COPY assets/ ./assets/

# client/ в образ не кладём: это библиотеки для КОПИРОВАНИЯ в другие сервисы,
# самому auth они не нужны.

# Каталог данных (аккаунты, сессии, ключи подписи) — монтируется как volume.
RUN mkdir -p /app/data && chown -R node:node /app

USER node

ENV HOST=0.0.0.0
ENV PORT=8788
ENV DATA_DIR=/app/data

EXPOSE 8788
VOLUME ["/app/data"]

CMD ["node", "server.js"]
