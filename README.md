# AVQON — браузерное расширение для проверки ссылок и файлов

> **Статус: архив.** Командный проект (2025–2026), сервис закрыт. Репозиторий оставлен как пример архитектуры и инфраструктуры. Все ключи, логи и базы данных удалены из истории.

Расширение для Chrome проверяет URL и файлы на вредоносность через собственное API-ядро. Ядро объединяет локальный кэш и внешние сервисы проверки. На пике расширением пользовались **80+ человек**.

## Архитектура

```
 Chrome-расширение (avqon_start/)
   popup / sidepanel / content script
        │  HTTPS + WebSocket
        ▼
 Nginx ──► API-ядро (antivirus-core/, FastAPI + uvicorn, systemd)
              │            │
              │            ├─► VirusTotal / Google Safe Browsing / AbuseIPDB
              │            └─► WHOIS (возраст домена)
              ▼
         PostgreSQL (пользователи, ключи, кэш вердиктов, логи запросов)

 Админ-сервис (antivirus-core/new-admin-service/) — дашборд, ключи, логи
 Сайт (avqon-website/) — лендинг и оплата
 Telegram-бот — поддержка и уведомления
```

## Кто что делал

**Артём** ([@Artemy579](https://github.com/Artemy579)) и **Никита** ([@NKubarR](https://github.com/NKubarR)) — продукт и код:
- API-ядро на FastAPI: проверка URL и файлов, интеграции с VirusTotal, Google Safe Browsing, AbuseIPDB и WHOIS, кэш вердиктов, WebSocket-связь с расширением;
- авторизация (JWT), API-ключи и лимиты, оплата через ЮKassa;
- админ-сервис: дашборд, управление ключами, логи;
- браузерное расширение (Chrome, Manifest V3): popup, side panel, content script, native host;
- сайт и Telegram-бот.

**Никита Рябченко** ([@Rneeshka](https://github.com/Rneeshka)) — инфраструктура и деплой:
- сервер, сервисы под systemd, Nginx;
- два окружения, dev и prod, на одном сервере в разных каталогах и юнитах;
- CI/CD на GitHub Actions (`.github/workflows/`): пуш в `dev` выкатывает dev-окружение, тег `v*` — прод; доступ к серверу по SSH-ключу из GitHub Secrets;
- переезд с SQLite на PostgreSQL, бэкап и восстановление БД;
- разбор инцидентов, в том числе рассинхрона dev и prod.

## Найденная проблема в прод-деплое (исправлено)

В `deploy-prod.yml` команды на сервер передавались через heredoc в кавычках (`<< 'EOF'`), поэтому переменная `$GITHUB_REF_NAME` не подставлялась на раннере. На сервере она пустая, и `git checkout` без аргумента ничего не делал: прод перезапускался на той версии кода, что уже лежала на сервере, а не на выпущенном теге.

Исправление: тег передаётся явно через `env` и `TAG=$TAG bash -s`, на сервере выполняется `git checkout "$TAG"`.

## Стек

Python, FastAPI, uvicorn, aiohttp, PostgreSQL, Nginx, systemd, GitHub Actions, JavaScript (Chrome Extension Manifest V3), Docker Compose (админ-сервис).

## Локальный запуск ядра

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r antivirus-core/requirements.txt
cd antivirus-core
cp ../.env.example .env   # заполнить своими ключами
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Без ключей внешних сервисов ядро работает в базовом режиме, только на локальном кэше.

Основные эндпоинты: `GET /health`, `POST /check/url`, `POST /scan/url`, `POST /check/file`.
