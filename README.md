# AVQON

Расширение для Chrome, которое проверяет ссылки и файлы на вредоносность. Делали втроём в 2025–2026, на пике было 80+ пользователей. Сейчас проект закрыт, репа лежит как архив.

Ключи, логи и базы из истории вычищены – в старой версии репы они лежали в открытую.

## Как устроено

```
 Chrome-расширение (avqon_start/)
        |  HTTPS + WebSocket
        v
 Nginx --> API-ядро (antivirus-core/, FastAPI, systemd)
              |         |
              |         +--> VirusTotal / Safe Browsing / AbuseIPDB / WHOIS
              v
         PostgreSQL

 Админка (antivirus-core/new-admin-service/)
 Сайт с оплатой (avqon-website/)
 Telegram-бот
```

Расширение отправляет ссылку или файл в ядро. Ядро сначала смотрит в свой кэш, если там пусто – спрашивает внешние сервисы и отдаёт вердикт.

## Кто что делал

Артём ([@Artemy579](https://github.com/Artemy579)) и Никита ([@NKubarR](https://github.com/NKubarR)) – весь продукт:
- ядро на FastAPI: проверка ссылок и файлов, интеграции с VirusTotal, Safe Browsing, AbuseIPDB, WHOIS, кэш, WebSocket
- авторизация, API-ключи и лимиты, оплата через ЮKassa
- админка
- само расширение (Manifest V3), сайт, бот

Я ([@Rneeshka](https://github.com/Rneeshka)) – инфраструктура:
- сервер, systemd, Nginx
- два окружения на одном сервере: dev и prod, разные каталоги и юниты
- CI/CD на GitHub Actions: пуш в `dev` – выкатывается dev, тег `v*` – выкатывается прод. Ключ от сервера лежит в GitHub Secrets
- переезд с SQLite на PostgreSQL, бэкапы
- разбор инцидентов, самый неприятный был с рассинхроном dev и prod

## Баг в деплое прода

Нашёл, когда чистил репу. В `deploy-prod.yml` команды уходили на сервер через heredoc в кавычках (`<< 'EOF'`). Из-за кавычек `$GITHUB_REF_NAME` не подставлялся на раннере и прилетал на сервер пустым. `git checkout` без аргумента ничего не делал – прод просто перезапускался на том коде, что уже лежал на сервере, а не на новом теге.

Поправил: тег передаю явно через `env` и `TAG=$TAG bash -s`, на сервере `git checkout "$TAG"`.

## Стек

Python, FastAPI, aiohttp, PostgreSQL, Nginx, systemd, GitHub Actions, JS (Chrome Extension), Docker Compose для админки.

## Запустить ядро локально

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r antivirus-core/requirements.txt
cd antivirus-core
cp ../.env.example .env   # свои ключи
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Без ключей тоже запустится, просто будет работать только на локальном кэше.

Эндпоинты: `GET /health`, `POST /check/url`, `POST /scan/url`, `POST /check/file`.
