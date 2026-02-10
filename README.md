# AVQON Monitor MVP 0.1

Сервис мониторинга копирования контента в Telegram. Часть экосистемы **AVQON**.

**Архитектура:** Telegram-бот (интерфейс) + Data Fetcher (сбор постов) + Analysis Worker (сравнение по pHash и тексту) + PostgreSQL + планировщик. Всё разворачивается на одном сервере.

## Компоненты

| Компонент | Назначение |
|-----------|------------|
| **Бот** | `/start`, `/connect @channel`, `/stats`, уведомления о найденных копиях |
| **Data Fetcher** | Подписка на каналы, парсинг постов → `raw_posts` |
| **Analysis Worker** | pHash для изображений, сравнение текста → `content_hashes`, `matches` |
| **Notifier** | Отправка уведомлений по записям в `matches` |
| **Scheduler** | Запуск fetcher и worker по расписанию (по умолчанию каждые 30 мин) |

## Установка

```bash
cd avqon-monitor
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

## Конфигурация

Переменные окружения (или создайте `.env` и подставьте значения):

| Переменная | Описание |
|------------|----------|
| `AVQON_DATABASE_URL` | **Обязательно.** PostgreSQL: `postgresql://user:password@host:5432/dbname` |
| `AVQON_TELEGRAM_BOT_TOKEN` | Токен бота (BotFather) — **обязательно** для бота и уведомлений |
| `AVQON_TELEGRAM_API_ID` | API ID с .[mytelegram.org](https://my.telegram.org) — для Data Fetcher и Worker |
| `AVQON_TELEGRAM_API_HASH` | API Hash — для Data Fetcher и Worker |
| `AVQON_TELEGRAM_SESSION` | Имя файла сессии Telethon (по умолчанию `avqon_monitor`) |
| `AVQON_FETCH_INTERVAL` | Интервал сбора постов, мин (по умолчанию 30) |
| `AVQON_ANALYSIS_INTERVAL` | Интервал анализа, мин (по умолчанию 30) |
| `AVQON_MATCH_LOOKBACK_DAYS` | Окно поиска совпадений, дней (по умолчанию 30) |
| `AVQON_PHASH_THRESHOLD` | Порог Хэмминга для pHash (по умолчанию 10) |
| `AVQON_TEXT_SIMILARITY_THRESHOLD` | Порог совпадения текста 0–1 (по умолчанию 0.85) |
| `AVQON_API_DELAY` | Задержка между запросами к API Telegram, сек |
| `AVQON_TELEGRAM_PROXY` | Опционально: `socks5://user:pass@host:port` |

База данных: **PostgreSQL**. Укажите `AVQON_DATABASE_URL` (например `postgresql://user:password@localhost:5432/avqon_monitor`). При первом запуске схема создаётся автоматически. Перед запуском создайте БД: `createdb avqon_monitor`.

## Первый запуск

1. **Создать бота** в Telegram (@BotFather), получить токен → `AVQON_TELEGRAM_BOT_TOKEN`.
2. **Получить API ID и Hash** на [my.telegram.org](https://my.telegram.org) → `AVQON_TELEGRAM_API_ID`, `AVQON_TELEGRAM_API_HASH`.
3. **Один раз авторизовать Telethon** (создаётся сессия для Data Fetcher и Worker):
   ```bash
   set AVQON_TELEGRAM_BOT_TOKEN=...
   set AVQON_TELEGRAM_API_ID=...
   set AVQON_TELEGRAM_API_HASH=...
   python -c "
   import asyncio
   from telethon import TelegramClient
   import os
   from pathlib import Path
   p = Path('data'); p.mkdir(exist_ok=True)
   client = TelegramClient('data/avqon_monitor', int(os.environ['AVQON_TELEGRAM_API_ID']), os.environ['AVQON_TELEGRAM_API_HASH'])
   asyncio.run(client.start())
   print('Session saved.')
   "
   ```
4. **Запустить бота:**
   ```bash
   python run_bot.py
   ```
5. В Telegram: `/start`, затем `/connect @ваш_канал` (нужны права администратора канала).
6. **Запустить планировщик** (сбор + анализ + уведомления по расписанию):
   ```bash
   python run_scheduler.py
   ```

Либо вручную:

- `python run_fetcher.py` — один проход сбора постов;
- `python run_worker.py` — один проход анализа;
- `python run_notifier.py` — отправить накопленные уведомления о совпадениях.

## Структура проекта

```
avqon-monitor/
├── config.py           # Конфигурация
├── db/
│   ├── schema.sql      # Схема БД
│   ├── database.py     # Подключение SQLite
│   └── models.py       # Операции с таблицами
├── bot/
│   ├── main.py         # Запуск бота
│   └── handlers.py     # /start, /connect, /stats, уведомления
├── worker/
│   ├── data_fetcher.py # Сбор постов (Telethon)
│   └── analysis_worker.py # pHash, текст, matches
├── scheduler.py        # Планировщик (APScheduler)
├── run_bot.py
├── run_fetcher.py
├── run_worker.py
├── run_notifier.py
├── run_scheduler.py
├── data/               # Сессии Telethon (БД — PostgreSQL на сервере)
├── logs/
└── requirements.txt
```

## Риски и ограничения MVP

- **Лимиты Telegram API** — соблюдайте задержки (`AVQON_API_DELAY`), при 429 увеличивайте паузы.
- **Права администратора** — проверка через `get_chat_member`; бот должен быть в канале с правами.
- На MVP мониторируются только те каналы, которые пользователь явно подключает через `/connect` (и с которых идёт сбор). Добавление отдельных «целевых» каналов для мониторинга можно ввести в следующих версиях.

---

Экосистема **AVQON** — защита и мониторинг контента.
