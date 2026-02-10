# -*- coding: utf-8 -*-
"""
AVQON Monitor MVP 0.1 — конфигурация.
Экосистема AVQON: мониторинг копирования контента в Telegram.
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass

# Корень проекта
BASE_DIR = Path(__file__).resolve().parent

# Telegram Bot (получить у @BotFather)
TELEGRAM_BOT_TOKEN = os.environ.get("AVQON_TELEGRAM_BOT_TOKEN", "")

# Telegram API (my.telegram.org — для Data Fetcher)
TELEGRAM_API_ID = int(os.environ.get("AVQON_TELEGRAM_API_ID", "0"))
TELEGRAM_API_HASH = os.environ.get("AVQON_TELEGRAM_API_HASH", "")

# Сессия Telethon (файл создаётся после первого входа)
TELEGRAM_SESSION_NAME = os.environ.get("AVQON_TELEGRAM_SESSION", "avqon_monitor")

# База данных (PostgreSQL)
# Формат: postgresql://user:password@host:port/dbname
DATABASE_URL = os.environ.get(
    "AVQON_DATABASE_URL",
    "postgresql://avqon:avqon@localhost:5432/avqon_monitor",
)

# Планировщик: интервал запуска сборщика и воркера (минуты)
FETCH_INTERVAL_MINUTES = int(os.environ.get("AVQON_FETCH_INTERVAL", "30"))
ANALYSIS_INTERVAL_MINUTES = int(os.environ.get("AVQON_ANALYSIS_INTERVAL", "30"))

# Анализ: окно дней для поиска совпадений
MATCH_LOOKBACK_DAYS = int(os.environ.get("AVQON_MATCH_LOOKBACK_DAYS", "30"))

# Порог pHash: расстояние Хэмминга <= N считаем совпадением
PHASH_HAMMING_THRESHOLD = int(os.environ.get("AVQON_PHASH_THRESHOLD", "10"))

# Порог совпадения текста (0.0–1.0)
TEXT_SIMILARITY_THRESHOLD = float(os.environ.get("AVQON_TEXT_SIMILARITY_THRESHOLD", "0.85"))

# Лимиты API: задержка между запросами (секунды)
TELEGRAM_API_DELAY_SEC = float(os.environ.get("AVQON_API_DELAY", "1.0"))

# Прокси (опционально): "socks5://user:pass@host:port"
TELEGRAM_PROXY = os.environ.get("AVQON_TELEGRAM_PROXY") or None

# Папки
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
