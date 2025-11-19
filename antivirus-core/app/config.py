# app/config.py
import os
from pathlib import Path
from typing import Dict, Any

# Автозагрузка переменных окружения из файла app/env.env (если он существует)
def _load_env_from_file():
    try:
        env_path = Path(__file__).with_name("env.env")
        if not env_path.exists():
            return
        with env_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # Не перезаписываем, если уже задано в окружении
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        # Тихо игнорируем ошибки чтения .env, чтобы не рушить запуск
        pass

_load_env_from_file()

class LoggingConfig:
    """Конфигурация логирования"""
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_MAX_SIZE_MB = int(os.getenv("LOG_MAX_SIZE_MB", "10"))
    LOG_ROTATION_DAYS = int(os.getenv("LOG_ROTATION_DAYS", "7"))

class SecurityConfig:
    """Конфигурация безопасности"""
    ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "")
    SECRET_KEY = os.getenv("SECRET_KEY", "")
    ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
    MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "100"))
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

class ExternalAPIConfig:
    """Конфигурация внешних антивирусных API"""
    
    # Ключи API (в продакшене использовать environment variables)
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    
    # URL эндпоинтов
    VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3"
    GOOGLE_SAFE_BROWSING_API = "https://safebrowsing.googleapis.com/v4"
    ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
    
    # Настройки таймаутов
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 3
    
    # Лимиты запросов
    VIRUSTOTAL_HOURLY_LIMIT = 500
    GOOGLE_DAILY_LIMIT = 10000

config = ExternalAPIConfig()

# Создаем экземпляры конфигураций
logging_config = LoggingConfig()
security_config = SecurityConfig()
external_config = ExternalAPIConfig()