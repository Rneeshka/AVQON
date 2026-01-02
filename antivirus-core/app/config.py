# app/config.py
import os
from pathlib import Path
from typing import Dict, Any
import logging

# Автозагрузка переменных окружения из файла app/env.env (если он существует)
ENV_FILE_PATH = Path(__file__).with_name("env.env")
ENV_FILE_LOADED = False
ENV_FILE_KEYS = []

def _load_env_from_file():
    global ENV_FILE_LOADED, ENV_FILE_KEYS
    try:
        if not ENV_FILE_PATH.exists():
            logging.getLogger(__name__).info(f"env.env not found at {ENV_FILE_PATH}")
            return
        with ENV_FILE_PATH.open("r", encoding="utf-8") as f:
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
                    ENV_FILE_KEYS.append(key)
        ENV_FILE_LOADED = True
        logging.getLogger(__name__).info(
            f"Loaded env variables from {ENV_FILE_PATH.name}: {', '.join(ENV_FILE_KEYS) if ENV_FILE_KEYS else 'none'}"
        )
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
    ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "e972cfe7ff57a6175f8d5b828532c83ff62e71ad6d619714c01dbb3b23880352")
    SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key_here")
    ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
    MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "100"))
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

class ServerConfig:
    """Конфигурация сервера и окружений"""
    # Определяем окружение (DEV или PROD)
    ENVIRONMENT = os.getenv("ENVIRONMENT", "dev").lower()
    
    # Базовые URL для API и WebSocket
    # DEV окружение
    API_BASE_DEV = "https://dev.avqon.com"
    WS_BASE_DEV = "wss://dev.avqon.com"
    
    # PROD окружение
    API_BASE_PROD = "https://prod.avqon.com"
    WS_BASE_PROD = "wss://prod.avqon.com"
    
    # Текущие значения в зависимости от окружения
    @property
    def API_BASE(self):
        return self.API_BASE_DEV if self.ENVIRONMENT == "dev" else self.API_BASE_PROD
    
    @property
    def WS_BASE(self):
        return self.WS_BASE_DEV if self.ENVIRONMENT == "dev" else self.WS_BASE_PROD
    
    # WebSocket endpoint path (одинаковый для всех окружений)
    WS_ENDPOINT_PATH = "/ws"
    
    @property
    def WS_URL(self):
        """Полный URL для WebSocket соединения"""
        return f"{self.WS_BASE}{self.WS_ENDPOINT_PATH}"

class ExternalAPIConfig:
    """Конфигурация внешних антивирусных API"""
    
    # Ключи API (в продакшене использовать environment variables)
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "8958873d9567fe0eeaf1d4468e1515964da7d499b2a51e8618907b131cec96ce")
    GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "your_google_key_here")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "96707cab41d7ac50b7503d883ccc6fa002cba3245b086e9cf129eaa55b13c12dfe79bfe4ebb6846")
    
    # URL эндпоинтов
    VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3"
    GOOGLE_SAFE_BROWSING_API = "https://safebrowsing.googleapis.com/v4"
    ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
    
    # Настройки таймаутов
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 3
    
    # Лимиты запросов
    # VirusTotal: бесплатный тариф - 500 запросов в сутки, ставим 20 в час для безопасности
    VIRUSTOTAL_HOURLY_LIMIT = int(os.getenv("VIRUSTOTAL_HOURLY_LIMIT", "2000"))
    # Google Safe Browsing: обычно 10000 запросов в сутки
    GOOGLE_DAILY_LIMIT = int(os.getenv("GOOGLE_DAILY_LIMIT", "10000"))

# Создаем экземпляры конфигураций
logging_config = LoggingConfig()
security_config = SecurityConfig()
external_config = ExternalAPIConfig()
server_config = ServerConfig()

# Для обратной совместимости
config = ExternalAPIConfig()