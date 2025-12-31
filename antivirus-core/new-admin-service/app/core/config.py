"""
Конфигурация админ-сервиса
"""
import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Настройки приложения"""
    
    # Базовые настройки
    APP_NAME: str = "Admin Service"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "dev").lower()
    DEBUG: bool = ENVIRONMENT == "dev"
    
    # Сервер
    HOST: str = os.getenv("ADMIN_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("ADMIN_PORT", "8001"))
    
    # База данных (используем ту же БД, что и основной сервис)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
    # Проверка будет выполнена при первом использовании, а не при импорте
    
    # Redis (опционально, для кэширования)
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL", None)
    
    # JWT настройки
    JWT_SECRET: str = os.getenv("ADMIN_JWT_SECRET", os.getenv("JWT_SECRET", "change-me-in-production"))
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 часа
    
    # Роли пользователей
    ROLES: List[str] = ["admin", "moderator", "viewer"]
    
    # Безопасность
    ADMIN_DEFAULT_USER: str = os.getenv("ADMIN_DEFAULT_USER", "admin")
    ADMIN_DEFAULT_PASSWORD: str = os.getenv("ADMIN_DEFAULT_PASSWORD", "admin123")
    ADMIN_PASSWORD_HASH: Optional[str] = os.getenv("ADMIN_PASSWORD_HASH", None)
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        origin.strip() 
        for origin in os.getenv(
            "ADMIN_ALLOWED_ORIGINS", 
            "http://localhost:8001,http://127.0.0.1:8001,https://avqonadmin.com,https://admin.avqon.com"
        ).split(",")
        if origin.strip()
    ]
    
    # Rate limiting
    RATE_LIMIT_PER_SECOND: int = int(os.getenv("ADMIN_RATE_LIMIT_PER_SECOND", "10"))
    
    # Мониторинг
    ENABLE_PROMETHEUS: bool = os.getenv("ENABLE_PROMETHEUS", "false").lower() == "true"
    PROMETHEUS_PORT: int = int(os.getenv("PROMETHEUS_PORT", "9090"))
    
    # Webhook уведомления
    WEBHOOK_TELEGRAM_TOKEN: Optional[str] = os.getenv("WEBHOOK_TELEGRAM_TOKEN", None)
    WEBHOOK_TELEGRAM_CHAT_ID: Optional[str] = os.getenv("WEBHOOK_TELEGRAM_CHAT_ID", None)
    WEBHOOK_SLACK_URL: Optional[str] = os.getenv("WEBHOOK_SLACK_URL", None)
    
    # Логирование
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json" if ENVIRONMENT == "prod" else "text")
    
    # Sentry (опционально)
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN", None)
    
    # Пагинация
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 100
    
    class Config:
        env_file = [".env", "env.local"]  # Пробуем оба файла
        case_sensitive = True


# Создаем экземпляр настроек
settings = Settings()

