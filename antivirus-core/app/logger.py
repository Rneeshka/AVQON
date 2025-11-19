# app/logger.py
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from app.config import logging_config

def setup_logging():
    """Настройка логирования для приложения с ротацией."""
    # Создаем папку для логов
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Форматирование логов
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Настройка уровня логирования
    log_level = getattr(logging, logging_config.LOG_LEVEL.upper(), logging.INFO)
    
    # Создаем форматтер
    formatter = logging.Formatter(log_format)
    
    # Настройка файлового хендлера с ротацией
    log_file = f"logs/antivirus_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=logging_config.LOG_MAX_SIZE_MB * 1024 * 1024,  # MB to bytes
        backupCount=logging_config.LOG_ROTATION_DAYS,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)
    
    # Настройка консольного хендлера
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    
    # Базовая настройка логирования
    logging.basicConfig(
        level=log_level,
        handlers=[file_handler, console_handler],
        format=log_format
    )
    
    # Настройка логгеров для внешних библиотек
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.info("Logging system initialized with rotation")
    
    return logger

def cleanup_old_logs():
    """Очистка старых логов"""
    try:
        log_dir = Path("logs")
        if not log_dir.exists():
            return
        
        cutoff_date = datetime.now().timestamp() - (logging_config.LOG_ROTATION_DAYS * 24 * 60 * 60)
        
        for log_file in log_dir.glob("antivirus_*.log*"):
            if log_file.stat().st_mtime < cutoff_date:
                log_file.unlink()
                logging.getLogger(__name__).info(f"Removed old log file: {log_file}")
    except Exception as e:
        logging.getLogger(__name__).error(f"Error cleaning up old logs: {e}")

# Глобальный логгер
logger = setup_logging()

# Очищаем старые логи при запуске
cleanup_old_logs()