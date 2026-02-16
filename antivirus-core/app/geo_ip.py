# app/geo_ip.py
"""
Интеграция IP2Location для определения страны по IP.
Используется в админке для блока «Топ стран по трафику».

Настройка:
  - Установите: pip install IP2Location
  - Скачайте BIN: https://lite.ip2location.com (бесплатно) или коммерческая версия
  - Укажите путь в env: IP2LOCATION_BIN_PATH=/path/to/IPV6-COUNTRY.BIN
    или IP2LOCATION_DB (альтернативное имя)
"""
import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Кэш IP -> страна (уменьшает повторные запросы к BIN)
_cache: Dict[str, Dict[str, str]] = {}
_db = None


def _get_db_path() -> Optional[str]:
    path = os.getenv("IP2LOCATION_BIN_PATH") or os.getenv("IP2LOCATION_DB")
    if path and os.path.isfile(path):
        return path
    # Типичное место рядом с проектом
    for name in ("IPV6-COUNTRY.BIN", "IP2LOCATION-LITE-DB1.BIN", "IP-COUNTRY.BIN"):
        candidate = os.path.join(os.path.dirname(__file__), "..", "data", name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _load_db():
    global _db
    if _db is not None:
        return _db
    path = _get_db_path()
    if not path:
        logger.debug("IP2Location: BIN path not set (IP2LOCATION_BIN_PATH). Geo by country disabled.")
        return None
    try:
        import IP2Location
        _db = IP2Location.IP2Location(path)
        logger.info("IP2Location: loaded %s", path)
        return _db
    except ImportError:
        logger.debug("IP2Location: package not installed (pip install IP2Location). Geo by country disabled.")
        return None
    except Exception as e:
        logger.warning("IP2Location: failed to load %s: %s", path, e)
        return None


def get_country(ip: Optional[str]) -> Optional[Dict[str, str]]:
    """
    Возвращает страну по IP через IP2Location BIN.
    Возвращает None, если библиотека/файл не настроены или IP невалиден.

    Результат: {"country_short": "RU", "country_long": "Russia"}
    """
    if not ip or not str(ip).strip():
        return None
    ip = str(ip).strip()
    # Локальные и приватные диапазоны
    if ip.startswith("127.") or ip == "::1" or ip.startswith("0."):
        return {"country_short": "—", "country_long": "Local"}
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return {"country_short": "—", "country_long": "Private"}

    if ip in _cache:
        return _cache[ip]

    db = _load_db()
    if not db:
        return None
    try:
        rec = db.get_all(ip)
        if rec and getattr(rec, "country_short", None):
            result = {
                "country_short": (rec.country_short or "").strip() or "—",
                "country_long": (rec.country_long or "").strip() or "—",
            }
        else:
            result = {"country_short": "—", "country_long": "Unknown"}
        _cache[ip] = result
        return result
    except Exception as e:
        logger.debug("IP2Location lookup %s: %s", ip, e)
        _cache[ip] = {"country_short": "—", "country_long": "Error"}
        return _cache[ip]


def is_available() -> bool:
    """Проверяет, доступна ли геолокация по IP (библиотека и BIN загружены)."""
    return _load_db() is not None
