# app/cache.py
import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional
from app.logger import logger

class DiskCache:
    """Диск-кэш с TTL для переживания перезапусков"""
    
    def __init__(self, cache_db_path: str = "data/cache.db"):
        self.cache_db_path = cache_db_path
        self._init_cache_db()
    
    def _init_cache_db(self):
        """Инициализация базы данных кэша"""
        try:
            Path(self.cache_db_path).parent.mkdir(parents=True, exist_ok=True)
            
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cache (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        created_at INTEGER DEFAULT (strftime('%s', 'now'))
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at)")
                conn.commit()
        except Exception as e:
            logger.error(f"Cache DB initialization error: {e}")
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Получение значения из кэша"""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT value, expires_at FROM cache WHERE key = ? AND expires_at > ?",
                    (key, int(time.time()))
                )
                result = cursor.fetchone()
                
                if result:
                    value_str, expires_at = result
                    return json.loads(value_str)
                else:
                    # Удаляем истекшие записи
                    cursor.execute("DELETE FROM cache WHERE expires_at <= ?", (int(time.time()),))
                    conn.commit()
                    return None
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None
    
    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int = 300):
        """Сохранение значения в кэш"""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                expires_at = int(time.time()) + ttl_seconds
                value_str = json.dumps(value)
                
                cursor.execute(
                    "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                    (key, value_str, expires_at)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Cache set error: {e}")
    
    def delete(self, key: str):
        """Удаление значения из кэша"""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
    
    def clear_expired(self):
        """Очистка истекших записей"""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cache WHERE expires_at <= ?", (int(time.time()),))
                conn.commit()
        except Exception as e:
            logger.error(f"Cache clear expired error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики кэша"""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM cache")
                total_entries = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM cache WHERE expires_at > ?", (int(time.time()),))
                active_entries = cursor.fetchone()[0]
                
                return {
                    "total_entries": total_entries,
                    "active_entries": active_entries,
                    "expired_entries": total_entries - active_entries
                }
        except Exception as e:
            logger.error(f"Cache stats error: {e}")
            return {"total_entries": 0, "active_entries": 0, "expired_entries": 0}

# Глобальный экземпляр диск-кэша
disk_cache = DiskCache()
