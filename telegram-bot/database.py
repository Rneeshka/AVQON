"""Работа с базой данных"""
import sqlite3
import logging
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        # Создаем директорию если её нет
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _get_connection(self):
        """Получить соединение с БД"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        """Инициализация таблиц"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Таблица пользователей
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                username TEXT,
                has_license BOOLEAN DEFAULT FALSE,
                license_key TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Таблица платежей
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                payment_id TEXT PRIMARY KEY,
                user_id BIGINT,
                amount INTEGER,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info("База данных инициализирована")
    
    def get_user(self, user_id: int) -> Optional[Dict]:
        """Получить пользователя по ID"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def create_user(self, user_id: int, username: Optional[str] = None):
        """Создать нового пользователя"""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (user_id, username) VALUES (?, ?)",
                (user_id, username)
            )
            conn.commit()
            logger.info(f"Создан пользователь {user_id}")
        except sqlite3.IntegrityError:
            # Пользователь уже существует
            pass
        finally:
            conn.close()
    
    def update_user_license(self, user_id: int, license_key: str):
        """Обновить лицензию пользователя"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET has_license = TRUE, license_key = ? WHERE user_id = ?",
            (license_key, user_id)
        )
        conn.commit()
        conn.close()
        logger.info(f"Обновлена лицензия для пользователя {user_id}")
    
    def create_payment(self, payment_id: str, user_id: int, amount: int, status: str = "pending"):
        """Создать запись о платеже"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO payments (payment_id, user_id, amount, status) VALUES (?, ?, ?, ?)",
            (payment_id, user_id, amount, status)
        )
        conn.commit()
        conn.close()
        logger.info(f"Создан платеж {payment_id} для пользователя {user_id}")
    
    def update_payment_status(self, payment_id: str, status: str):
        """Обновить статус платежа"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE payments SET status = ? WHERE payment_id = ?",
            (status, payment_id)
        )
        conn.commit()
        conn.close()
    
    def get_licenses_count(self) -> int:
        """Получить количество выданных лицензий"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE has_license = TRUE")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_total_users(self) -> int:
        """Получить общее количество пользователей"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_stats(self) -> Dict:
        """Получить статистику"""
        return {
            "total_users": self.get_total_users(),
            "licenses_count": self.get_licenses_count(),
            "remaining_licenses": max(0, 1000 - self.get_licenses_count())
        }

