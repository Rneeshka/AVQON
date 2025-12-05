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
        
        # Таблица платежей (старая, для совместимости)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id BIGINT NOT NULL,
                amount INTEGER NOT NULL,
                license_type TEXT NOT NULL,
                license_key TEXT,
                payment_id TEXT UNIQUE,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        """)
        
        # Таблица платежей ЮKassa
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS yookassa_payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payment_id TEXT UNIQUE NOT NULL,
                user_id BIGINT NOT NULL,
                amount INTEGER NOT NULL,
                license_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                license_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Добавляем новые колонки если таблица уже существует
        try:
            cursor.execute("ALTER TABLE payments ADD COLUMN license_type TEXT")
        except sqlite3.OperationalError:
            pass  # Колонка уже существует
        
        try:
            cursor.execute("ALTER TABLE payments ADD COLUMN license_key TEXT")
        except sqlite3.OperationalError:
            pass
        
        try:
            cursor.execute("ALTER TABLE payments ADD COLUMN completed_at TIMESTAMP")
        except sqlite3.OperationalError:
            pass
        
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
    
    def create_payment(self, payment_id: str, user_id: int, amount: int, license_type: str, status: str = "pending"):
        """Создать запись о платеже"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO payments (payment_id, user_id, amount, license_type, status) VALUES (?, ?, ?, ?, ?)",
            (payment_id, user_id, amount, license_type, status)
        )
        conn.commit()
        conn.close()
        logger.info(f"Создан платеж {payment_id} для пользователя {user_id}")
    
    def update_payment_license_key(self, payment_id: str, license_key: str):
        """Обновить лицензионный ключ в платеже"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE payments SET license_key = ? WHERE payment_id = ?",
            (license_key, payment_id)
        )
        conn.commit()
        conn.close()
    
    def update_payment_status(self, payment_id: str, status: str):
        """Обновить статус платежа"""
        conn = self._get_connection()
        cursor = conn.cursor()
        if status == "completed":
            cursor.execute(
                "UPDATE payments SET status = ?, completed_at = ? WHERE payment_id = ?",
                (status, datetime.now(), payment_id)
            )
        else:
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
    
    def get_forever_licenses_count(self) -> int:
        """Получить количество выданных постоянных лицензий"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM payments WHERE license_type = 'forever' AND status = 'completed'"
        )
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_available_forever_licenses(self) -> int:
        """Получить количество оставшихся постоянных лицензий"""
        # Используем данные из yookassa_payments (приоритет) или из старой таблицы payments
        issued_yookassa = self.get_forever_licenses_count_from_yookassa()
        issued_old = self.get_forever_licenses_count()
        issued = max(issued_yookassa, issued_old)
        return max(0, 1000 - issued)
    
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
        forever_count = self.get_forever_licenses_count()
        return {
            "total_users": self.get_total_users(),
            "licenses_count": self.get_licenses_count(),
            "forever_licenses_count": forever_count,
            "remaining_forever_licenses": max(0, 1000 - forever_count)
        }
    
    def get_detailed_stats(self) -> Dict:
        """Получить детальную статистику по БД"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Подсчет записей в каждой таблице
        cursor.execute("SELECT COUNT(*) FROM users")
        users_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM payments")
        payments_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE has_license = TRUE")
        licenses_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM payments WHERE status = 'completed'")
        completed_payments = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM payments WHERE status = 'pending'")
        pending_payments = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM payments WHERE status = 'failed'")
        failed_payments = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "users": users_count,
            "payments": payments_count,
            "licenses": licenses_count,
            "completed_payments": completed_payments,
            "pending_payments": pending_payments,
            "failed_payments": failed_payments
        }
    
    def reset_all_data(self):
        """Очистить все данные из БД"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Получаем список всех таблиц в БД
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Список таблиц для очистки (только пользовательские таблицы)
        tables_to_clear = ['users', 'payments', 'yookassa_payments', 'licenses']
        
        # Очищаем только существующие таблицы
        cleared_tables = []
        for table in tables_to_clear:
            if table in tables:
                try:
                    cursor.execute(f"DELETE FROM {table}")
                    cleared_tables.append(table)
                    logger.info(f"Очищена таблица: {table}")
                except sqlite3.OperationalError as e:
                    logger.error(f"Ошибка при очистке таблицы {table}: {e}")
        
        conn.commit()
        conn.close()
        logger.warning(f"База данных очищена. Очищены таблицы: {', '.join(cleared_tables)}")
    
    def create_yookassa_payment(self, payment_id: str, user_id: int, amount: int, license_type: str):
        """Создать запись о платеже ЮKassa"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO yookassa_payments 
               (payment_id, user_id, amount, license_type, status) 
               VALUES (?, ?, ?, ?, 'pending')""",
            (payment_id, user_id, amount, license_type)
        )
        conn.commit()
        conn.close()
        logger.info(f"Создан платеж ЮKassa {payment_id} для пользователя {user_id}")
    
    def get_yookassa_payment(self, payment_id: str) -> Optional[Dict]:
        """Получить платеж ЮKassa по ID"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM yookassa_payments WHERE payment_id = ?", (payment_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    
    def get_pending_payments_by_user(self, user_id: int) -> List[Dict]:
        """Получить все pending платежи пользователя"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM yookassa_payments WHERE user_id = ? AND status = 'pending' ORDER BY created_at DESC",
            (user_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def update_yookassa_payment_status(self, payment_id: str, status: str, license_key: Optional[str] = None):
        """Обновить статус платежа ЮKassa"""
        conn = self._get_connection()
        cursor = conn.cursor()
        from datetime import datetime
        if license_key:
            cursor.execute(
                """UPDATE yookassa_payments 
                   SET status = ?, license_key = ?, updated_at = ? 
                   WHERE payment_id = ?""",
                (status, license_key, datetime.now(), payment_id)
            )
        else:
            cursor.execute(
                """UPDATE yookassa_payments 
                   SET status = ?, updated_at = ? 
                   WHERE payment_id = ?""",
                (status, datetime.now(), payment_id)
            )
        conn.commit()
        conn.close()
        logger.info(f"Обновлен статус платежа {payment_id} на {status}")
    
    def get_forever_licenses_count_from_yookassa(self) -> int:
        """Получить количество выданных постоянных лицензий из платежей ЮKassa"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM yookassa_payments WHERE license_type = 'forever' AND status = 'succeeded'"
        )
        count = cursor.fetchone()[0]
        conn.close()
        return count

