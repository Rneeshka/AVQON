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
        db_dir = Path(db_path).parent
        try:
            db_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"База данных будет создана/использована: {db_path}")
            logger.info(f"Директория БД: {db_dir} (существует: {db_dir.exists()})")
        except PermissionError as e:
            logger.error(f"Ошибка прав доступа при создании директории {db_dir}: {e}")
            raise
        except Exception as e:
            logger.error(f"Ошибка при создании директории {db_dir}: {e}")
            raise
        self._init_db()
    
    def _get_connection(self):
        """Получить соединение с БД (с улучшенной обработкой блокировок)"""
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(
                    self.db_path,
                    timeout=30,
                    check_same_thread=False
                )
                conn.row_factory = sqlite3.Row
                # Включаем foreign keys и улучшаем производительность
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                conn.execute("PRAGMA cache_size = -10000")
                # Проверяем что соединение работает
                conn.execute("SELECT 1").fetchone()
                return conn
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    import time
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                logger.error(f"Database connection error (attempt {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    raise
            except sqlite3.Error as e:
                logger.error(f"Database connection error: {e}")
                if attempt == max_retries - 1:
                    raise
                import time
                time.sleep(retry_delay * (attempt + 1))
        
        raise sqlite3.Error("Failed to establish database connection after retries")
    
    def _init_db(self):
        """Инициализация таблиц (единая БД для бота и backend)"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Включаем foreign keys и улучшаем производительность
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA synchronous = NORMAL")
        cursor.execute("PRAGMA cache_size = -10000")
        
        # ===== ТАБЛИЦЫ ДЛЯ TELEGRAM БОТА =====
        
        # Таблица пользователей Telegram бота
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                username TEXT,
                has_license BOOLEAN DEFAULT FALSE,
                license_key TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_has_license ON users(has_license)")
        
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
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_payment_id ON payments(payment_id)")
        
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
                is_renewal BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_yookassa_payments_user_id ON yookassa_payments(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_yookassa_payments_status ON yookassa_payments(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_yookassa_payments_payment_id ON yookassa_payments(payment_id)")
        
        # Таблица подписок (для месячных лицензий)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id BIGINT NOT NULL,
                license_key TEXT NOT NULL,
                license_type TEXT NOT NULL DEFAULT 'monthly',
                expires_at TIMESTAMP NOT NULL,
                auto_renew BOOLEAN DEFAULT FALSE,
                renewal_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active' CHECK(status IN ('active', 'expired', 'canceled')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (license_key) REFERENCES users(license_key) ON DELETE CASCADE
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_license_key ON subscriptions(license_key)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_expires_at ON subscriptions(expires_at)")
        
        # ===== ТАБЛИЦЫ ДЛЯ BACKEND (ANTIVIRUS CORE) =====
        
        # Таблица для аккаунтов пользователей (веб-интерфейс)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP DEFAULT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                reset_code TEXT DEFAULT NULL,
                reset_code_expires TIMESTAMP DEFAULT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email)")
        
        # Таблица для API ключей
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                api_key TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                is_active BOOLEAN DEFAULT TRUE,
                access_level TEXT DEFAULT 'basic' CHECK(access_level IN ('basic', 'premium')),
                features TEXT DEFAULT '[]',
                rate_limit_daily INTEGER DEFAULT 1000,
                rate_limit_hourly INTEGER DEFAULT 100,
                requests_total INTEGER DEFAULT 0,
                requests_today INTEGER DEFAULT 0,
                requests_hour INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT NULL,
                user_id INTEGER DEFAULT NULL,
                FOREIGN KEY (user_id) REFERENCES accounts(id) ON DELETE SET NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)")
        
        # Таблица для вредоносных хэшей файлов
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS malicious_hashes (
                hash TEXT PRIMARY KEY,
                threat_type TEXT NOT NULL CHECK(threat_type IN (
                    'malware', 'trojan', 'ransomware', 'virus', 
                    'worm', 'spyware', 'adware', 'rootkit', 'backdoor'
                )),
                severity TEXT NOT NULL CHECK(severity IN (
                    'low', 'medium', 'high', 'critical'
                )) DEFAULT 'medium',
                description TEXT,
                source TEXT DEFAULT 'manual',
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                detection_count INTEGER DEFAULT 1
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_malicious_hashes_hash ON malicious_hashes(hash)")
        
        # Таблица для вредоносных URL
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS malicious_urls (
                url TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                threat_type TEXT NOT NULL CHECK(threat_type IN (
                    'phishing', 'malware', 'scam', 'fraud',
                    'defacement', 'spam', 'botnet', 'cryptojacking'
                )),
                severity TEXT NOT NULL CHECK(severity IN (
                    'low', 'medium', 'high', 'critical'
                )) DEFAULT 'medium',
                description TEXT,
                source TEXT DEFAULT 'manual',
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                detection_count INTEGER DEFAULT 1
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_malicious_urls_url ON malicious_urls(url)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_malicious_urls_domain ON malicious_urls(domain)")
        
        # Таблица для логов запросов
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_hash TEXT,
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                status_code INTEGER,
                response_time_ms INTEGER,
                user_agent TEXT,
                client_ip_truncated TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_api_hash ON request_logs(api_key_hash)")
        
        # Таблица репутации IP
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                threat_type TEXT,
                reputation_score INTEGER,
                details TEXT,
                source TEXT,
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                detection_count INTEGER DEFAULT 1
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_reputation_score ON ip_reputation(reputation_score)")
        
        # Таблица для локальной базы доверенных доменов (white-list)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cached_whitelist (
                domain TEXT PRIMARY KEY,
                details TEXT,
                detection_ratio TEXT,
                confidence INTEGER,
                source TEXT DEFAULT 'external_apis',
                payload TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hit_count INTEGER DEFAULT 1
            )
        """)
        
        # Таблица для локальной базы известных угроз (black-list)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cached_blacklist (
                url_hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                threat_type TEXT,
                details TEXT,
                source TEXT DEFAULT 'external_apis',
                payload TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hit_count INTEGER DEFAULT 1
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cached_blacklist_domain ON cached_blacklist(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cached_blacklist_url ON cached_blacklist(url)")
        
        # Таблица фоновых задач
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS background_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_type TEXT NOT NULL,
                job_data TEXT NOT NULL,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'processing', 'completed', 'failed')),
                retry_count INTEGER DEFAULT 0,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_background_jobs_status ON background_jobs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_background_jobs_created ON background_jobs(created_at)")
        
        # Таблица активных сессий
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                user_id INTEGER PRIMARY KEY,
                session_token TEXT UNIQUE NOT NULL,
                device_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES accounts(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_active_sessions_token ON active_sessions(session_token)")
        
        # Добавляем новые колонки если таблица уже существует (миграции)
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
        
        # Миграции для request_logs
        try:
            cursor.execute("PRAGMA table_info(request_logs)")
            cols = {row[1] for row in cursor.fetchall()}
            if "api_key_hash" not in cols:
                cursor.execute("ALTER TABLE request_logs ADD COLUMN api_key_hash TEXT")
            if "client_ip_truncated" not in cols:
                cursor.execute("ALTER TABLE request_logs ADD COLUMN client_ip_truncated TEXT")
        except sqlite3.OperationalError:
            pass
        
        # Миграции для api_keys
        try:
            cursor.execute("PRAGMA table_info(api_keys)")
            api_cols = {row[1] for row in cursor.fetchall()}
            if "access_level" not in api_cols:
                cursor.execute("ALTER TABLE api_keys ADD COLUMN access_level TEXT DEFAULT 'basic'")
            if "features" not in api_cols:
                cursor.execute("ALTER TABLE api_keys ADD COLUMN features TEXT DEFAULT '[]'")
            if "user_id" not in api_cols:
                cursor.execute("ALTER TABLE api_keys ADD COLUMN user_id INTEGER DEFAULT NULL")
        except sqlite3.OperationalError:
            pass
        
        # Миграции для accounts
        try:
            cursor.execute("PRAGMA table_info(accounts)")
            account_cols = {row[1] for row in cursor.fetchall()}
            if "reset_code" not in account_cols:
                cursor.execute("ALTER TABLE accounts ADD COLUMN reset_code TEXT DEFAULT NULL")
            if "reset_code_expires" not in account_cols:
                cursor.execute("ALTER TABLE accounts ADD COLUMN reset_code_expires TIMESTAMP DEFAULT NULL")
        except sqlite3.OperationalError:
            pass
        
        # Миграции для yookassa_payments
        try:
            cursor.execute("PRAGMA table_info(yookassa_payments)")
            payment_cols = {row[1] for row in cursor.fetchall()}
            if "is_renewal" not in payment_cols:
                cursor.execute("ALTER TABLE yookassa_payments ADD COLUMN is_renewal BOOLEAN DEFAULT FALSE")
        except sqlite3.OperationalError:
            pass
        except sqlite3.OperationalError:
            pass
        
        conn.commit()
        conn.close()
        logger.info("База данных инициализирована (единая БД для бота и backend)")
    
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
        """Очистить все данные из БД (единая БД для бота и backend)"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Получаем список всех таблиц в БД
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Список таблиц для очистки (все пользовательские таблицы)
        tables_to_clear = [
            # Таблицы бота
            'users', 'payments', 'yookassa_payments',
            # Таблицы backend
            'accounts', 'api_keys', 'malicious_hashes', 'malicious_urls',
            'request_logs', 'ip_reputation', 'cached_whitelist', 'cached_blacklist',
            'background_jobs', 'active_sessions'
        ]
        
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
    
    def reset_user_data(self, user_id: int) -> Dict[str, int]:
        """
        Точечный сброс данных только для одного пользователя (для главного админа).
        Удаляет его платежи, подписки и лицензию, не затрагивая других.
        Возвращает статистику удаленных записей.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        stats = {"users": 0, "payments": 0, "yookassa_payments": 0, "subscriptions": 0}

        try:
            cursor.execute("DELETE FROM subscriptions WHERE user_id = ?", (user_id,))
            stats["subscriptions"] = cursor.rowcount

            cursor.execute("DELETE FROM yookassa_payments WHERE user_id = ?", (user_id,))
            stats["yookassa_payments"] = cursor.rowcount

            cursor.execute("DELETE FROM payments WHERE user_id = ?", (user_id,))
            stats["payments"] = cursor.rowcount

            cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            stats["users"] = cursor.rowcount

            conn.commit()
            logger.info(f"[RESET_USER] Cleared data for user {user_id}: {stats}")
        except Exception as e:
            logger.error(f"[RESET_USER] Error while clearing data for user {user_id}: {e}", exc_info=True)
            conn.rollback()
        finally:
            conn.close()

        return stats
    
    def create_yookassa_payment(self, payment_id: str, user_id: int, amount: int, license_type: str, is_renewal: bool = False):
        """Создать запись о платеже ЮKassa"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO yookassa_payments 
               (payment_id, user_id, amount, license_type, status, is_renewal) 
               VALUES (?, ?, ?, ?, 'pending', ?)""",
            (payment_id, user_id, amount, license_type, is_renewal)
        )
        conn.commit()
        conn.close()
        logger.info(f"Создан платеж ЮKassa {payment_id} для пользователя {user_id} (renewal: {is_renewal})")
    
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
    
    def get_yookassa_payment_by_license_key(self, license_key: str) -> Optional[Dict]:
        """Получить платеж ЮKassa по license_key"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM yookassa_payments WHERE license_key = ? AND status = 'succeeded' ORDER BY created_at DESC LIMIT 1",
            (license_key,)
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    
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
    
    # ===== МЕТОДЫ ДЛЯ РАБОТЫ С ПОДПИСКАМИ =====
    
    def create_subscription(self, user_id: int, license_key: str, license_type: str, expires_at: datetime, auto_renew: bool = False) -> Optional[int]:
        """Создать подписку для пользователя"""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO subscriptions 
                   (user_id, license_key, license_type, expires_at, auto_renew, status) 
                   VALUES (?, ?, ?, ?, ?, 'active')""",
                (user_id, license_key, license_type, expires_at, auto_renew)
            )
            conn.commit()
            subscription_id = cursor.lastrowid
            logger.info(f"Создана подписка {subscription_id} для пользователя {user_id}, expires_at={expires_at}")
            return subscription_id
        except sqlite3.IntegrityError as e:
            logger.error(f"Ошибка создания подписки: {e}")
            return None
        finally:
            conn.close()
    
    def get_subscription(self, user_id: int) -> Optional[Dict]:
        """Получить активную подписку пользователя"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM subscriptions 
               WHERE user_id = ? AND status = 'active' 
               ORDER BY expires_at DESC LIMIT 1""",
            (user_id,)
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    
    def get_subscription_by_license_key(self, license_key: str) -> Optional[Dict]:
        """Получить подписку по license_key"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM subscriptions 
               WHERE license_key = ? AND status = 'active' 
               ORDER BY expires_at DESC LIMIT 1""",
            (license_key,)
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    
    def update_subscription_expiry(self, user_id: int, new_expires_at: datetime, renewal_count: Optional[int] = None):
        """Обновить срок действия подписки (при продлении)"""
        conn = self._get_connection()
        cursor = conn.cursor()
        from datetime import datetime as dt
        if renewal_count is not None:
            cursor.execute(
                """UPDATE subscriptions 
                   SET expires_at = ?, renewal_count = ?, updated_at = ? 
                   WHERE user_id = ? AND status = 'active'""",
                (new_expires_at, renewal_count, dt.now(), user_id)
            )
        else:
            # Увеличиваем renewal_count на 1
            cursor.execute(
                """UPDATE subscriptions 
                   SET expires_at = ?, renewal_count = renewal_count + 1, updated_at = ? 
                   WHERE user_id = ? AND status = 'active'""",
                (new_expires_at, dt.now(), user_id)
            )
        conn.commit()
        conn.close()
        logger.info(f"Обновлен срок подписки для пользователя {user_id}, новый expires_at={new_expires_at}")
    
    def set_subscription_auto_renew(self, user_id: int, auto_renew: bool):
        """Включить/выключить автопродление подписки"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE subscriptions 
               SET auto_renew = ?, updated_at = ? 
               WHERE user_id = ? AND status = 'active'""",
            (auto_renew, datetime.now(), user_id)
        )
        conn.commit()
        conn.close()
        logger.info(f"Автопродление для пользователя {user_id} установлено: {auto_renew}")
    
    def expire_subscription(self, user_id: int):
        """Пометить подписку как истекшую"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE subscriptions 
               SET status = 'expired', updated_at = ? 
               WHERE user_id = ? AND status = 'active'""",
            (datetime.now(), user_id)
        )
        conn.commit()
        conn.close()
        logger.info(f"Подписка пользователя {user_id} помечена как истекшая")
    
    def get_expiring_subscriptions(self, days: int) -> List[Dict]:
        """Получить подписки, которые истекают в течение указанного количества дней"""
        conn = self._get_connection()
        cursor = conn.cursor()
        from datetime import datetime, timedelta
        expiry_date = datetime.now() + timedelta(days=days)
        cursor.execute(
            """SELECT * FROM subscriptions 
               WHERE status = 'active' 
               AND expires_at <= ? 
               AND expires_at > ? 
               ORDER BY expires_at ASC""",
            (expiry_date, datetime.now())
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_expired_subscriptions(self) -> List[Dict]:
        """Получить все истекшие, но еще не помеченные подписки"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM subscriptions 
               WHERE status = 'active' 
               AND expires_at < ? 
               ORDER BY expires_at ASC""",
            (datetime.now(),)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_subscription_history(self, user_id: int) -> List[Dict]:
        """Получить историю всех подписок пользователя"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM subscriptions 
               WHERE user_id = ? 
               ORDER BY created_at DESC""",
            (user_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_auto_renew_subscriptions(self) -> List[Dict]:
        """Получить все активные подписки с включенным автопродлением"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM subscriptions 
               WHERE status = 'active' 
               AND auto_renew = TRUE 
               ORDER BY expires_at ASC""",
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
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

