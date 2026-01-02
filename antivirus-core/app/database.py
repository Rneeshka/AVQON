# app/database.py
import logging
import secrets
import os
import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime, timedelta
from pathlib import Path
import psycopg2
import psycopg2.extras

# Настраиваем логирование
logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Менеджер базы данных для PostgreSQL.
    Только PostgreSQL - SQLite удалён.
    """
    
    def __init__(self, db_url: str = None):
        """
        Инициализация менеджера базы данных.
        Только PostgreSQL через DATABASE_URL.
        """

        if db_url is None:
            db_url = os.getenv("DATABASE_URL")
            if not db_url:
                raise ValueError("DATABASE_URL must be set in environment variables")
        
        self.db_url = db_url
        parsed = urlparse(db_url)
        self.db_scheme = parsed.scheme

        if not (self.db_scheme.startswith("postgresql") or self.db_scheme.startswith("postgres")):
            raise ValueError(f"Only PostgreSQL is supported, got: {self.db_scheme}")

        logger.info(f"Initializing PostgreSQL database: {self.db_url[:30]}...")
    
    def _get_connection(self):
        """Возвращает соединение с PostgreSQL"""
        return self._get_postgres_connection()
    
    def _adapt_query(self, query: str) -> str:
        """Адаптирует SQL запрос для PostgreSQL (заменяет ? на %s)"""
        # PostgreSQL использует %s вместо ?
        return query.replace("?", "%s")
    
    def _commit_if_needed(self, conn):
        """
        Для PostgreSQL с autocommit=True этот метод не нужен,
        но оставлен для совместимости кода.
        """
        # PostgreSQL использует autocommit=True, поэтому commit не требуется
        # Метод оставлен для совместимости, но ничего не делает
        pass
    
    def _get_postgres_connection(self):
        """Получает соединение с PostgreSQL с retry логикой"""
        max_retries = 3
        retry_delay = 0.5
        
        for attempt in range(max_retries):
            try:
                conn = psycopg2.connect(
                    self.db_url,
                    cursor_factory=psycopg2.extras.RealDictCursor,
                    connect_timeout=5
                )
                conn.autocommit = True
                # Проверяем соединение
                with conn.cursor() as test_cursor:
                    test_cursor.execute("SELECT 1")
                    test_cursor.fetchone()
                return conn
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                if attempt < max_retries - 1:
                    logger.warning(f"PostgreSQL connection error, retrying ({attempt + 1}/{max_retries}): {e}")
                    import time
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                logger.error(f"PostgreSQL connection error after {max_retries} attempts: {e}")
                raise
            except Exception as e:
                logger.error(f"PostgreSQL connection error: {e}")
                raise
    
    def _init_database(self):
        """
        Инициализирует базу данных: создает все таблицы и индексы.
        """
        try:
            # Создаем папку для базы данных если ее нет
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # 1. Таблица для аккаунтов пользователей
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
                
                # 2. Таблица для API ключей (компактная)
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
                
                # 3. Таблица для вредоносных хэшей файлов
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
                
                # 4. Таблица для вредоносных URL
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
                
                # 5. Таблица для логов запросов (для аналитики)
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

                # 6. Таблица репутации IP
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
                
                # 8. Таблица для локальной базы доверенных доменов (white-list)
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
                
                # 9. Таблица для локальной базы известных угроз (black-list)
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
                
                # 7. Таблица фоновых задач
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
                
                # 10. Таблица активных сессий (один аккаунт - одна активная сессия)
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

                # 11. Таблица для кодов восстановления пароля
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS password_resets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        code TEXT NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES accounts(id) ON DELETE CASCADE
                    )
                """)
                
                # 12. Таблица пользователей Telegram бота
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
                
                # 13. Таблица платежей (старая, для совместимости)
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
                
                # 14. Таблица платежей ЮKassa
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS yookassa_payments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        payment_id TEXT UNIQUE NOT NULL,
                        user_id BIGINT,  -- NULLABLE: платеж может быть сохранен без пользователя
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
                
                # 15. Таблица подписок (для месячных лицензий)
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
                        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_license_key ON subscriptions(license_key)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_expires_at ON subscriptions(expires_at)")
                
                # Миграции схемы для совместимости со старыми базами (до индексов)
                self._migrate_schema(conn)

                # Создаем индексы для быстрого поиска
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_malicious_hashes_hash ON malicious_hashes(hash)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_malicious_urls_url ON malicious_urls(url)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_malicious_urls_domain ON malicious_urls(domain)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp)")
                # Индекс для хеша ключа создаем только если колонка существует
                try:
                    c2 = conn.cursor()
                    c2.execute("PRAGMA table_info(request_logs)")
                    cols = {row[1] for row in c2.fetchall()}
                    if "api_key_hash" in cols:
                        cursor.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_api_hash ON request_logs(api_key_hash)")
                except Exception as e:
                    logger.warning(f"Could not create api_key_hash index: {e}")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_reputation_score ON ip_reputation(reputation_score)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_background_jobs_status ON background_jobs(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_background_jobs_created ON background_jobs(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_active_sessions_token ON active_sessions(session_token)")

                # Добавляем тестовые данные
                self._add_test_data(cursor)
                
                self._commit_if_needed(conn)
                logger.info("Database initialized successfully with all tables")
                
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Database initialization error: {e}")
            raise

    def _migrate_schema(self, conn):
        """
        DEPRECATED: Миграции схемы БД больше не используются для PostgreSQL.
        Все миграции должны выполняться через отдельные SQL файлы в папке migrations/.
        Этот метод оставлен для обратной совместимости, но не выполняет никаких действий.
        """
        # Миграции теперь выполняются через отдельные SQL файлы
        # См. migrations/001_add_missing_columns.sql
        pass
    
    def _add_test_data(self, cursor):
        """DEPRECATED: Тестовые данные больше не добавляются автоматически."""
        """Добавляет тестовые данные в базу."""
        # Только тестовый API ключ премиум уровня (базовый функционал работает без ключей)
        query = """
            INSERT INTO api_keys 
            (api_key, name, description, access_level, features, rate_limit_daily, rate_limit_hourly)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(api_key) DO NOTHING
        """
        cursor.execute(self._adapt_query(query), (
            "PREMI-12345-67890-ABCDE-FGHIJ-KLMNO", 
            "Test Premium Client", 
            "API key for premium testing with advanced features",
            "premium",
            '["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]',
            10000,  # 10k запросов в день
            1000    # 1k запросов в час
        ))
        
        # Тестовые вредоносные хэши
        test_hashes = [
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 
             "trojan", "high", "Test Trojan horse"),
            ("a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
             "ransomware", "critical", "Test Ransomware variant")
        ]
        
        for file_hash, threat_type, severity, description in test_hashes:
            query = """
                INSERT INTO malicious_hashes 
                (hash, threat_type, severity, description)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT(hash) DO NOTHING
            """
            cursor.execute(self._adapt_query(query), (file_hash, threat_type, severity, description))
        
        # Тестовые вредоносные URL
        test_urls = [
            ("https://evil-site.com/download/malware.exe", "evil-site.com",
             "malware", "high", "Malware distribution site"),
            ("https://phishing-bank.com/login", "phishing-bank.com",
             "phishing", "medium", "Fake bank login page")
        ]
        
        for url, domain, threat_type, severity, description in test_urls:
            query = """
                INSERT INTO malicious_urls 
                (url, domain, threat_type, severity, description)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT(url) DO NOTHING
            """
            cursor.execute(self._adapt_query(query), (url, domain, threat_type, severity, description))
    
    # ===== API KEYS MANAGEMENT =====
    # Метод validate_api_key удалён - используйте JWT аутентификацию через security.py
    
    def create_api_key(self, name: str, description: str = "", 
                      access_level: str = "basic", daily_limit: Optional[int] = 10000, 
                      hourly_limit: Optional[int] = 10000, expires_days: int = 365, 
                      user_id: Optional[int] = None) -> Optional[str]:
        """Создает новый API ключ в формате XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"""
        try:
            safe_name = (name or "").strip() or "Client"
            safe_desc = (description or "").strip()
            # Поддержка «без лимитов»: None или <=0 означает без ограничений
            def _normalize_limit(value: Optional[int], default: int) -> Optional[int]:
                try:
                    if value is None:
                        return None
                    val_int = int(value)
                    return None if val_int <= 0 else val_int
                except Exception:
                    return default

            daily_limit = _normalize_limit(daily_limit, 10000)
            hourly_limit = _normalize_limit(hourly_limit, 10000)

            # Генерируем ключ в новом формате
            api_key = self._generate_formatted_key(access_level)
            logger.info(f"Generated API key: {api_key[:10]}... for {safe_name}, user_id={user_id}")
            
            # Определяем доступные функции в зависимости от уровня
            if access_level == "premium":
                features = '["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]'
            else:
                features = '["url_check", "file_check", "domain_check"]'
            
            expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        """
                        INSERT INTO api_keys (
                            api_key, name, description, is_active, access_level, features,
                            rate_limit_daily, rate_limit_hourly,
                            requests_total, requests_today, requests_hour,
                            created_at, last_used, expires_at, user_id
                        ) VALUES (
                            %s, %s, %s, TRUE, %s, %s,
                            %s, %s,
                            0, 0, 0,
                            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %s, %s
                        )
                        """,
                        (api_key, safe_name, safe_desc, access_level, features, 
                         daily_limit, hourly_limit, expires_at, user_id)
                    )
                    self._commit_if_needed(conn)
                    logger.info(f"✅ API key created successfully in api_keys table for {safe_name} (user_id={user_id}) with level {access_level}: {api_key[:10]}...")
                    return api_key
                except psycopg2.IntegrityError as e:
                    logger.error(f"❌ API key creation failed - duplicate key: {e}")
                    # Пробуем еще раз с новым ключом
                    api_key = self._generate_formatted_key(access_level)
                    query = """
                        INSERT INTO api_keys (
                            api_key, name, description, is_active, access_level, features,
                            rate_limit_daily, rate_limit_hourly,
                            requests_total, requests_today, requests_hour,
                            created_at, last_used, expires_at, user_id
                        ) VALUES (
                            %s, %s, %s, TRUE, %s, %s,
                            %s, %s,
                            0, 0, 0,
                            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %s, %s
                        )
                    """
                    cursor.execute(self._adapt_query(query), (api_key, safe_name, safe_desc, access_level, features, 
                         daily_limit, hourly_limit, expires_at, user_id))
                    self._commit_if_needed(conn)
                    logger.info(f"✅ API key created on retry in api_keys table for {safe_name} (user_id={user_id}): {api_key[:10]}...")
                    return api_key
        except (psycopg2.Error, Exception) as e:
            logger.error(f"❌ API key creation error: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error during API key creation: {e}", exc_info=True)
            return None
    
    def _generate_formatted_key(self, access_level: str) -> str:
        """Генерирует ключ в формате PREMI-XXXXX-XXXXX-XXXXX-XXXXX (4 группы после префикса)"""
        import string
        import random
        
        # Префикс в зависимости от уровня доступа
        prefix = "BASIC" if access_level == "basic" else "PREMI"
        
        # Генерируем случайные символы (буквы и цифры)
        chars = string.ascii_uppercase + string.digits
        
        # Создаем 4 группы по 5 символов (после префикса)
        groups = []
        for i in range(4):
            if i == 0:
                # Первая группа содержит префикс + 1 символ
                group = prefix + random.choice(chars)
            else:
                # Остальные группы по 5 случайных символов
                group = ''.join(random.choice(chars) for _ in range(5))
            groups.append(group)
        
        return '-'.join(groups)
    
    def extend_api_key(self, api_key: str, extend_days: int) -> bool:
        """Продлевает срок действия API ключа"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Проверяем, существует ли ключ
                query = "SELECT expires_at FROM api_keys WHERE api_key = %s"
                cursor.execute(self._adapt_query(query), (api_key,))
                result = cursor.fetchone()
                
                if not result:
                    return False
                
                # Получаем текущую дату истечения
                current_expires = datetime.fromisoformat(result["expires_at"])
                
                # Добавляем дни
                new_expires = current_expires + timedelta(days=extend_days)
                
                # Обновляем дату истечения
                query = "UPDATE api_keys SET expires_at = %s WHERE api_key = %s"
                cursor.execute(self._adapt_query(query), (new_expires.isoformat(), api_key))
                
                self._commit_if_needed(conn)
                return True
                
        except Exception as e:
            logger.error(f"Extend API key error: {e}")
            return False
    
    def list_api_keys(self) -> List[Dict[str, Any]]:
        """Возвращает список всех API ключей"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT api_key, name, description, access_level, features, 
                           daily_limit, hourly_limit, created_at, expires_at
                    FROM api_keys 
                    ORDER BY created_at DESC
                """)
                
                keys = []
                for row in cursor.fetchall():
                    # cursor использует RealDictCursor, поэтому row - это dict, а не tuple
                    keys.append({
                        "api_key": row["api_key"],
                        "name": row["name"],
                        "description": row["description"],
                        "access_level": row["access_level"],
                        "features": row["features"],
                        "daily_limit": row["daily_limit"],
                        "hourly_limit": row["hourly_limit"],
                        "created_at": row["created_at"],
                        "expires_at": row["expires_at"],
                        "requests_today": 0
                    })
                
                return keys
        except Exception as e:
            logger.error(f"List API keys error: {e}")
            return []
    
    def get_api_key_info(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Возвращает информацию об API ключе."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM api_keys WHERE api_key = %s"
                cursor.execute(self._adapt_query(query), (api_key,))
                result = cursor.fetchone()
                return dict(result) if result else None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"API key info error: {e}")
            return None
    
    def reset_rate_limits(self):
        """Ежедневное сброс счетчиков запросов."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE api_keys SET requests_today = 0, requests_hour = 0")
                self._commit_if_needed(conn)
                logger.info("Rate limits reset successfully")
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Rate limit reset error: {e}")
    
    # ===== THREAT DATABASE METHODS =====
    
    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Проверяет хэш файла в базе данных."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT hash, threat_type, severity, description, detection_count
                    FROM malicious_hashes 
                    WHERE hash = %s
                """
                cursor.execute(self._adapt_query(query), (file_hash.lower(),))
                
                result = cursor.fetchone()
                if result:
                    # Увеличиваем счетчик обнаружений
                    query_update = """
                        UPDATE malicious_hashes 
                        SET detection_count = detection_count + 1,
                            last_updated = CURRENT_TIMESTAMP
                        WHERE hash = %s
                    """
                    cursor.execute(self._adapt_query(query_update), (file_hash.lower(),))
                    self._commit_if_needed(conn)
                
                return dict(result) if result else None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Hash check error: {e}")
            return None
    
    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Проверяет URL в базе данных с улучшенной обработкой ошибок."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    query = """
                        SELECT url, domain, threat_type, severity, description, detection_count
                        FROM malicious_urls 
                        WHERE url = %s
                    """
                    cursor.execute(self._adapt_query(query), (url.lower(),))
                    
                    result = cursor.fetchone()
                    if result:
                        # Увеличиваем счетчик обнаружений
                        try:
                            query_update = """
                                UPDATE malicious_urls 
                                SET detection_count = detection_count + 1,
                                    last_updated = CURRENT_TIMESTAMP
                                WHERE url = %s
                            """
                            cursor.execute(self._adapt_query(query_update), (url.lower(),))
                            self._commit_if_needed(conn)
                        except psycopg2.Error as update_error:
                            logger.warning(f"Failed to update detection_count for {url}: {update_error}")
                            # Не критично, продолжаем
                    
                    return dict(result) if result else None
            except psycopg2.OperationalError as e:
                error_msg = str(e).lower()
                if attempt < max_retries - 1:
                    logger.warning(f"PostgreSQL operational error during URL check (attempt {attempt + 1}/{max_retries}), retrying...")
                    import time
                    time.sleep(0.1 * (attempt + 1))
                    continue
                logger.error(f"URL check operational error: {e}", exc_info=True)
                raise
            except (psycopg2.Error, Exception) as e:
                logger.error(f"URL check database error: {e}", exc_info=True)
                if attempt == max_retries - 1:
                    raise
                import time
                time.sleep(0.1 * (attempt + 1))
        
        logger.error(f"URL check failed after {max_retries} attempts")
        return None
    
    def check_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Проверяет домен в базе данных с улучшенной обработкой ошибок."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    query = """
                        SELECT url, threat_type, severity, description, detection_count
                        FROM malicious_urls 
                        WHERE domain = %s
                    """
                    cursor.execute(self._adapt_query(query), (domain.lower(),))
                    
                    return [dict(row) for row in cursor.fetchall()]
            except psycopg2.OperationalError as e:
                error_msg = str(e).lower()
                if attempt < max_retries - 1:
                    logger.warning(f"PostgreSQL operational error during domain check (attempt {attempt + 1}/{max_retries}), retrying...")
                    import time
                    time.sleep(0.1 * (attempt + 1))
                    continue
                logger.error(f"Domain check operational error: {e}", exc_info=True)
                raise
            except (psycopg2.Error, Exception) as e:
                logger.error(f"Domain check database error: {e}", exc_info=True)
                if attempt == max_retries - 1:
                    raise
                import time
                time.sleep(0.1 * (attempt + 1))
        
        logger.error(f"Domain check failed after {max_retries} attempts")
        return []
    
    def add_malicious_hash(self, file_hash: str, threat_type: str, 
                          description: str = "", severity: str = "medium") -> bool:
        """Добавляет вредоносный хэш в базу данных."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO malicious_hashes 
                    (hash, threat_type, severity, description, last_updated)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(hash) DO UPDATE SET
                        threat_type = EXCLUDED.threat_type,
                        severity = EXCLUDED.severity,
                        description = EXCLUDED.description,
                        last_updated = CURRENT_TIMESTAMP,
                        detection_count = malicious_hashes.detection_count + 1
                """
                cursor.execute(self._adapt_query(query), (file_hash.lower(), threat_type, severity, description))
                
                self._commit_if_needed(conn)
                logger.info(f"Malicious hash added: {file_hash}")
                return True
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Add hash error: {e}")
            return False
    
    def add_malicious_url(self, url: str, threat_type: str, 
                         description: str = "", severity: str = "medium") -> bool:
        """Добавляет вредоносный URL в базу данных."""
        try:
            domain = urlparse(url).netloc.lower()
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO malicious_urls 
                    (url, domain, threat_type, severity, description, last_updated)
                    VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(url) DO UPDATE SET
                        domain = EXCLUDED.domain,
                        threat_type = EXCLUDED.threat_type,
                        severity = EXCLUDED.severity,
                        description = EXCLUDED.description,
                        last_updated = CURRENT_TIMESTAMP,
                        detection_count = malicious_urls.detection_count + 1
                """
                cursor.execute(self._adapt_query(query), (url.lower(), domain, threat_type, severity, description))
                
                self._commit_if_needed(conn)
                logger.info(f"Malicious URL added: {url}")
                return True
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Add URL error: {e}")
            return False
    
    # ===== LOCAL SECURITY CACHE METHODS =====

    def _extract_domain(self, value: str) -> Optional[str]:
        if not value:
            return None
        try:
            parsed = urlparse(value if value.startswith(('http://', 'https://')) else f"https://{value}")
            hostname = parsed.hostname or parsed.netloc
            return hostname.lower() if hostname else None
        except Exception:
            return None

    def _hash_url(self, url: str) -> str:
        normalized = url.strip().lower()
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

    # Метод _append_cache_file удалён - только PostgreSQL

    def get_cached_security(self, url: str) -> Optional[Dict[str, Any]]:
        """Возвращает сохраненный результат (whitelist/blacklist) для URL."""
        domain = self._extract_domain(url)
        url_hash = self._hash_url(url)
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if domain:
                    query = "SELECT * FROM cached_whitelist WHERE domain = %s"
                    cursor.execute(self._adapt_query(query), (domain,))
                    row = cursor.fetchone()
                    if row:
                        query_update = """
                            UPDATE cached_whitelist
                            SET hit_count = hit_count + 1,
                                last_seen = CURRENT_TIMESTAMP
                            WHERE domain = %s
                        """
                        cursor.execute(self._adapt_query(query_update), (domain,))
                        self._commit_if_needed(conn)
                        payload = json.loads(row["payload"]) if row["payload"] else None
                        return {
                            "safe": True,
                            "threat_type": None,
                            "details": row["details"],
                            "source": row["source"] or "local_whitelist",
                            "detection_ratio": row["detection_ratio"],
                            "confidence": row["confidence"],
                            "storage": "whitelist",
                            "domain": row["domain"],
                            "cached_at": row["last_seen"],
                            "payload": payload
                        }
                query = "SELECT * FROM cached_blacklist WHERE url_hash = %s"
                cursor.execute(self._adapt_query(query), (url_hash,))
                row = cursor.fetchone()
                if row:
                    query_update = """
                        UPDATE cached_blacklist
                        SET hit_count = hit_count + 1,
                            last_seen = CURRENT_TIMESTAMP
                        WHERE url_hash = %s
                    """
                    cursor.execute(self._adapt_query(query_update), (url_hash,))
                    self._commit_if_needed(conn)
                    payload = json.loads(row["payload"]) if row["payload"] else None
                    return {
                        "safe": False,
                        "threat_type": row["threat_type"] or "malicious",
                        "details": row["details"],
                        "source": row["source"] or "local_blacklist",
                        "storage": "blacklist",
                        "url": row["url"],
                        "domain": row["domain"],
                        "cached_at": row["last_seen"],
                        "payload": payload
                    }
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Cache lookup error: {e}", exc_info=True)
        except json.JSONDecodeError as json_error:
            logger.warning(f"Cache payload decode issue: {json_error}")
        return None

    def save_whitelist_entry(self, domain: str, payload: Dict[str, Any]) -> bool:
        domain = self._extract_domain(domain)
        if not domain:
            return False
        details = payload.get("details")
        detection_ratio = payload.get("detection_ratio")
        confidence = payload.get("confidence")
        source = payload.get("source", "external_apis")
        serialized = json.dumps(payload, ensure_ascii=False)
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                        details = EXCLUDED.details,
                        detection_ratio = EXCLUDED.detection_ratio,
                        confidence = EXCLUDED.confidence,
                        source = EXCLUDED.source,
                        payload = EXCLUDED.payload,
                        last_seen = CURRENT_TIMESTAMP
                """
                cursor.execute(self._adapt_query(query), (domain, details, detection_ratio, confidence, source, serialized))
                self._commit_if_needed(conn)
                file_entry = {
                    "domain": domain,
                    "details": details,
                    "detection_ratio": detection_ratio,
                    "confidence": confidence,
                    "source": source,
                    "payload": payload,
                    "saved_at": datetime.utcnow().isoformat()
                }
                # Кеш-файлы удалены - только PostgreSQL
                return True
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Save whitelist entry error: {e}")
            return False

    def save_blacklist_entry(self, url: str, payload: Dict[str, Any]) -> bool:
        domain = self._extract_domain(url)
        if not domain:
            return False
        url_hash = self._hash_url(url)
        details = payload.get("details")
        threat_type = payload.get("threat_type", "malicious")
        source = payload.get("source", "external_apis")
        serialized = json.dumps(payload, ensure_ascii=False)
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO cached_blacklist (url_hash, url, domain, threat_type, details, source, payload)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(url_hash) DO UPDATE SET
                        url = EXCLUDED.url,
                        domain = EXCLUDED.domain,
                        threat_type = EXCLUDED.threat_type,
                        details = EXCLUDED.details,
                        source = EXCLUDED.source,
                        payload = EXCLUDED.payload,
                        last_seen = CURRENT_TIMESTAMP
                """
                cursor.execute(self._adapt_query(query), (url_hash, url, domain, threat_type, details, source, serialized))
                self._commit_if_needed(conn)
                file_entry = {
                    "url": url,
                    "domain": domain,
                    "threat_type": threat_type,
                    "details": details,
                    "source": source,
                    "payload": payload,
                    "saved_at": datetime.utcnow().isoformat()
                }
                # Кеш-файлы удалены - только PostgreSQL
                return True
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Save blacklist entry error: {e}")
            return False

    def get_cache_stats(self) -> Dict[str, Any]:
        """Возвращает статистику локального кэша."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count, SUM(hit_count) as hits FROM cached_whitelist")
                whitelist_row = cursor.fetchone()
                cursor.execute("SELECT COUNT(*) as count, SUM(hit_count) as hits FROM cached_blacklist")
                blacklist_row = cursor.fetchone()
                cursor.execute("""
                    SELECT COALESCE(SUM(LENGTH(COALESCE(payload, '')) + LENGTH(COALESCE(details, '')) + LENGTH(COALESCE(url, ''))), 0) as sum_bytes
                    FROM cached_blacklist
                """)
                blacklist_result = cursor.fetchone()
                blacklist_bytes = blacklist_result["sum_bytes"] if blacklist_result else 0
                cursor.execute("""
                    SELECT COALESCE(SUM(LENGTH(COALESCE(payload, '')) + LENGTH(COALESCE(details, '')) + LENGTH(COALESCE(domain, ''))), 0) as sum_bytes
                    FROM cached_whitelist
                """)
                whitelist_result = cursor.fetchone()
                whitelist_bytes = whitelist_result["sum_bytes"] if whitelist_result else 0
                total_entries = (whitelist_row["count"] or 0) + (blacklist_row["count"] or 0)
                return {
                    "whitelist_entries": whitelist_row["count"] or 0,
                    "blacklist_entries": blacklist_row["count"] or 0,
                    "whitelist_hits": whitelist_row["hits"] or 0,
                    "blacklist_hits": blacklist_row["hits"] or 0,
                    "bytes_estimated": int(whitelist_bytes + blacklist_bytes),
                    "total_entries": total_entries
                }
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Cache stats error: {e}")
            return {
                "whitelist_entries": 0,
                "blacklist_entries": 0,
                "whitelist_hits": 0,
                "blacklist_hits": 0,
                "bytes_estimated": 0,
                "total_entries": 0
            }

    def get_cached_entries(self, store: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Возвращает старейшие записи из whitelist/blacklist."""
        table = 'cached_whitelist' if store == 'whitelist' else 'cached_blacklist'
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = f"SELECT * FROM {table} ORDER BY last_seen ASC LIMIT %s"
                cursor.execute(self._adapt_query(query), (limit,))
                rows = []
                for row in cursor.fetchall():
                    payload = None
                    if row["payload"]:
                        try:
                            payload = json.loads(row["payload"])
                        except json.JSONDecodeError:
                            payload = None
                    entry = dict(row)
                    entry["payload"] = payload
                    rows.append(entry)
                return rows
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Fetch cached entries error: {e}")
            return []

    # ===== STATISTICS AND ADMIN METHODS =====
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Возвращает статистику базы данных."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) as count FROM malicious_hashes")
                hash_count = cursor.fetchone()["count"]
                
                cursor.execute("SELECT COUNT(*) as count FROM malicious_urls")
                url_count = cursor.fetchone()["count"]
                
                cursor.execute("SELECT COUNT(*) as count FROM api_keys WHERE is_active = TRUE")
                active_keys = cursor.fetchone()["count"]
                
                cursor.execute("SELECT SUM(requests_total) as total FROM api_keys")
                total_requests = cursor.fetchone()["total"] or 0
                
                cache_stats = self.get_cache_stats()
                
                return {
                    "malicious_hashes": hash_count,
                    "malicious_urls": url_count,
                    "total_threats": hash_count + url_count,
                    "active_api_keys": active_keys,
                    "total_requests": total_requests,
                    "whitelist_entries": cache_stats.get("whitelist_entries", 0),
                    "blacklist_entries": cache_stats.get("blacklist_entries", 0),
                    "cache_hits": (cache_stats.get("whitelist_hits", 0) or 0) + (cache_stats.get("blacklist_hits", 0) or 0)
                }
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Database stats error: {e}")
            return {}
    
    def log_request(self, user_id: Optional[int], endpoint: str, method: str,
                   status_code: int, response_time_ms: int, 
                   user_agent: Optional[str], client_ip: Optional[str]):
        """Логирует запрос в базу данных."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Усечение IP до /24 для приватности
                truncated_ip = None
                try:
                    if client_ip and ":" not in client_ip:
                        parts = client_ip.split(".")
                        if len(parts) == 4:
                            truncated_ip = ".".join(parts[:3]) + ".0"
                except Exception:
                    truncated_ip = None

                query = """
                    INSERT INTO request_logs 
                    (user_id, endpoint, method, status_code, response_time_ms, user_agent, client_ip_truncated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(self._adapt_query(query), (user_id, endpoint, method, status_code, response_time_ms, user_agent, truncated_ip))
                self._commit_if_needed(conn)
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Request log error: {e}")

    # ===== IP REPUTATION =====
    def upsert_ip_reputation(self, ip: str, threat_type: Optional[str], reputation_score: Optional[int], details: str, source: str) -> bool:
        """Создает или обновляет запись репутации IP."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO ip_reputation (ip, threat_type, reputation_score, details, source)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT(ip) DO UPDATE SET
                        threat_type=EXCLUDED.threat_type,
                        reputation_score=EXCLUDED.reputation_score,
                        details=EXCLUDED.details,
                        source=EXCLUDED.source,
                        last_updated=CURRENT_TIMESTAMP,
                        detection_count=ip_reputation.detection_count+1
                """
                cursor.execute(self._adapt_query(query), (ip, threat_type, reputation_score, details, source))
                self._commit_if_needed(conn)
                return True
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Upsert IP reputation error: {e}")
            return False

    def get_ip_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM ip_reputation WHERE ip = %s"
                cursor.execute(self._adapt_query(query), (ip,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get IP reputation error: {e}")
            return None

    def list_ip_reputation(self, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT ip, threat_type, reputation_score, details, source, last_updated, detection_count FROM ip_reputation ORDER BY last_updated DESC LIMIT %s"
                cursor.execute(self._adapt_query(query), (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except (psycopg2.Error, Exception) as e:
            logger.error(f"List IP reputation error: {e}")
            return []
    def get_api_key_stats(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Возвращает статистику использования API ключа."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT name, is_active, rate_limit_daily, rate_limit_hourly,
                       requests_total, requests_today, requests_hour,
                       created_at, last_used, expires_at
                FROM api_keys 
                WHERE api_key = %s
            """, (api_key,))
            
                result = cursor.fetchone()
                return dict(result) if result else None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"API key stats error: {e}")
            return None
    # В класс DatabaseManager добавим методы:

    def get_all_hashes(self) -> List[Dict[str, Any]]:
        """Возвращает все вредоносные хэши."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT hash, threat_type, severity FROM malicious_hashes")
                return [dict(row) for row in cursor.fetchall()]
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get all hashes error: {e}")
        return []

    def get_all_urls(self) -> List[Dict[str, Any]]:
        """Возвращает все вредоносные URL."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT url, threat_type, severity FROM malicious_urls")
                return [dict(row) for row in cursor.fetchall()]
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get all URLs error: {e}")
        return []
    
    def get_all_threats(self) -> List[Dict[str, Any]]:
        """Получает все угрозы из реальных таблиц (malicious_urls и malicious_hashes)"""
        threats = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Получаем URL угрозы
                cursor.execute("""
                    SELECT url as value, threat_type, severity, description, 
                           source, first_detected as created_at, detection_count
                    FROM malicious_urls
                    ORDER BY first_detected DESC
                """)
                for row in cursor.fetchall():
                    threats.append({
                        "type": "url",
                        "value": row["value"],
                        "threat_level": row["severity"],
                        "threat_type": row["threat_type"],
                        "description": row["description"],
                        "source": row["source"] or "unknown",
                        "created_at": row["created_at"],
                        "detection_count": row["detection_count"]
                    })
                
                # Получаем хэш угрозы
                cursor.execute("""
                    SELECT hash as value, threat_type, severity, description,
                           source, first_detected as created_at, detection_count
                    FROM malicious_hashes
                    ORDER BY first_detected DESC
                """)
                for row in cursor.fetchall():
                    threats.append({
                        "type": "hash",
                        "value": row["value"],
                        "threat_level": row["severity"],
                        "threat_type": row["threat_type"],
                        "description": row["description"],
                        "source": row["source"] or "unknown",
                        "created_at": row["created_at"],
                        "detection_count": row["detection_count"]
                    })
                
                return threats
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get all threats error: {e}")
            return []
    
    def get_all_logs(self) -> List[Dict[str, Any]]:
        """Получает все логи из упрощенной таблицы logs"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT endpoint, method, status_code, response_time_ms, client_ip, api_key_hash, created_at
                    FROM logs
                    ORDER BY created_at DESC
                """)
                return [dict(row) for row in cursor.fetchall()]
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get all logs error: {e}")
            return []
    
    # ===== ACCOUNT MANAGEMENT =====
    
    def create_account(self, username: str, email: str, password_hash: str) -> Optional[int]:
        """Создает новый аккаунт и возвращает его ID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO accounts (username, email, password_hash, is_active)
                    VALUES (%s, %s, %s, TRUE)
                    RETURNING id
                """
                cursor.execute(self._adapt_query(query), (username, email, password_hash))
                self._commit_if_needed(conn)
                result = cursor.fetchone()
                return result["id"] if result else None
        except psycopg2.IntegrityError as e:
            logger.error(f"Account creation error (duplicate): {e}")
            return None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Account creation error: {e}")
            return None
    
    def get_account_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Возвращает аккаунт по username."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM accounts WHERE username = %s"
                cursor.execute(self._adapt_query(query), (username,))
                result = cursor.fetchone()
                return dict(result) if result else None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get account by username error: {e}")
            return None
    
    def get_account_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Возвращает аккаунт по email."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM accounts WHERE email = %s"
                cursor.execute(self._adapt_query(query), (email,))
                result = cursor.fetchone()
                return dict(result) if result else None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get account by email error: {e}")
            return None
    
    def get_account_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Возвращает аккаунт по ID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM accounts WHERE id = %s"
                cursor.execute(self._adapt_query(query), (user_id,))
                result = cursor.fetchone()
                return dict(result) if result else None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get account by ID error: {e}")
            return None
    
    def bind_api_key_to_account(self, api_key: str, user_id: int) -> bool:
        """Привязывает API ключ к аккаунту."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Проверяем, что ключ существует и не привязан
                query = "SELECT user_id FROM api_keys WHERE api_key = %s"
                cursor.execute(self._adapt_query(query), (api_key,))
                result = cursor.fetchone()
                
                if not result:
                    return False  # Ключ не найден
                
                if result["user_id"] is not None:
                    return False  # Ключ уже привязан
                
                # Привязываем ключ
                query = """
                    UPDATE api_keys 
                    SET user_id = %s 
                    WHERE api_key = %s
                """
                cursor.execute(self._adapt_query(query), (user_id, api_key))
                self._commit_if_needed(conn)
                
                logger.info(f"API key {api_key} bound to account {user_id}")
                return True
                
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Bind API key error: {e}")
            return False
    
    def get_api_keys_for_account(self, user_id: int) -> List[Dict[str, Any]]:
        """Возвращает все API ключи для аккаунта."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT api_key, name, description, access_level, expires_at,
                           created_at, last_used, requests_total
                    FROM api_keys 
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """
                cursor.execute(self._adapt_query(query), (user_id,))
                
                return [dict(row) for row in cursor.fetchall()]
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get API keys for account error: {e}")
            return []
    
    def get_free_api_keys(self) -> List[Dict[str, Any]]:
        """Возвращает все свободные (не привязанные) API ключи."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT api_key, name, description, access_level, expires_at,
                           created_at
                    FROM api_keys 
                    WHERE user_id IS NULL AND is_active = TRUE
                    ORDER BY created_at DESC
                """)
                
                return [dict(row) for row in cursor.fetchall()]
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get free API keys error: {e}")
            return []
    
    def update_last_login(self, user_id: int):
        """Обновляет время последнего входа."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    UPDATE accounts 
                    SET last_login = CURRENT_TIMESTAMP 
                    WHERE id = %s
                """
                cursor.execute(self._adapt_query(query), (user_id,))
                self._commit_if_needed(conn)
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Update last login error: {e}")
    
    # ===== SESSION MANAGEMENT METHODS =====
    
    def get_active_session_token(self, user_id: int) -> Optional[str]:
        """Получает активный session_token пользователя."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT session_token FROM active_sessions 
                    WHERE user_id = %s 
                    AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                """
                cursor.execute(self._adapt_query(query), (user_id,))
                result = cursor.fetchone()
                return result["session_token"] if result else None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get active session token error: {e}")
            return None
    
    def get_session_by_device_id(self, user_id: int, device_id: str) -> Optional[Dict[str, Any]]:
        """Получает сессию по user_id и device_id."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT user_id, session_token, device_id, created_at, expires_at
                    FROM active_sessions 
                    WHERE user_id = %s AND device_id = %s
                """
                cursor.execute(self._adapt_query(query), (user_id, device_id))
                result = cursor.fetchone()
                if result:
                    expires_at_str = result["expires_at"]
                    # Проверяем срок действия в Python
                    if expires_at_str:
                        try:
                            expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                            if expires_at <= datetime.now():
                                logger.debug(f"Session expired for user_id={user_id}, device_id={device_id}")
                                return None
                        except (ValueError, AttributeError):
                            pass  # При ошибке парсинга считаем валидной
                    
                    return {
                        "user_id": result["user_id"],
                        "session_token": result["session_token"],
                        "device_id": result["device_id"],
                        "created_at": result["created_at"],
                        "expires_at": result["expires_at"]
                    }
                return None
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get session by device_id error: {e}")
            return None
    
    def set_active_session(self, user_id: int, session_token: str, device_id: str = None, expires_hours: int = 720) -> bool:
        """
        Устанавливает активную сессию для пользователя.
        КРИТИЧНО: Если device_id совпадает - обновляем существующую сессию.
        Если device_id отличается - заменяем сессию (старое устройство автоматически выйдет).
        """
        try:
            expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Если device_id указан, проверяем существующую сессию для этого device_id
                if device_id:
                    query = """
                        SELECT user_id FROM active_sessions 
                        WHERE user_id = %s AND device_id = %s
                    """
                    cursor.execute(self._adapt_query(query), (user_id, device_id))
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Обновляем только expires_at для существующей сессии (НЕ меняем session_token!)
                        query_update = """
                            UPDATE active_sessions 
                            SET expires_at = %s
                            WHERE user_id = %s AND device_id = %s
                        """
                        cursor.execute(self._adapt_query(query_update), (expires_at, user_id, device_id))
                        logger.info(f"Updated existing session expiry for user_id={user_id}, device_id={device_id}")
                    else:
                        # Удаляем старую сессию для этого user_id (если есть) и создаем новую
                        query_delete = "DELETE FROM active_sessions WHERE user_id = %s"
                        cursor.execute(self._adapt_query(query_delete), (user_id,))
                        query_insert = """
                            INSERT INTO active_sessions 
                    (user_id, session_token, device_id, expires_at)
                            VALUES (%s, %s, %s, %s)
                        """
                        cursor.execute(self._adapt_query(query_insert), (user_id, session_token, device_id, expires_at))
                        logger.info(f"Replaced session for user_id={user_id}, new device_id={device_id}")
                else:
                    # Если device_id не указан - используем INSERT ... ON CONFLICT для PostgreSQL
                    query = """
                        INSERT INTO active_sessions 
                        (user_id, session_token, device_id, expires_at)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT(user_id) DO UPDATE SET
                            session_token = EXCLUDED.session_token,
                            device_id = EXCLUDED.device_id,
                            expires_at = EXCLUDED.expires_at
                    """
                    cursor.execute(self._adapt_query(query), (user_id, session_token, device_id, expires_at))
                logger.info(f"Active session set for user_id={user_id}, device_id={device_id}")
                
                self._commit_if_needed(conn)
                return True
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Set active session error: {e}")
            return False
    
    def update_session_expiry(self, user_id: int, device_id: str, expires_hours: int = 720) -> bool:
        """Обновляет срок действия существующей сессии без изменения session_token."""
        try:
            expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    UPDATE active_sessions 
                    SET expires_at = %s
                    WHERE user_id = %s AND device_id = %s
                """
                cursor.execute(self._adapt_query(query), (expires_at, user_id, device_id))
                
                self._commit_if_needed(conn)
                logger.info(f"Updated session expiry for user_id={user_id}, device_id={device_id}")
                return cursor.rowcount > 0
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Update session expiry error: {e}")
            return False
    
    def validate_session_token(self, session_token: str) -> Optional[int]:
        """
        Проверяет валидность session_token.
        Возвращает user_id если сессия валидна, иначе None.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Получаем сессию и проверяем expires_at в Python (более надежно)
                query = """
                    SELECT user_id, expires_at, device_id FROM active_sessions 
                    WHERE session_token = %s
                """
                cursor.execute(self._adapt_query(query), (session_token,))
                result = cursor.fetchone()
                
                if not result:
                    logger.debug(f"Session token not found: {session_token[:10]}...")
                    return None
                
                user_id = result["user_id"]
                expires_at_str = result["expires_at"]
                device_id = result["device_id"]
                
                # Если expires_at NULL - сессия бессрочная
                if expires_at_str is None:
                    logger.debug(f"Session valid (no expiry) for user_id={user_id}, device_id={device_id}")
                    return user_id
                
                # Проверяем срок действия в Python
                try:
                    # Обрабатываем разные форматы времени
                    expires_at_str_clean = expires_at_str.replace('Z', '+00:00')
                    if '+' not in expires_at_str_clean and expires_at_str_clean.count(':') == 2:
                        # Формат без timezone - добавляем локальное время
                        expires_at = datetime.fromisoformat(expires_at_str_clean)
                    else:
                        expires_at = datetime.fromisoformat(expires_at_str_clean)
                    
                    now = datetime.now()
                    if expires_at > now:
                        logger.debug(f"Session valid for user_id={user_id}, device_id={device_id}, expires_at={expires_at_str}")
                        return user_id
                    else:
                        logger.warning(f"Session expired for user_id={user_id}, device_id={device_id}, expires_at={expires_at_str}, now={now.isoformat()}")
                        return None
                except (ValueError, AttributeError) as e:
                    logger.warning(f"Error parsing expires_at '{expires_at_str}': {e}, treating as valid")
                    return user_id  # При ошибке парсинга считаем сессию валидной
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Validate session token error: {e}", exc_info=True)
            return None
    
    def delete_session(self, session_token: str) -> bool:
        """Удаляет сессию по токену."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "DELETE FROM active_sessions WHERE session_token = %s"
                cursor.execute(self._adapt_query(query), (session_token,))
                self._commit_if_needed(conn)
                return cursor.rowcount > 0
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Delete session error: {e}")
            return False
    
    def generate_reset_code(self, email: str) -> Optional[str]:
        """
        Генерирует код восстановления и сохраняет его в таблицу password_resets.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                query = "SELECT id FROM accounts WHERE email = %s"
                cursor.execute(self._adapt_query(query), (email,))
                result = cursor.fetchone()
                if not result:
                    return None

                user_id = result["id"]

                import secrets
                code = str(secrets.randbelow(900000) + 100000)

                expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
                
                query_delete = "DELETE FROM password_resets WHERE user_id = %s"
                cursor.execute(self._adapt_query(query_delete), (user_id,))

                query_insert = """
                    INSERT INTO password_resets (user_id, token, expires_at)
                    VALUES (%s, %s, %s)
                """
                cursor.execute(self._adapt_query(query_insert), (user_id, code, expires_at))

                self._commit_if_needed(conn)
                logger.info(f"Generated reset code {code} for user_id {user_id}")
                return code

        except Exception as e:
            logger.error(f"Generate reset code error: {e}", exc_info=True)
            return None
    
    def verify_reset_code(self, email: str, code: str) -> bool:
        """Проверяет код восстановления."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT reset_code, reset_code_expires
                    FROM accounts 
                    WHERE email = %s
                """
                cursor.execute(self._adapt_query(query), (email,))
                
                result = cursor.fetchone()
                if not result:
                    return False
                
                stored_code = result["reset_code"]
                expires_str = result["reset_code_expires"]
                if not stored_code or stored_code != code:
                    return False
                
                # Проверяем срок действия
                expires_at = datetime.fromisoformat(expires_str)
                if datetime.now() > expires_at:
                    return False
                
                return True
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Verify reset code error: {e}")
            return False
    
    def reset_password(self, email: str, new_password_hash: str) -> bool:
        """Сбрасывает пароль и очищает код восстановления."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    UPDATE accounts 
                    SET password_hash = %s, reset_code = NULL, reset_code_expires = NULL
                    WHERE email = %s
                """
                cursor.execute(self._adapt_query(query), (new_password_hash, email))
                
                if cursor.rowcount == 0:
                    return False
                
                self._commit_if_needed(conn)
                return True
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Reset password error: {e}")
            return False
    
    # ===== DATABASE CLEANUP METHODS =====
    
    def clear_malicious_urls(self) -> int:
        """Очищает все вредоносные URL из базы данных. Возвращает количество удаленных записей."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM malicious_urls")
                count = cursor.fetchone()["count"]
                cursor.execute("DELETE FROM malicious_urls")
                self._commit_if_needed(conn)
                logger.info(f"Cleared {count} malicious URLs from database")
                return count
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Clear malicious URLs error: {e}")
            return 0
    
    def clear_malicious_hashes(self) -> int:
        """Очищает все вредоносные хэши из базы данных. Возвращает количество удаленных записей."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM malicious_hashes")
                count = cursor.fetchone()["count"]
                cursor.execute("DELETE FROM malicious_hashes")
                self._commit_if_needed(conn)
                logger.info(f"Cleared {count} malicious hashes from database")
                return count
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Clear malicious hashes error: {e}")
            return 0
    
    def clear_cached_whitelist(self) -> int:
        """Очищает весь whitelist кэш. Возвращает количество удаленных записей."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM cached_whitelist")
                count = cursor.fetchone()["count"]
                cursor.execute("DELETE FROM cached_whitelist")
                self._commit_if_needed(conn)
                logger.info(f"Cleared {count} whitelist entries from cache")
                return count
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Clear whitelist cache error: {e}")
            return 0
    
    def clear_cached_blacklist(self) -> int:
        """Очищает весь blacklist кэш. Возвращает количество удаленных записей."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM cached_blacklist")
                count = cursor.fetchone()["count"]
                cursor.execute("DELETE FROM cached_blacklist")
                self._commit_if_needed(conn)
                logger.info(f"Cleared {count} blacklist entries from cache")
                return count
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Clear blacklist cache error: {e}")
            return 0
    
    def clear_all_url_data(self) -> Dict[str, int]:
        """Очищает все данные, связанные с URL (malicious_urls, cached_whitelist, cached_blacklist)."""
        return {
            "malicious_urls": self.clear_malicious_urls(),
            "cached_whitelist": self.clear_cached_whitelist(),
            "cached_blacklist": self.clear_cached_blacklist()
        }
    
    def remove_malicious_url(self, url: str) -> bool:
        """Удаляет конкретный URL из таблицы malicious_urls."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "DELETE FROM malicious_urls WHERE url = %s"
                cursor.execute(self._adapt_query(query), (url.lower(),))
                self._commit_if_needed(conn)
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.info(f"Removed malicious URL from database: {url}")
                return deleted
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Remove malicious URL error: {e}")
            return False
    
    def remove_cached_blacklist_url(self, url: str) -> bool:
        """Удаляет конкретный URL из cached_blacklist."""
        try:
            url_hash = self._hash_url(url)
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "DELETE FROM cached_blacklist WHERE url_hash = %s"
                cursor.execute(self._adapt_query(query), (url_hash,))
                self._commit_if_needed(conn)
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.info(f"Removed URL from blacklist cache: {url}")
                return deleted
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Remove cached blacklist URL error: {e}")
            return False
    
    def mark_url_as_safe(self, url: str) -> bool:
        """Помечает URL как безопасный: удаляет из malicious_urls и cached_blacklist."""
        removed_malicious = self.remove_malicious_url(url)
        removed_blacklist = self.remove_cached_blacklist_url(url)
        return removed_malicious or removed_blacklist
    
    def search_urls_in_database(self, search_term: str, limit: int = 100) -> Dict[str, List[Dict[str, Any]]]:
        """Ищет URL в базе данных по частичному совпадению."""
        results = {
            "malicious_urls": [],
            "cached_blacklist": [],
            "cached_whitelist": []
        }
        search_lower = search_term.lower()
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Поиск в malicious_urls
                query = """
                    SELECT url, domain, threat_type, severity, description, 
                           source, first_detected, last_updated, detection_count
                    FROM malicious_urls
                    WHERE url LIKE %s OR domain LIKE %s
                    ORDER BY last_updated DESC
                    LIMIT %s
                """
                cursor.execute(self._adapt_query(query), (f"%{search_lower}%", f"%{search_lower}%", limit))
                results["malicious_urls"] = [dict(row) for row in cursor.fetchall()]
                
                # Поиск в cached_blacklist
                query = """
                    SELECT url_hash, url, domain, threat_type, details, source,
                           first_seen, last_seen, hit_count
                    FROM cached_blacklist
                    WHERE url LIKE %s OR domain LIKE %s
                    ORDER BY last_seen DESC
                    LIMIT %s
                """
                cursor.execute(self._adapt_query(query), (f"%{search_lower}%", f"%{search_lower}%", limit))
                results["cached_blacklist"] = [dict(row) for row in cursor.fetchall()]
                
                # Поиск в cached_whitelist
                query = """
                    SELECT domain, details, detection_ratio, confidence, source,
                           first_seen, last_seen, hit_count
                    FROM cached_whitelist
                    WHERE domain LIKE %s
                    ORDER BY last_seen DESC
                    LIMIT %s
                """
                cursor.execute(self._adapt_query(query), (f"%{search_lower}%", limit))
                results["cached_whitelist"] = [dict(row) for row in cursor.fetchall()]
                
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Search URLs error: {e}")
        
        return results
    
    def get_all_cached_whitelist(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Возвращает все записи из whitelist кэша."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT domain, details, detection_ratio, confidence, source,
                           first_seen, last_seen, hit_count, payload
                    FROM cached_whitelist
                    ORDER BY last_seen DESC
                    LIMIT %s
                """, (limit,))
                rows = []
                for row in cursor.fetchall():
                    entry = dict(row)
                    if entry["payload"]:
                        try:
                            entry["payload"] = json.loads(entry["payload"])
                        except json.JSONDecodeError:
                            entry["payload"] = None
                    rows.append(entry)
                return rows
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get all cached whitelist error: {e}")
            return []
    
    def get_all_cached_blacklist(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Возвращает все записи из blacklist кэша."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT url_hash, url, domain, threat_type, details, source,
                           first_seen, last_seen, hit_count, payload
                    FROM cached_blacklist
                    ORDER BY last_seen DESC
                    LIMIT %s
                """, (limit,))
                rows = []
                for row in cursor.fetchall():
                    entry = dict(row)
                    if entry["payload"]:
                        try:
                            entry["payload"] = json.loads(entry["payload"])
                        except json.JSONDecodeError:
                            entry["payload"] = None
                    rows.append(entry)
                return rows
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Get all cached blacklist error: {e}")
            return []
    
    def clear_all_database_data(self) -> Dict[str, int]:
        """ПОЛНАЯ ОЧИСТКА базы данных - удаляет все данные из всех таблиц (кроме системных).
        ВНИМАНИЕ: Это удалит ВСЕ угрозы, кэш, IP репутацию, но сохранит API ключи и аккаунты.
        Также очищает JSONL файлы и диск-кэш.
        """
        results = {}
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Очищаем все таблицы с данными
                tables_to_clear = [
                    "malicious_urls",
                    "malicious_hashes",
                    "cached_whitelist",
                    "cached_blacklist",
                    "ip_reputation",
                    "request_logs",
                    "background_jobs"
                ]
                
                for table in tables_to_clear:
                    try:
                        cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                        count = cursor.fetchone()["count"]
                        cursor.execute(f"DELETE FROM {table}")
                        results[table] = count
                        logger.info(f"Cleared {count} records from {table}")
                    except (psycopg2.Error, Exception) as e:
                        logger.error(f"Error clearing {table}: {e}")
                        results[table] = 0
                
                self._commit_if_needed(conn)
                
                # JSONL файлы удалены - только PostgreSQL
                
                # Очищаем диск-кэш
                try:
                    from app.cache import disk_cache
                    cache_count = disk_cache.clear_all()
                    results["cache.db"] = cache_count
                    logger.info(f"Cleared {cache_count} entries from cache.db")
                except Exception as e:
                    logger.error(f"Error clearing disk cache: {e}")
                    results["cache.db"] = 0
                
                logger.warning("⚠️ FULL DATABASE CLEAR completed - all data tables, JSONL files and cache cleared")
                return results
        except (psycopg2.Error, Exception) as e:
            logger.error(f"Clear all database data error: {e}")
            return {}

    async def create_yookassa_payment(self, payment_id: str, user_id: int = None, amount: int = 0, license_type: str = "forever", is_renewal: bool = False):
        """Создает запись о платеже ЮKassa. user_id может быть None (nullable)."""
        try:
            logger.info(f"[DB] Creating YooKassa payment: payment_id={payment_id}, user_id={user_id}, amount={amount}, license_type={license_type}, is_renewal={is_renewal}")
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO yookassa_payments 
                    (payment_id, user_id, amount, license_type, status, is_renewal) 
                    VALUES (%s, %s, %s, %s, 'pending', %s)
                """
                logger.debug(f"[DB] Executing query: {query}")
                logger.debug(f"[DB] Parameters: payment_id={payment_id}, user_id={user_id}, amount={amount}, license_type={license_type}, is_renewal={is_renewal}")
                cursor.execute(self._adapt_query(query), (payment_id, user_id, amount, license_type, is_renewal))
                logger.debug(f"[DB] Query executed, committing...")
                self._commit_if_needed(conn)
                logger.info(f"[DB] ✅ Created YooKassa payment {payment_id} for user {user_id}, is_renewal={is_renewal}")
                return True
        except psycopg2.IntegrityError as e:
            logger.warning(f"[DB] Payment {payment_id} already exists in database (IntegrityError: {e})")
            return False
        except psycopg2.Error as e:
            logger.error(f"[DB] PostgreSQL error creating YooKassa payment: {type(e).__name__}: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"[DB] Unexpected error creating YooKassa payment: {type(e).__name__}: {e}", exc_info=True)
            return False

    async def get_yookassa_payment(self, payment_id: str):
        """Получает платёж Юкассы по ID"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT payment_id, user_id, amount, license_type, status, license_key, is_renewal, created_at, updated_at 
                    FROM yookassa_payments WHERE payment_id = %s
                """
                cursor.execute(self._adapt_query(query), (payment_id,))
                row = cursor.fetchone()
                if row:
                    # cursor использует RealDictCursor, поэтому row - это dict, а не tuple
                    return {
                        "payment_id": row["payment_id"],
                        "user_id": row["user_id"],
                        "amount": row["amount"],
                        "license_type": row["license_type"],
                        "status": row["status"],
                        "license_key": row["license_key"],
                        "is_renewal": bool(row["is_renewal"]) if row["is_renewal"] is not None else False,
                        "created_at": row["created_at"],
                        "updated_at": row["updated_at"]
                    }
                return None
        except Exception as e:
            logger.error(f"Get payment error: {e}", exc_info=True)
            return None
    
    async def update_yookassa_payment_status(self, payment_id: str, status: str, license_key: str = None):
        """Обновляет статус платежа ЮKassa"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                from datetime import datetime
                if license_key:
                    query = """
                        UPDATE yookassa_payments 
                        SET status = %s, license_key = %s, updated_at = %s 
                        WHERE payment_id = %s
                    """
                    cursor.execute(self._adapt_query(query), (status, license_key, datetime.now(), payment_id))
                else:
                    query = """
                        UPDATE yookassa_payments 
                        SET status = %s, updated_at = %s 
                        WHERE payment_id = %s
                    """
                    cursor.execute(self._adapt_query(query), (status, datetime.now(), payment_id))
                self._commit_if_needed(conn)
                logger.info(f"Updated YooKassa payment {payment_id} status to {status}, license_key={'set' if license_key else 'not set'}")
                return True
        except Exception as e:
            logger.error(f"Update YooKassa payment status error: {e}", exc_info=True)
            return False
    
    def get_user(self, user_id: int):
        """Получает пользователя Telegram бота по ID"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT user_id, username, has_license, license_key, created_at FROM users WHERE user_id = %s"
                cursor.execute(self._adapt_query(query), (user_id,))
                row = cursor.fetchone()
                if row:
                    # cursor использует RealDictCursor, поэтому row - это dict, а не tuple
                    return {
                        "user_id": row["user_id"],
                        "username": row["username"],
                        "has_license": bool(row["has_license"]),
                        "license_key": row["license_key"],
                        "created_at": row["created_at"]
                    }
                return None
        except Exception as e:
            logger.error(f"Get user error: {e}", exc_info=True)
            return None
    
    def create_user(self, user_id: int, username: str = None, email: str = None):
        """Создает пользователя Telegram бота или веб-пользователя"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO users (user_id, username, email) 
                    VALUES (%s, %s, %s)
                    ON CONFLICT(user_id) DO UPDATE SET username = COALESCE(EXCLUDED.username, users.username), email = COALESCE(EXCLUDED.email, users.email)
                """
                cursor.execute(self._adapt_query(query), (user_id, username, email))
                self._commit_if_needed(conn)
                logger.info(f"Created/updated user: user_id={user_id}, username={username}, email={email}")
                return True
        except Exception as e:
            logger.error(f"Create user error: {e}", exc_info=True)
            return False
    
    def update_user_license(self, user_id: int, license_key: str, email: str = None):
        """Обновляет лицензию пользователя"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Сначала создаем пользователя, если его нет
                query_insert = """
                    INSERT INTO users (user_id, email) 
                    VALUES (%s, %s)
                    ON CONFLICT(user_id) DO UPDATE SET email = COALESCE(EXCLUDED.email, users.email)
                """
                cursor.execute(self._adapt_query(query_insert), (user_id, email))
                # Обновляем лицензию
                query_update = """
                    UPDATE users SET has_license = TRUE, license_key = %s, email = COALESCE(%s, users.email) WHERE user_id = %s
                """
                cursor.execute(self._adapt_query(query_update), (license_key, email, user_id))
                self._commit_if_needed(conn)
                logger.info(f"Updated license for user {user_id}, email={email}")
                return True
        except Exception as e:
            logger.error(f"Update user license error: {e}", exc_info=True)
            return False
    
    def get_subscription(self, user_id: int):
        """Получает активную подписку пользователя"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """SELECT id, user_id, license_key, license_type, expires_at, auto_renew, renewal_count, status, created_at, updated_at
                           FROM subscriptions WHERE user_id = %s AND status = 'active' ORDER BY created_at DESC LIMIT 1"""
                cursor.execute(self._adapt_query(query), (user_id,))
                row = cursor.fetchone()
                if row:
                    # cursor использует RealDictCursor, поэтому row - это dict, а не tuple
                    return {
                        "id": row["id"],
                        "user_id": row["user_id"],
                        "license_key": row["license_key"],
                        "license_type": row["license_type"],
                        "expires_at": row["expires_at"],
                        "auto_renew": bool(row["auto_renew"]),
                        "renewal_count": row["renewal_count"],
                        "status": row["status"],
                        "created_at": row["created_at"],
                        "updated_at": row["updated_at"]
                    }
                return None
        except Exception as e:
            logger.error(f"Get subscription error: {e}", exc_info=True)
            return None
            
    def create_subscription(self, user_id: int, license_key: str, license_type: str, expires_at, auto_renew: bool = False):
        """Создает подписку для пользователя"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                from datetime import datetime
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                cursor.execute(
                    """INSERT INTO subscriptions (user_id, license_key, license_type, expires_at, auto_renew, status)
                       VALUES (%s, %s, %s, %s, %s, 'active')""",
                    (user_id, license_key, license_type, expires_at, auto_renew)
                )
                self._commit_if_needed(conn)
                logger.info(f"Created subscription for user {user_id}, expires_at={expires_at}")
                return True
        except Exception as e:
            logger.error(f"Create subscription error: {e}", exc_info=True)
            return False
    
    def update_subscription_expiry(self, user_id: int, expires_at):
        """Обновляет дату окончания подписки"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                from datetime import datetime
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                cursor.execute(
                    """UPDATE subscriptions 
                       SET expires_at = %s, renewal_count = renewal_count + 1, updated_at = %s
                       WHERE user_id = %s AND status = 'active'""",
                    (expires_at, datetime.now(), user_id)
                )
                self._commit_if_needed(conn)
                logger.info(f"Updated subscription expiry for user {user_id}, expires_at={expires_at}")
                return True
        except Exception as e:
            logger.error(f"Update subscription expiry error: {e}", exc_info=True)
            return False
    
    async def get_yookassa_payment_by_license_key(self, license_key: str):
        """Получает платеж ЮKassa по license_key"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT payment_id, user_id, amount, license_type, status, license_key, is_renewal, created_at, updated_at
                    FROM yookassa_payments WHERE license_key = %s ORDER BY created_at DESC LIMIT 1
                """
                cursor.execute(self._adapt_query(query), (license_key,))
                row = cursor.fetchone()
                if row:
                    # cursor использует RealDictCursor, поэтому row - это dict, а не tuple
                    return {
                        "payment_id": row["payment_id"],
                        "user_id": row["user_id"],
                        "amount": row["amount"],
                        "license_type": row["license_type"],
                        "status": row["status"],
                        "license_key": row["license_key"],
                        "is_renewal": bool(row["is_renewal"]) if row["is_renewal"] is not None else False,
                        "created_at": row["created_at"],
                        "updated_at": row["updated_at"]
                    }
                return None
        except Exception as e:
            logger.error(f"Get payment by license key error: {e}", exc_info=True)
            return None
            
        # --- МЕТОДЫ ДЛЯ ВОССТАНОВЛЕНИЯ ПАРОЛЯ ---

    def save_reset_token(self, user_id: int, token: str, expires_at) -> bool:
        """
        Сохраняет токен восстановления пароля.
        Предварительно удаляет старые токены этого пользователя, чтобы не засорять БД.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # 1. Удаляем старые токены для этого пользователя (опционально, для чистоты)
                query_delete = "DELETE FROM password_resets WHERE user_id = %s"
                cursor.execute(self._adapt_query(query_delete), (user_id,))
                
                # 2. Вставляем новый токен
                query_insert = """
                    INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s, %s, %s)
                """
                cursor.execute(self._adapt_query(query_insert), (user_id, token, expires_at))
                self._commit_if_needed(conn)
                return True
        except Exception as e:
            logger.error(f"Error saving reset token: {e}")
            return False

            logger.error(f"Error saving reset token: {e}")
            return False

    def get_user_id_by_token(self, token: str) -> Optional[int]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT user_id, expires_at FROM password_resets WHERE token = %s"
                cursor.execute(self._adapt_query(query), (token,))
                result = cursor.fetchone()

                if not result:
                    return None

                # cursor использует RealDictCursor, поэтому result - это dict, а не tuple
                user_id = result["user_id"]
                expires_str = result["expires_at"]

                if expires_str:
                    try:
                        clean_time = expires_str.replace("Z", "+00:00")
                        expires_at = datetime.fromisoformat(clean_time)

                        # Сравнение даты
                        if expires_at.tzinfo:
                            if datetime.now() > expires_at.replace(tzinfo=None):
                                self.delete_reset_tokens(user_id)
                                return None
                        else:
                            if datetime.now() > expires_at:
                                self.delete_reset_tokens(user_id)
                                return None

                    except Exception as e:
                        logger.error(f"Error parsing expires_at: {e}")
                        return None

                return user_id

        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            return None
    def update_password(self, user_id: int, password_hash: str) -> bool:
        """
        Обновляет хеш пароля пользователя.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "UPDATE accounts SET password_hash = %s WHERE id = %s"
                cursor.execute(self._adapt_query(query), (password_hash, user_id))
                self._commit_if_needed(conn)
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating password: {e}")
            return False

    def delete_reset_tokens(self, user_id: int) -> bool:
        """
        Удаляет все токены восстановления для пользователя.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "DELETE FROM password_resets WHERE user_id = %s"
                cursor.execute(self._adapt_query(query), (user_id,))
                self._commit_if_needed(conn)
                return True
        except Exception as e:
            logger.error(f"Error deleting reset tokens: {e}")
            return False
# Глобальный экземпляр менеджера базы данных
# Только PostgreSQL через DATABASE_URL
# КРИТИЧНО: Graceful degradation - не падаем если БД недоступна
_db_url = os.getenv("DATABASE_URL")
db_manager = None

if _db_url:
    try:
        logger.info(f"Initializing database manager with DATABASE_URL: {_db_url[:30]}...")
        db_manager = DatabaseManager(_db_url)
        # Проверяем подключение (не блокирующее)
        try:
            conn = db_manager._get_connection()
            conn.close()
            logger.info("✅ Database connection successful")
        except Exception as conn_error:
            logger.warning(f"⚠️ Database connection failed (will retry on use): {conn_error}")
            # Не падаем - сервис может работать без БД для JWT аутентификации
    except Exception as init_error:
        logger.error(f"❌ Failed to initialize database manager: {init_error}", exc_info=True)
        logger.warning("⚠️ Service will run with limited functionality (JWT auth will work)")
        db_manager = None
else:
    logger.warning("⚠️ DATABASE_URL not set - service will run with limited functionality")
    logger.warning("⚠️ JWT authentication will work, but database features will be unavailable")
