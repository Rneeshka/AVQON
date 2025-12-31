-- PostgreSQL initialization script for AEGIS DEV
-- This script creates all necessary tables for the application
-- Run automatically on first container start via docker-entrypoint-initdb.d

-- 1. Таблица для аккаунтов пользователей
CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP DEFAULT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    reset_code TEXT DEFAULT NULL,
    reset_code_expires TIMESTAMP DEFAULT NULL
);

-- 2. Таблица для API ключей (компактная)
CREATE TABLE IF NOT EXISTS api_keys (
    api_key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    is_active BOOLEAN DEFAULT TRUE,
    access_level VARCHAR(20) DEFAULT 'basic' CHECK(access_level IN ('basic', 'premium')),
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
);

-- 3. Таблица для вредоносных хэшей файлов
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
);

-- 4. Таблица для вредоносных URL
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
);

-- 5. Таблица для логов запросов (для аналитики)
CREATE TABLE IF NOT EXISTS request_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER DEFAULT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    user_agent TEXT,
    client_ip_truncated TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES accounts(id) ON DELETE SET NULL
);

-- 6. Таблица репутации IP
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip TEXT PRIMARY KEY,
    threat_type TEXT,
    reputation_score INTEGER,
    details TEXT,
    source TEXT,
    first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    detection_count INTEGER DEFAULT 1
);

-- 7. Таблица фоновых задач
CREATE TABLE IF NOT EXISTS background_jobs (
    id SERIAL PRIMARY KEY,
    job_type TEXT NOT NULL,
    job_data TEXT NOT NULL,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'processing', 'completed', 'failed')),
    retry_count INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. Таблица для локальной базы доверенных доменов (white-list)
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
);

-- 9. Таблица для локальной базы известных угроз (black-list)
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
);

CREATE INDEX IF NOT EXISTS idx_cached_blacklist_domain ON cached_blacklist(domain);
CREATE INDEX IF NOT EXISTS idx_cached_blacklist_url ON cached_blacklist(url);

-- 10. Таблица активных сессий (один аккаунт - одна активная сессия)
CREATE TABLE IF NOT EXISTS active_sessions (
    user_id INTEGER PRIMARY KEY,
    session_token TEXT UNIQUE NOT NULL,
    device_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- 11. Таблица для кодов восстановления пароля
CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- 12. Таблица пользователей Telegram бота
CREATE TABLE IF NOT EXISTS users (
    user_id BIGINT PRIMARY KEY,
    username TEXT,
    has_license BOOLEAN DEFAULT FALSE,
    license_key TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_has_license ON users(has_license);

-- 13. Таблица подписок Telegram бота
CREATE TABLE IF NOT EXISTS subscriptions (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    license_key TEXT NOT NULL,
    subscription_type TEXT NOT NULL CHECK(subscription_type IN ('monthly', 'forever')),
    expires_at TIMESTAMP,
    auto_renew BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_expires_at ON subscriptions(expires_at);

-- 14. Таблица платежей (старая, для совместимости)
CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    amount INTEGER NOT NULL,
    license_type TEXT NOT NULL,
    license_key TEXT,
    payment_id TEXT UNIQUE,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_payment_id ON payments(payment_id);

-- 15. Таблица платежей ЮKassa
CREATE TABLE IF NOT EXISTS yookassa_payments (
    id SERIAL PRIMARY KEY,
    payment_id TEXT UNIQUE NOT NULL,
    user_id BIGINT NOT NULL,
    amount INTEGER NOT NULL,
    license_type TEXT NOT NULL CHECK(license_type IN ('monthly', 'forever')),
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'succeeded', 'canceled', 'failed')),
    license_key TEXT,
    is_renewal BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_yookassa_payments_user_id ON yookassa_payments(user_id);
CREATE INDEX IF NOT EXISTS idx_yookassa_payments_status ON yookassa_payments(status);
CREATE INDEX IF NOT EXISTS idx_yookassa_payments_payment_id ON yookassa_payments(payment_id);

-- Индексы для оптимизации запросов
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_user_id ON request_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);
CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username);

