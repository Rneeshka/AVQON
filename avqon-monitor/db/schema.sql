-- AVQON Monitor MVP 0.1 — схема БД (PostgreSQL)
-- Экосистема AVQON

-- Пользователи бота (владельцы каналов)
CREATE TABLE IF NOT EXISTS users (
    user_id BIGINT PRIMARY KEY,
    username TEXT,
    first_name TEXT,
    subscription_status TEXT DEFAULT 'trial',
    tariff TEXT DEFAULT 'free',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Каналы: защищаемые (клиенты) и мониторируемые (целевые)
CREATE TABLE IF NOT EXISTS channels (
    channel_id BIGINT PRIMARY KEY,
    channel_username TEXT,
    channel_title TEXT,
    user_id BIGINT NOT NULL REFERENCES users(user_id),
    is_protected SMALLINT DEFAULT 1,
    is_active SMALLINT DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_channels_user_id ON channels(user_id);
CREATE INDEX IF NOT EXISTS idx_channels_is_active ON channels(is_active);

-- Сырые посты (собраны Data Fetcher)
CREATE TABLE IF NOT EXISTS raw_posts (
    post_id SERIAL PRIMARY KEY,
    channel_id BIGINT NOT NULL REFERENCES channels(channel_id),
    telegram_message_id INTEGER NOT NULL,
    text TEXT,
    media_urls JSONB,
    media_type TEXT,
    date TIMESTAMPTZ NOT NULL,
    fetched_at TIMESTAMPTZ DEFAULT NOW(),
    processed SMALLINT DEFAULT 0,
    UNIQUE(channel_id, telegram_message_id)
);

CREATE INDEX IF NOT EXISTS idx_raw_posts_channel_date ON raw_posts(channel_id, date);
CREATE INDEX IF NOT EXISTS idx_raw_posts_processed ON raw_posts(processed);

-- Хеши контента для сравнения
CREATE TABLE IF NOT EXISTS content_hashes (
    hash_id SERIAL PRIMARY KEY,
    post_id INTEGER NOT NULL REFERENCES raw_posts(post_id),
    media_hash TEXT,
    text_hash TEXT,
    text_normalized TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_content_hashes_post ON content_hashes(post_id);
CREATE INDEX IF NOT EXISTS idx_content_hashes_media ON content_hashes(media_hash);
CREATE INDEX IF NOT EXISTS idx_content_hashes_text ON content_hashes(text_hash);

-- Найденные совпадения (нарушения)
CREATE TABLE IF NOT EXISTS matches (
    match_id SERIAL PRIMARY KEY,
    original_post_id INTEGER NOT NULL REFERENCES raw_posts(post_id),
    copied_post_id INTEGER NOT NULL REFERENCES raw_posts(post_id),
    match_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    notified SMALLINT DEFAULT 0,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_matches_original ON matches(original_post_id);
CREATE INDEX IF NOT EXISTS idx_matches_notified ON matches(notified);
