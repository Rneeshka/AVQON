-- Скрипт восстановления базы данных из SQLite дампа в PostgreSQL
-- Адаптировано для PostgreSQL

-- Очистка существующих данных (опционально)
-- TRUNCATE TABLE accounts CASCADE;
-- TRUNCATE TABLE api_keys CASCADE;

-- Восстановление таблицы accounts
-- SQLite: INTEGER PRIMARY KEY AUTOINCREMENT -> PostgreSQL: SERIAL PRIMARY KEY
-- SQLite: BOOLEAN (1/0) -> PostgreSQL: BOOLEAN (TRUE/FALSE)

-- Вставка данных в accounts (адаптировано для PostgreSQL)
INSERT INTO accounts (id, username, email, password_hash, created_at, last_login, is_active, reset_code, reset_code_expires)
VALUES
(1,'kit','kit@kit.ru','a1fe0cd95606747a50dde1074fc1cc57:2f8fbdccce3ec3fe926e8aa7043dac6851b4dc7b87d614c60c9411ed93e56d66','2025-12-17 21:36:27','2025-12-17 21:37:12',TRUE,NULL,NULL),
(2,'kitkit','kit@mail.ru','9f91bd357c28b05d588aafce05717845:091df8e516671fe82cd77ca868ae8ba2a7e7bb71197f2b6890a03d462e68c9ef','2025-12-17 21:37:06',NULL,TRUE,NULL,NULL),
(3,'123','123@123.ru','98f2837f6f771471b1746d4240c22508:fa27cda226fc22ffd0ec5c767b15945ddc97b0338c1616b90877616d23dfd314','2025-12-17 21:40:57','2025-12-17 22:04:27',TRUE,NULL,NULL),
(4,'Git@рист','gitarist1804@mail.ru','70534c9ccbde489a7eae3167cc535615:5ad428c6c14f9694d587b9b5860949dcdf8e5afe9bd536a71b507cfa8008af22','2025-12-18 07:39:30','2025-12-18 07:39:30',TRUE,NULL,NULL)
ON CONFLICT (id) DO UPDATE SET
    username = EXCLUDED.username,
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    created_at = EXCLUDED.created_at,
    last_login = EXCLUDED.last_login,
    is_active = EXCLUDED.is_active,
    reset_code = EXCLUDED.reset_code,
    reset_code_expires = EXCLUDED.reset_code_expires;

-- Восстановление таблицы api_keys
INSERT INTO api_keys (api_key, name, description, is_active, access_level, features, rate_limit_daily, rate_limit_hourly, requests_total, requests_today, requests_hour, created_at, last_used, expires_at, user_id)
VALUES
('PREMI-12345-67890-ABCDE-FGHIJ-KLMNO','Test Premium Client','API key for premium testing with advanced features',TRUE,'premium','["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]',10000,1000,0,0,0,'2025-12-17 20:19:59','2025-12-17 20:19:59',NULL,NULL),
('PREMIP-UN65Y-M7UEV-2ZX87','234','',TRUE,'premium','["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]',1000,100,100,100,100,'2025-12-17 21:40:28','2025-12-18 06:16:47','2026-01-17T00:40:28.292230',3),
('PREMI3-NOHMD-7JZ9Y-7D5VW','123','',TRUE,'premium','["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]',1000,1000,7,7,7,'2025-12-17 22:17:13','2025-12-18 07:40:49','2026-12-18T01:17:13.343078',4),
('PREMIU-N9OBF-FONHJ-10QEO','11','',TRUE,'premium','["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]',1000,1000,0,0,0,'2025-12-17 22:18:06','2025-12-17 22:18:06','2026-12-18T01:18:06.271509',NULL),
('PREMIG-K99SO-25IPP-J7KFU','ert','',TRUE,'premium','["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]',1000,100,0,0,0,'2025-12-18 17:52:25','2025-12-18 17:52:25','2026-01-17T20:52:25.636028',NULL)
ON CONFLICT (api_key) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    is_active = EXCLUDED.is_active,
    access_level = EXCLUDED.access_level,
    features = EXCLUDED.features,
    rate_limit_daily = EXCLUDED.rate_limit_daily,
    rate_limit_hourly = EXCLUDED.rate_limit_hourly,
    requests_total = EXCLUDED.requests_total,
    requests_today = EXCLUDED.requests_today,
    requests_hour = EXCLUDED.requests_hour,
    created_at = EXCLUDED.created_at,
    last_used = EXCLUDED.last_used,
    expires_at = EXCLUDED.expires_at,
    user_id = EXCLUDED.user_id;

-- Сброс последовательности для accounts (чтобы следующий ID был правильным)
SELECT setval('accounts_id_seq', (SELECT MAX(id) FROM accounts));

