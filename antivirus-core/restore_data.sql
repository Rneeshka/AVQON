-- Восстановление данных из SQLite дампа в PostgreSQL
-- Выполните этот файл в PostgreSQL:
-- psql -h 127.0.0.1 -p 5433 -U aegis -d aegis_dev -f restore_data.sql


INSERT INTO accounts (id, username, email, password_hash, created_at, last_login, is_active, reset_code, reset_code_expires)
VALUES (1, 'kit', 'kit@kit.ru', 'a1fe0cd95606747a50dde1074fc1cc57:2f8fbdccce3ec3fe926e8aa7043dac6851b4dc7b87d614c60c9411ed93e56d66', '2025-12-17 21:36:27', '2025-12-17 21:37:12', TRUE, NULL, NULL)
ON CONFLICT (id) DO UPDATE SET
    username = EXCLUDED.username,
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    created_at = EXCLUDED.created_at,
    last_login = EXCLUDED.last_login,
    is_active = EXCLUDED.is_active,
    reset_code = EXCLUDED.reset_code,
    reset_code_expires = EXCLUDED.reset_code_expires;


INSERT INTO accounts (id, username, email, password_hash, created_at, last_login, is_active, reset_code, reset_code_expires)
VALUES (2, 'kitkit', 'kit@mail.ru', '9f91bd357c28b05d588aafce05717845:091df8e516671fe82cd77ca868ae8ba2a7e7bb71197f2b6890a03d462e68c9ef', '2025-12-17 21:37:06', NULL, TRUE, NULL, NULL)
ON CONFLICT (id) DO UPDATE SET
    username = EXCLUDED.username,
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    created_at = EXCLUDED.created_at,
    last_login = EXCLUDED.last_login,
    is_active = EXCLUDED.is_active,
    reset_code = EXCLUDED.reset_code,
    reset_code_expires = EXCLUDED.reset_code_expires;


INSERT INTO accounts (id, username, email, password_hash, created_at, last_login, is_active, reset_code, reset_code_expires)
VALUES (3, '123', '123@123.ru', '98f2837f6f771471b1746d4240c22508:fa27cda226fc22ffd0ec5c767b15945ddc97b0338c1616b90877616d23dfd314', '2025-12-17 21:40:57', '2025-12-17 22:04:27', TRUE, NULL, NULL)
ON CONFLICT (id) DO UPDATE SET
    username = EXCLUDED.username,
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    created_at = EXCLUDED.created_at,
    last_login = EXCLUDED.last_login,
    is_active = EXCLUDED.is_active,
    reset_code = EXCLUDED.reset_code,
    reset_code_expires = EXCLUDED.reset_code_expires;


INSERT INTO accounts (id, username, email, password_hash, created_at, last_login, is_active, reset_code, reset_code_expires)
VALUES (4, 'Git@рист', 'gitarist1804@mail.ru', '70534c9ccbde489a7eae3167cc535615:5ad428c6c14f9694d587b9b5860949dcdf8e5afe9bd536a71b507cfa8008af22', '2025-12-18 07:39:30', '2025-12-18 07:39:30', TRUE, NULL, NULL)
ON CONFLICT (id) DO UPDATE SET
    username = EXCLUDED.username,
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    created_at = EXCLUDED.created_at,
    last_login = EXCLUDED.last_login,
    is_active = EXCLUDED.is_active,
    reset_code = EXCLUDED.reset_code,
    reset_code_expires = EXCLUDED.reset_code_expires;


INSERT INTO api_keys (api_key, name, description, is_active, access_level, features, rate_limit_daily, rate_limit_hourly, requests_total, requests_today, requests_hour, created_at, last_used, expires_at, user_id)
VALUES ('PREMI-12345-67890-ABCDE-FGHIJ-KLMNO', 'Test Premium Client', 'API key for premium testing with advanced features', TRUE, 'premium', '["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]', 10000, 1000, 0, 0, 0, '2025-12-17 20:19:59', '2025-12-17 20:19:59', NULL, NULL)
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


INSERT INTO api_keys (api_key, name, description, is_active, access_level, features, rate_limit_daily, rate_limit_hourly, requests_total, requests_today, requests_hour, created_at, last_used, expires_at, user_id)
VALUES ('PREMIP-UN65Y-M7UEV-2ZX87', '234', '', TRUE, 'premium', '["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]', 1000, 100, 100, 100, 100, '2025-12-17 21:40:28', '2025-12-18 06:16:47', '2026-01-17T00:40:28.292230', 3)
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


INSERT INTO api_keys (api_key, name, description, is_active, access_level, features, rate_limit_daily, rate_limit_hourly, requests_total, requests_today, requests_hour, created_at, last_used, expires_at, user_id)
VALUES ('PREMI3-NOHMD-7JZ9Y-7D5VW', '123', '', TRUE, 'premium', '["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]', 1000, 1000, 7, 7, 7, '2025-12-17 22:17:13', '2025-12-18 07:40:49', '2026-12-18T01:17:13.343078', 4)
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


INSERT INTO api_keys (api_key, name, description, is_active, access_level, features, rate_limit_daily, rate_limit_hourly, requests_total, requests_today, requests_hour, created_at, last_used, expires_at, user_id)
VALUES ('PREMIU-N9OBF-FONHJ-10QEO', '11', '', TRUE, 'premium', '["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]', 1000, 1000, 0, 0, 0, '2025-12-17 22:18:06', '2025-12-17 22:18:06', '2026-12-18T01:18:06.271509', NULL)
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


INSERT INTO api_keys (api_key, name, description, is_active, access_level, features, rate_limit_daily, rate_limit_hourly, requests_total, requests_today, requests_hour, created_at, last_used, expires_at, user_id)
VALUES ('PREMIG-K99SO-25IPP-J7KFU', 'ert', '', TRUE, 'premium', '["url_check", "file_check", "domain_check", "ip_check", "advanced_analysis", "hover_analysis"]', 1000, 100, 0, 0, 0, '2025-12-18 17:52:25', '2025-12-18 17:52:25', '2026-01-17T20:52:25.636028', NULL)
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


INSERT INTO malicious_hashes (hash, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'trojan', 'high', 'Test Trojan horse', 'manual', '2025-12-17 20:19:59', '2025-12-17 20:19:59', 1)
ON CONFLICT (hash) DO UPDATE SET
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_hashes (hash, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890', 'ransomware', 'critical', 'Test Ransomware variant', 'manual', '2025-12-17 20:19:59', '2025-12-17 20:19:59', 1)
ON CONFLICT (hash) DO UPDATE SET
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://evil-site.com/download/malware.exe', 'evil-site.com', 'malware', 'high', 'Malware distribution site', 'manual', '2025-12-17 20:19:59', '2025-12-17 21:43:34', 2)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://phishing-bank.com/login', 'phishing-bank.com', 'phishing', 'medium', 'Fake bank login page', 'manual', '2025-12-17 20:19:59', '2025-12-17 21:43:35', 2)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://zonafilm.click/poslednie-filmy-hd//', 'zonafilm.click', 'malware', 'medium', 'Обнаружено вредоносное ПО (1 антивирусов)', 'manual', '2025-12-17 20:31:57', '2025-12-17 21:43:31', 2)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://w6.filmworld01.buzz/films-2025/', 'w6.filmworld01.buzz', 'malware', 'medium', 'Обнаружено вредоносное ПО (2 антивирусов)', 'manual', '2025-12-17 20:32:07', '2025-12-17 21:43:32', 2)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://evilgames.eu/flashgames.htm', 'evilgames.eu', 'malware', 'medium', 'Обнаружено вредоносное ПО (1 антивирусов)', 'manual', '2025-12-17 20:59:28', '2025-12-17 21:43:31', 3)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://store.steampowered.com/app/578080/pubg_battlegrounds/', 'store.steampowered.com', 'malware', 'medium', 'Обнаружено вредоносное ПО (1 антивирусов)', 'manual', '2025-12-18 01:02:28', '2025-12-18 01:02:28', 1)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://web.telegram.org/k/', 'web.telegram.org', 'malware', 'medium', 'Обнаружено вредоносное ПО (1 антивирусов)', 'manual', '2025-12-18 01:17:11', '2025-12-18 18:00:26', 24)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://vk.ru/im', 'vk.ru', 'malware', 'medium', 'Обнаружено вредоносное ПО (1 антивирусов)', 'manual', '2025-12-18 14:16:15', '2025-12-18 14:16:15', 1)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://huggingface.co/spaces', 'huggingface.co', 'malware', 'medium', 'Обнаружено вредоносное ПО (1 антивирусов)', 'manual', '2025-12-18 14:43:34', '2025-12-18 14:43:34', 1)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://vms.drweb.ru/scan_file/', 'vms.drweb.ru', 'malware', 'medium', 'Обнаружено вредоносное ПО (2 антивирусов)', 'manual', '2025-12-18 16:01:57', '2025-12-18 16:01:57', 1)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ('https://steamcommunity.com/sharedfiles/filedetails/?id=3412688383', 'steamcommunity.com', 'malware', 'medium', 'Обнаружено вредоносное ПО (3 антивирусов)', 'manual', '2025-12-18 17:46:38', '2025-12-18 17:46:38', 1)
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('rotoro.cloud', 'URL appears safe (heuristic only, external APIs unavailable): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unavailable): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-17 20:32:31', '2025-12-17 21:43:27', 12)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('aegis.builders', 'Private/internal URL - not sent to external security services', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "Private/internal URL - not sent to external security services", "request_id": null}', '2025-12-17 21:34:13', '2025-12-18 17:34:56', 80)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('github.com', 'Trusted domain: github.com', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "Trusted domain: github.com", "request_id": null}', '2025-12-17 21:37:58', '2025-12-18 16:14:57', 31)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('direct.yandex.ru', 'URL appears to be safe (partial external verification)', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears to be safe (partial external verification)", "request_id": null}', '2025-12-17 21:50:17', '2025-12-17 21:53:10', 10)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('yabs.yandex.ru', 'URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-17 21:58:59', '2025-12-18 16:02:30', 7)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('www.firefox.com', 'URL appears to be safe (partial external verification)', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears to be safe (partial external verification)", "request_id": null}', '2025-12-17 21:59:05', '2025-12-17 21:59:05', 1)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('www.mozilla.org', 'Trusted domain: www.mozilla.org', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "Trusted domain: www.mozilla.org", "request_id": null}', '2025-12-17 21:59:07', '2025-12-17 21:59:07', 1)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('ru.wikipedia.org', 'Trusted domain: ru.wikipedia.org', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "Trusted domain: ru.wikipedia.org", "request_id": null}', '2025-12-17 21:59:09', '2025-12-17 21:59:09', 1)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('apps.microsoft.com', 'Trusted domain: apps.microsoft.com', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "Trusted domain: apps.microsoft.com", "request_id": null}', '2025-12-17 21:59:10', '2025-12-18 16:01:28', 3)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('mozilla-russia.org', 'URL appears to be safe (partial external verification)', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears to be safe (partial external verification)", "request_id": null}', '2025-12-17 21:59:12', '2025-12-17 21:59:12', 1)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('mozilla.khelsoft.com', 'URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-17 22:02:48', '2025-12-17 22:02:52', 4)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('ofont.ru', 'URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-17 22:13:13', '2025-12-17 22:16:28', 86)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('vk.com', 'URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-17 22:17:27', '2025-12-18 16:42:11', 56)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('yookassa.ru', 'URL appears to be safe (partial external verification)', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears to be safe (partial external verification)", "request_id": null}', '2025-12-17 23:10:17', '2025-12-17 23:12:36', 29)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('aqsi.ru', 'URL appears safe (heuristic only, external APIs unavailable): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unavailable): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-17 23:13:26', '2025-12-17 23:13:26', 1)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('vkvideo.ru', 'URL appears safe (heuristic only, external APIs unavailable): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unavailable): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-18 07:39:56', '2025-12-18 07:40:42', 6)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('rutube.ru', 'URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-18 08:52:00', '2025-12-18 09:32:04', 2)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('lk.mts.ru', 'URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-18 09:59:59', '2025-12-18 10:00:51', 6)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('chromewebstore.google.com', 'Trusted domain: chromewebstore.google.com', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "Trusted domain: chromewebstore.google.com", "request_id": null}', '2025-12-18 14:07:51', '2025-12-18 14:08:36', 6)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('www.google.com', 'Trusted domain: www.google.com', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "Trusted domain: www.google.com", "request_id": null}', '2025-12-18 15:10:19', '2025-12-18 16:43:48', 8)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('www.virustotal.com', 'URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "URL appears safe (heuristic only, external APIs unclear): Heuristic analysis passed, but external API verification required", "request_id": null}', '2025-12-18 16:21:28', '2025-12-18 16:21:28', 1)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ('api.aegis.builders', 'Private/internal URL - not sent to external security services', NULL, NULL, 'external_apis', '{"status": "success", "safe": true, "threat_type": null, "details": "Private/internal URL - not sent to external security services", "request_id": null}', '2025-12-18 17:52:14', '2025-12-18 17:52:16', 3)
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_blacklist (url_hash, url, domain, threat_type, details, source, payload, first_seen, last_seen, hit_count)
VALUES ('9ee7e6676aa6dce89477dc5c324b124472553eeb7976277111a37366cb70dfb8', 'https://zonafilm.click/poslednie-filmy-hd//', 'zonafilm.click', 'malware', 'Local database: Обнаружено вредоносное ПО (1 антивирусов)', 'external_apis', '{"status": "success", "safe": false, "threat_type": "malware", "details": "Local database: Обнаружено вредоносное ПО (1 антивирусов)", "request_id": null}', '2025-12-17 21:43:31', '2025-12-18 06:13:14', 2)
ON CONFLICT (url_hash) DO UPDATE SET
    url = EXCLUDED.url,
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    details = EXCLUDED.details,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_blacklist (url_hash, url, domain, threat_type, details, source, payload, first_seen, last_seen, hit_count)
VALUES ('eaefe9aad2d055af8b80645d4ada8f54beb1ee3e1afb78bfdcc415f01dc4dc6c', 'https://evilgames.eu/flashgames.htm', 'evilgames.eu', 'malware', 'Local database: Обнаружено вредоносное ПО (1 антивирусов)', 'external_apis', '{"status": "success", "safe": false, "threat_type": "malware", "details": "Local database: Обнаружено вредоносное ПО (1 антивирусов)", "request_id": null}', '2025-12-17 21:43:31', '2025-12-18 16:23:42', 11)
ON CONFLICT (url_hash) DO UPDATE SET
    url = EXCLUDED.url,
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    details = EXCLUDED.details,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_blacklist (url_hash, url, domain, threat_type, details, source, payload, first_seen, last_seen, hit_count)
VALUES ('6431dc1be4fc0e5050a278f7fee6c856bb2201a66d02122eb5813e66bbb7dfaf', 'https://w6.filmworld01.buzz/films-2025/', 'w6.filmworld01.buzz', 'malware', 'Local database: Обнаружено вредоносное ПО (2 антивирусов)', 'external_apis', '{"status": "success", "safe": false, "threat_type": "malware", "details": "Local database: Обнаружено вредоносное ПО (2 антивирусов)", "request_id": null}', '2025-12-17 21:43:32', '2025-12-17 21:43:32', 1)
ON CONFLICT (url_hash) DO UPDATE SET
    url = EXCLUDED.url,
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    details = EXCLUDED.details,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_blacklist (url_hash, url, domain, threat_type, details, source, payload, first_seen, last_seen, hit_count)
VALUES ('15802a48b8be460ac2cecabfeed135900c5914d8baf18733db51d9e677098fe3', 'https://evil-site.com/download/malware.exe', 'evil-site.com', 'malware', 'Local database: Malware distribution site', 'external_apis', '{"status": "success", "safe": false, "threat_type": "malware", "details": "Local database: Malware distribution site", "request_id": null}', '2025-12-17 21:43:34', '2025-12-17 21:43:34', 1)
ON CONFLICT (url_hash) DO UPDATE SET
    url = EXCLUDED.url,
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    details = EXCLUDED.details,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO cached_blacklist (url_hash, url, domain, threat_type, details, source, payload, first_seen, last_seen, hit_count)
VALUES ('6f5ea4c21add08595919fd7d5930209463676f2fb8569b852351a6727d468c4d', 'https://phishing-bank.com/login', 'phishing-bank.com', 'phishing', 'Local database: Fake bank login page', 'external_apis', '{"status": "success", "safe": false, "threat_type": "phishing", "details": "Local database: Fake bank login page", "request_id": null}', '2025-12-17 21:43:35', '2025-12-17 21:43:35', 1)
ON CONFLICT (url_hash) DO UPDATE SET
    url = EXCLUDED.url,
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    details = EXCLUDED.details,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;


INSERT INTO active_sessions (user_id, session_token, device_id, created_at, expires_at)
VALUES (1, 'JelqoeUcpD1amGUNq9QyLlPbllRWkGDXwQU9vLAoB8o', 'device_1765993280949_8yb9xsrtj', '2025-12-17 21:37:12', '2026-01-17T00:37:12.023058')
ON CONFLICT (user_id) DO UPDATE SET
    session_token = EXCLUDED.session_token,
    device_id = EXCLUDED.device_id,
    created_at = EXCLUDED.created_at,
    expires_at = EXCLUDED.expires_at;


INSERT INTO active_sessions (user_id, session_token, device_id, created_at, expires_at)
VALUES (3, '2nYE1OwjSwJVqhd36hQOqOiMa_4dxZh5S5L6hXaYwX8', 'device_1765370329257_0zy3sydrx', '2025-12-17 22:04:27', '2026-01-17T01:04:27.984074')
ON CONFLICT (user_id) DO UPDATE SET
    session_token = EXCLUDED.session_token,
    device_id = EXCLUDED.device_id,
    created_at = EXCLUDED.created_at,
    expires_at = EXCLUDED.expires_at;


INSERT INTO active_sessions (user_id, session_token, device_id, created_at, expires_at)
VALUES (4, '9D9YUBFyZ2j0NHvqZpkGEeb7LIhV_0C_1aXAKca0uv4', 'cc224565e970cf28606cb6d5d397ac86', '2025-12-18 07:39:30', '2026-01-17T10:39:30.699204')
ON CONFLICT (user_id) DO UPDATE SET
    session_token = EXCLUDED.session_token,
    device_id = EXCLUDED.device_id,
    created_at = EXCLUDED.created_at,
    expires_at = EXCLUDED.expires_at;


-- Сброс последовательностей
SELECT setval('accounts_id_seq', (SELECT MAX(id) FROM accounts));
SELECT setval('subscriptions_id_seq', (SELECT MAX(id) FROM subscriptions));
SELECT setval('yookassa_payments_id_seq', (SELECT MAX(id) FROM yookassa_payments));
SELECT setval('payments_id_seq', (SELECT MAX(id) FROM payments));
