#!/usr/bin/env python3
"""
Простой скрипт конвертации SQLite дампа в PostgreSQL формат
"""
import re
from pathlib import Path

SQLITE_DUMP = Path(__file__).parent.parent / "data" / "aegis_dump.sqlite.sql"
POSTGRES_DUMP = Path(__file__).parent / "restore_data.sql"

def convert():
    print(f"Чтение файла: {SQLITE_DUMP}")
    
    with open(SQLITE_DUMP, 'r', encoding='utf-8') as f:
        content = f.read()
    
    print("Конвертация в PostgreSQL формат...")
    
    # Удаляем SQLite-специфичные команды
    content = re.sub(r'PRAGMA\s+[^;]+;', '', content)
    content = re.sub(r'BEGIN\s+TRANSACTION;', '', content)
    content = re.sub(r'COMMIT;', '', content)
    content = re.sub(r'DELETE\s+FROM\s+sqlite_sequence[^;]*;', '', content)
    content = re.sub(r'INSERT\s+INTO\s+sqlite_sequence[^;]*;', '', content)
    content = re.sub(r'CREATE\s+TABLE\s+sqlite_sequence[^;]+;', '', content)
    
    # Заменяем INTEGER PRIMARY KEY AUTOINCREMENT на SERIAL PRIMARY KEY
    content = re.sub(
        r'(\w+)\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT',
        r'\1 SERIAL PRIMARY KEY',
        content,
        flags=re.IGNORECASE
    )
    
    # Конвертируем INSERT INTO table VALUES в правильный формат для PostgreSQL
    lines = content.split('\n')
    output_lines = []
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('--'):
            continue
        
        # Пропускаем CREATE TABLE (таблицы уже созданы через init.sql)
        if line.upper().startswith('CREATE TABLE'):
            continue
        
        # Обрабатываем INSERT INTO
        if line.upper().startswith('INSERT INTO'):
            # Извлекаем таблицу и значения
            match = re.match(r'INSERT\s+INTO\s+(\w+)\s+VALUES\s*\((.*)\);?', line, re.IGNORECASE)
            if match:
                table = match.group(1)
                values_str = match.group(2)
                
                # Парсим значения
                values = []
                current_val = ""
                in_quotes = False
                quote_char = None
                i = 0
                
                while i < len(values_str):
                    char = values_str[i]
                    if char in ("'", '"') and (i == 0 or values_str[i-1] != '\\'):
                        if not in_quotes:
                            in_quotes = True
                            quote_char = char
                        elif char == quote_char:
                            in_quotes = False
                            quote_char = None
                        current_val += char
                    elif char == ',' and not in_quotes:
                        val = current_val.strip()
                        values.append(val)
                        current_val = ""
                    else:
                        current_val += char
                    i += 1
                
                if current_val:
                    val = current_val.strip()
                    values.append(val)
                
                # Формируем INSERT для PostgreSQL с ON CONFLICT
                if table == 'accounts' and len(values) >= 9:
                    # Конвертируем boolean для is_active (индекс 6)
                    is_active_val = 'TRUE' if values[6] == '1' else 'FALSE' if values[6] == '0' else values[6]
                    output_lines.append(f"""
INSERT INTO accounts (id, username, email, password_hash, created_at, last_login, is_active, reset_code, reset_code_expires)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]}, {values[5]}, {is_active_val}, {values[7]}, {values[8]})
ON CONFLICT (id) DO UPDATE SET
    username = EXCLUDED.username,
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    created_at = EXCLUDED.created_at,
    last_login = EXCLUDED.last_login,
    is_active = EXCLUDED.is_active,
    reset_code = EXCLUDED.reset_code,
    reset_code_expires = EXCLUDED.reset_code_expires;
""")
                elif table == 'api_keys' and len(values) >= 15:
                    # Конвертируем boolean для is_active (индекс 3)
                    is_active_val = 'TRUE' if values[3] == '1' else 'FALSE' if values[3] == '0' else values[3]
                    output_lines.append(f"""
INSERT INTO api_keys (api_key, name, description, is_active, access_level, features, rate_limit_daily, rate_limit_hourly, requests_total, requests_today, requests_hour, created_at, last_used, expires_at, user_id)
VALUES ({values[0]}, {values[1]}, {values[2]}, {is_active_val}, {values[4]}, {values[5]}, {values[6]}, {values[7]}, {values[8]}, {values[9]}, {values[10]}, {values[11]}, {values[12]}, {values[13]}, {values[14]})
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
""")
                elif table == 'malicious_hashes' and len(values) >= 8:
                    output_lines.append(f"""
INSERT INTO malicious_hashes (hash, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]}, {values[5]}, {values[6]}, {values[7]})
ON CONFLICT (hash) DO UPDATE SET
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;
""")
                elif table == 'malicious_urls' and len(values) >= 9:
                    output_lines.append(f"""
INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]}, {values[5]}, {values[6]}, {values[7]}, {values[8]})
ON CONFLICT (url) DO UPDATE SET
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    last_updated = EXCLUDED.last_updated,
    detection_count = EXCLUDED.detection_count;
""")
                elif table == 'cached_whitelist' and len(values) >= 9:
                    output_lines.append(f"""
INSERT INTO cached_whitelist (domain, details, detection_ratio, confidence, source, payload, first_seen, last_seen, hit_count)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]}, {values[5]}, {values[6]}, {values[7]}, {values[8]})
ON CONFLICT (domain) DO UPDATE SET
    details = EXCLUDED.details,
    detection_ratio = EXCLUDED.detection_ratio,
    confidence = EXCLUDED.confidence,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;
""")
                elif table == 'cached_blacklist' and len(values) >= 9:
                    output_lines.append(f"""
INSERT INTO cached_blacklist (url_hash, url, domain, threat_type, details, source, payload, first_seen, last_seen, hit_count)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]}, {values[5]}, {values[6]}, {values[7]}, {values[8]}, {values[9] if len(values) > 9 else '1'})
ON CONFLICT (url_hash) DO UPDATE SET
    url = EXCLUDED.url,
    domain = EXCLUDED.domain,
    threat_type = EXCLUDED.threat_type,
    details = EXCLUDED.details,
    source = EXCLUDED.source,
    payload = EXCLUDED.payload,
    last_seen = EXCLUDED.last_seen,
    hit_count = EXCLUDED.hit_count;
""")
                elif table == 'active_sessions' and len(values) >= 5:
                    output_lines.append(f"""
INSERT INTO active_sessions (user_id, session_token, device_id, created_at, expires_at)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]})
ON CONFLICT (user_id) DO UPDATE SET
    session_token = EXCLUDED.session_token,
    device_id = EXCLUDED.device_id,
    created_at = EXCLUDED.created_at,
    expires_at = EXCLUDED.expires_at;
""")
                elif table == 'users' and len(values) >= 4:
                    # Конвертируем boolean для has_license (индекс 2)
                    has_license_val = 'TRUE' if values[2] == '1' else 'FALSE' if values[2] == '0' else values[2]
                    output_lines.append(f"""
INSERT INTO users (user_id, username, has_license, license_key, created_at)
VALUES ({values[0]}, {values[1]}, {has_license_val}, {values[3]}, {values[4] if len(values) > 4 else 'CURRENT_TIMESTAMP'})
ON CONFLICT (user_id) DO UPDATE SET
    username = EXCLUDED.username,
    has_license = EXCLUDED.has_license,
    license_key = EXCLUDED.license_key;
""")
                elif table == 'subscriptions' and len(values) >= 8:
                    # Конвертируем boolean для auto_renew (индекс 5)
                    auto_renew_val = 'TRUE' if values[5] == '1' else 'FALSE' if values[5] == '0' else values[5]
                    output_lines.append(f"""
INSERT INTO subscriptions (id, user_id, license_key, subscription_type, expires_at, auto_renew, created_at, updated_at, renewal_count, status)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]}, {auto_renew_val}, {values[6]}, {values[7]}, {values[8] if len(values) > 8 else '0'}, {values[9] if len(values) > 9 else "'active'"})
ON CONFLICT (id) DO UPDATE SET
    user_id = EXCLUDED.user_id,
    license_key = EXCLUDED.license_key,
    subscription_type = EXCLUDED.subscription_type,
    expires_at = EXCLUDED.expires_at,
    auto_renew = EXCLUDED.auto_renew,
    updated_at = EXCLUDED.updated_at,
    renewal_count = EXCLUDED.renewal_count,
    status = EXCLUDED.status;
""")
                elif table == 'yookassa_payments' and len(values) >= 8:
                    # Конвертируем boolean для is_renewal (индекс 7)
                    is_renewal_val = 'TRUE' if values[7] == '1' else 'FALSE' if values[7] == '0' else values[7]
                    output_lines.append(f"""
INSERT INTO yookassa_payments (id, payment_id, user_id, amount, license_type, status, license_key, is_renewal, created_at, updated_at)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]}, {values[5]}, {values[6]}, {is_renewal_val}, {values[8] if len(values) > 8 else 'CURRENT_TIMESTAMP'}, {values[9] if len(values) > 9 else 'CURRENT_TIMESTAMP'})
ON CONFLICT (payment_id) DO UPDATE SET
    user_id = EXCLUDED.user_id,
    amount = EXCLUDED.amount,
    license_type = EXCLUDED.license_type,
    status = EXCLUDED.status,
    license_key = EXCLUDED.license_key,
    is_renewal = EXCLUDED.is_renewal,
    updated_at = EXCLUDED.updated_at;
""")
                elif table == 'payments' and len(values) >= 7:
                    output_lines.append(f"""
INSERT INTO payments (id, user_id, amount, license_type, license_key, payment_id, status, created_at, completed_at)
VALUES ({values[0]}, {values[1]}, {values[2]}, {values[3]}, {values[4]}, {values[5]}, {values[6]}, {values[7] if len(values) > 7 else 'CURRENT_TIMESTAMP'}, {values[8] if len(values) > 8 else 'NULL'})
ON CONFLICT (id) DO UPDATE SET
    user_id = EXCLUDED.user_id,
    amount = EXCLUDED.amount,
    license_type = EXCLUDED.license_type,
    license_key = EXCLUDED.license_key,
    payment_id = EXCLUDED.payment_id,
    status = EXCLUDED.status,
    completed_at = EXCLUDED.completed_at;
""")
        
        # Пропускаем CREATE INDEX (индексы уже созданы через init.sql)
        elif line.upper().startswith('CREATE INDEX'):
            continue
    
    # Добавляем сброс последовательностей в конец
    output_lines.append("""
-- Сброс последовательностей
SELECT setval('accounts_id_seq', (SELECT MAX(id) FROM accounts));
SELECT setval('subscriptions_id_seq', (SELECT MAX(id) FROM subscriptions));
SELECT setval('yookassa_payments_id_seq', (SELECT MAX(id) FROM yookassa_payments));
SELECT setval('payments_id_seq', (SELECT MAX(id) FROM payments));
""")
    
    # Записываем результат
    output_content = '\n'.join(output_lines)
    
    with open(POSTGRES_DUMP, 'w', encoding='utf-8') as f:
        f.write("-- Восстановление данных из SQLite дампа в PostgreSQL\n")
        f.write("-- Выполните этот файл в PostgreSQL:\n")
        f.write("-- psql -h 127.0.0.1 -p 5433 -U aegis -d aegis_dev -f restore_data.sql\n\n")
        f.write(output_content)
    
    print(f"[OK] Готово! Файл создан: {POSTGRES_DUMP}")
    print(f"     Строк: {len(output_lines)}")
    print()
    print("Для восстановления выполните:")
    print(f"  psql -h 127.0.0.1 -p 5433 -U aegis -d aegis_dev -f {POSTGRES_DUMP}")
    print()
    print("Или через Docker:")
    print(f"  docker exec -i aegis-postgres-dev psql -U aegis -d aegis_dev < {POSTGRES_DUMP}")

if __name__ == "__main__":
    convert()

