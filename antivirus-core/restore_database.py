#!/usr/bin/env python3
"""
Скрипт восстановления базы данных из SQLite дампа в PostgreSQL
"""
import os
import sys
import re
import psycopg2
from pathlib import Path

# Конфигурация
DB_USER = "aegis"
DB_PASSWORD = "DEV_PASSWORD"  # Пароль из DATABASE_URL в логах
DB_NAME = "aegis_dev"
DB_HOST = "127.0.0.1"
DB_PORT = 5433

SQLITE_DUMP_FILE = Path(__file__).parent.parent / "data" / "aegis_dump.sqlite.sql"

def convert_sqlite_to_postgresql(sqlite_sql: str) -> str:
    """Конвертирует SQLite SQL в PostgreSQL SQL"""
    
    # Удаляем SQLite-специфичные команды
    sqlite_sql = re.sub(r'PRAGMA\s+[^;]+;', '', sqlite_sql)
    sqlite_sql = re.sub(r'BEGIN\s+TRANSACTION;', '', sqlite_sql)
    sqlite_sql = re.sub(r'COMMIT;', '', sqlite_sql)
    sqlite_sql = re.sub(r'DELETE\s+FROM\s+sqlite_sequence;', '', sqlite_sql)
    sqlite_sql = re.sub(r'CREATE\s+TABLE\s+sqlite_sequence[^;]+;', '', sqlite_sql)
    
    # Заменяем INTEGER PRIMARY KEY AUTOINCREMENT на SERIAL PRIMARY KEY
    sqlite_sql = re.sub(
        r'id\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT',
        'id SERIAL PRIMARY KEY',
        sqlite_sql,
        flags=re.IGNORECASE
    )
    
    # Заменяем BOOLEAN значения 1/0 на TRUE/FALSE
    def replace_boolean(match):
        value = match.group(0)
        if value == '1':
            return 'TRUE'
        elif value == '0':
            return 'FALSE'
        return value
    
    # Заменяем в INSERT VALUES
    sqlite_sql = re.sub(r'\b1\b(?=\s*[,)])', 'TRUE', sqlite_sql)
    sqlite_sql = re.sub(r'\b0\b(?=\s*[,)])', 'FALSE', sqlite_sql)
    
    # Но нужно быть осторожным - не заменять числа в других контекстах
    # Восстанавливаем числа в числовых полях
    sqlite_sql = re.sub(r'TRUE(?=\s*,\s*\d)', '1', sqlite_sql)  # Восстанавливаем числа после TRUE
    sqlite_sql = re.sub(r'FALSE(?=\s*,\s*\d)', '0', sqlite_sql)  # Восстанавливаем числа после FALSE
    
    # Исправляем INSERT INTO table VALUES на INSERT INTO table (columns) VALUES
    # Это сложно сделать автоматически, поэтому оставляем как есть и будем обрабатывать вручную
    
    return sqlite_sql

def parse_insert_statement(line: str) -> tuple:
    """Парсит INSERT INTO statement и возвращает таблицу и значения"""
    match = re.match(r'INSERT\s+INTO\s+(\w+)\s+VALUES\s*\((.*)\);?', line, re.IGNORECASE)
    if match:
        table = match.group(1)
        values_str = match.group(2)
        return table, values_str
    return None, None

def convert_values_to_postgresql(values_str: str, table: str) -> str:
    """Конвертирует значения из SQLite формата в PostgreSQL"""
    # Разбиваем значения по запятым, учитывая строки в кавычках
    values = []
    current_value = ""
    in_quotes = False
    quote_char = None
    
    for char in values_str:
        if char in ("'", '"') and (not current_value or current_value[-1] != '\\'):
            if not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char:
                in_quotes = False
                quote_char = None
            current_value += char
        elif char == ',' and not in_quotes:
            values.append(current_value.strip())
            current_value = ""
        else:
            current_value += char
    
    if current_value:
        values.append(current_value.strip())
    
    # Конвертируем значения
    converted_values = []
    for val in values:
        val = val.strip()
        if val.upper() == 'NULL':
            converted_values.append('NULL')
        elif val == '1' and table in ('accounts', 'api_keys'):
            # Проверяем контекст - если это boolean поле
            converted_values.append('TRUE')
        elif val == '0' and table in ('accounts', 'api_keys'):
            converted_values.append('FALSE')
        else:
            converted_values.append(val)
    
    return ', '.join(converted_values)

def restore_database():
    """Восстанавливает базу данных из SQLite дампа"""
    
    print("=== Восстановление базы данных из SQLite дампа ===")
    print()
    
    # 1. Проверяем наличие файла дампа
    if not SQLITE_DUMP_FILE.exists():
        print(f"❌ Файл дампа не найден: {SQLITE_DUMP_FILE}")
        return False
    
    print(f"✅ Файл дампа найден: {SQLITE_DUMP_FILE}")
    print(f"   Размер: {SQLITE_DUMP_FILE.stat().st_size / 1024 / 1024:.2f} MB")
    print()
    
    # 2. Подключаемся к PostgreSQL
    print("2. Подключение к PostgreSQL...")
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database="postgres",  # Подключаемся к postgres для создания БД
            user="postgres",
            password=os.getenv("POSTGRES_PASSWORD", "postgres")
        )
        conn.autocommit = True
        cursor = conn.cursor()
        print("   ✅ Подключение установлено")
    except Exception as e:
        print(f"   ❌ Ошибка подключения: {e}")
        print("   Попробуйте подключиться от пользователя postgres")
        return False
    
    # 3. Создаем пользователя и базу данных если не существует
    print()
    print("3. Создание пользователя и базы данных...")
    try:
        # Проверяем существует ли пользователь
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (DB_USER,))
        if not cursor.fetchone():
            cursor.execute(f"CREATE USER {DB_USER} WITH PASSWORD %s", (DB_PASSWORD,))
            print(f"   ✅ Пользователь '{DB_USER}' создан")
        else:
            # Обновляем пароль
            cursor.execute(f"ALTER USER {DB_USER} WITH PASSWORD %s", (DB_PASSWORD,))
            print(f"   ✅ Пароль пользователя '{DB_USER}' обновлен")
        
        # Проверяем существует ли база данных
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
        if not cursor.fetchone():
            cursor.execute(f"CREATE DATABASE {DB_NAME} OWNER {DB_USER}")
            print(f"   ✅ База данных '{DB_NAME}' создана")
        else:
            print(f"   ✅ База данных '{DB_NAME}' уже существует")
        
        # Выдаем права
        cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {DB_NAME} TO {DB_USER}")
        print(f"   ✅ Права выданы")
    except Exception as e:
        print(f"   ❌ Ошибка создания пользователя/БД: {e}")
        conn.close()
        return False
    
    # 4. Подключаемся к целевой базе данных
    conn.close()
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        conn.autocommit = True
        cursor = conn.cursor()
        print()
        print("4. Подключение к базе данных aegis_dev...")
        print("   ✅ Подключено")
    except Exception as e:
        print(f"   ❌ Ошибка подключения к БД: {e}")
        return False
    
    # 5. Читаем и обрабатываем дамп
    print()
    print("5. Обработка дампа SQLite...")
    
    with open(SQLITE_DUMP_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Разбиваем на строки
    lines = content.split('\n')
    
    # Обрабатываем INSERT INTO statements
    print("   Обработка INSERT INTO statements...")
    
    current_table = None
    insert_buffer = []
    insert_count = 0
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('--'):
            continue
        
        # CREATE TABLE - пропускаем (таблицы уже созданы через init.sql)
        if line.upper().startswith('CREATE TABLE'):
            continue
        
        # INSERT INTO - обрабатываем
        if line.upper().startswith('INSERT INTO'):
            match = re.match(r'INSERT\s+INTO\s+(\w+)\s+VALUES\s*\((.*)\);?', line, re.IGNORECASE)
            if match:
                table = match.group(1)
                values_str = match.group(2)
                
                # Конвертируем значения
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
                        # Конвертируем boolean
                        if val == '1' and table in ('accounts', 'api_keys'):
                            val = 'TRUE'
                        elif val == '0' and table in ('accounts', 'api_keys'):
                            val = 'FALSE'
                        values.append(val)
                        current_val = ""
                    else:
                        current_val += char
                    i += 1
                
                if current_val:
                    val = current_val.strip()
                    if val == '1' and table in ('accounts', 'api_keys'):
                        val = 'TRUE'
                    elif val == '0' and table in ('accounts', 'api_keys'):
                        val = 'FALSE'
                    values.append(val)
                
                # Формируем INSERT для PostgreSQL
                try:
                    if table == 'accounts':
                        query = """
                            INSERT INTO accounts (id, username, email, password_hash, created_at, last_login, is_active, reset_code, reset_code_expires)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                                username = EXCLUDED.username,
                                email = EXCLUDED.email,
                                password_hash = EXCLUDED.password_hash,
                                created_at = EXCLUDED.created_at,
                                last_login = EXCLUDED.last_login,
                                is_active = EXCLUDED.is_active,
                                reset_code = EXCLUDED.reset_code,
                                reset_code_expires = EXCLUDED.reset_code_expires
                        """
                        cursor.execute(query, values[:9])
                    elif table == 'api_keys':
                        query = """
                            INSERT INTO api_keys (api_key, name, description, is_active, access_level, features, rate_limit_daily, rate_limit_hourly, requests_total, requests_today, requests_hour, created_at, last_used, expires_at, user_id)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                                user_id = EXCLUDED.user_id
                        """
                        cursor.execute(query, values[:15])
                    elif table == 'malicious_hashes':
                        query = """
                            INSERT INTO malicious_hashes (hash, threat_type, severity, description, source, first_detected, last_updated, detection_count)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (hash) DO UPDATE SET
                                threat_type = EXCLUDED.threat_type,
                                severity = EXCLUDED.severity,
                                description = EXCLUDED.description,
                                source = EXCLUDED.source,
                                last_updated = EXCLUDED.last_updated,
                                detection_count = EXCLUDED.detection_count
                        """
                        cursor.execute(query, values[:8])
                    elif table == 'malicious_urls':
                        query = """
                            INSERT INTO malicious_urls (url, domain, threat_type, severity, description, source, first_detected, last_updated, detection_count)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (url) DO UPDATE SET
                                domain = EXCLUDED.domain,
                                threat_type = EXCLUDED.threat_type,
                                severity = EXCLUDED.severity,
                                description = EXCLUDED.description,
                                source = EXCLUDED.source,
                                last_updated = EXCLUDED.last_updated,
                                detection_count = EXCLUDED.detection_count
                        """
                        cursor.execute(query, values[:9])
                    elif table == 'request_logs':
                        # Пропускаем старые логи или конвертируем
                        # request_logs теперь использует user_id вместо api_key_hash
                        continue
                    
                    insert_count += 1
                    if insert_count % 100 == 0:
                        print(f"   Обработано {insert_count} записей...")
                        
                except Exception as e:
                    print(f"   ⚠️ Ошибка при вставке в {table}: {e}")
                    print(f"   Значения: {values[:5]}...")
                    continue
    
    print(f"   ✅ Обработано {insert_count} записей")
    
    # 6. Сбрасываем последовательности
    print()
    print("6. Сброс последовательностей...")
    try:
        cursor.execute("SELECT setval('accounts_id_seq', (SELECT MAX(id) FROM accounts));")
        print("   ✅ Последовательности обновлены")
    except Exception as e:
        print(f"   ⚠️ Ошибка обновления последовательностей: {e}")
    
    # 7. Проверяем восстановление
    print()
    print("7. Проверка восстановления...")
    try:
        cursor.execute("SELECT COUNT(*) FROM accounts")
        accounts_count = cursor.fetchone()[0]
        print(f"   ✅ Аккаунтов восстановлено: {accounts_count}")
        
        cursor.execute("SELECT COUNT(*) FROM api_keys")
        api_keys_count = cursor.fetchone()[0]
        print(f"   ✅ API ключей восстановлено: {api_keys_count}")
        
        cursor.execute("SELECT COUNT(*) FROM malicious_hashes")
        hashes_count = cursor.fetchone()[0]
        print(f"   ✅ Хэшей восстановлено: {hashes_count}")
        
        cursor.execute("SELECT COUNT(*) FROM malicious_urls")
        urls_count = cursor.fetchone()[0]
        print(f"   ✅ URL восстановлено: {urls_count}")
    except Exception as e:
        print(f"   ⚠️ Ошибка проверки: {e}")
    
    conn.close()
    
    print()
    print("=== Восстановление завершено! ===")
    print()
    print("Проверьте подключение:")
    print(f"  psql -h {DB_HOST} -p {DB_PORT} -U {DB_USER} -d {DB_NAME}")
    print()
    print("Перезапустите сервис:")
    print("  sudo systemctl restart aegis-backend-dev.service")
    
    return True

if __name__ == "__main__":
    success = restore_database()
    sys.exit(0 if success else 1)

