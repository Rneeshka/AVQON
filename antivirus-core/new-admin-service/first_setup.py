#!/usr/bin/env python3
"""
Скрипт первоначальной настройки админ-сервиса
"""
import os
import sys
from pathlib import Path

# Добавляем путь к основному приложению
sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

def check_database_connection():
    """Проверяет подключение к базе данных"""
    try:
        from app.core.config import settings
        import psycopg2
        
        conn = psycopg2.connect(settings.DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        conn.close()
        print("✅ Подключение к базе данных успешно")
        return True
    except Exception as e:
        print(f"❌ Ошибка подключения к базе данных: {e}")
        return False

def check_tables():
    """Проверяет наличие необходимых таблиц"""
    try:
        from app.core.config import settings
        import psycopg2
        
        conn = psycopg2.connect(settings.DATABASE_URL)
        with conn.cursor() as cur:
            # Проверяем основные таблицы
            tables = [
                "api_keys",
                "malicious_urls",
                "malicious_hashes",
                "request_logs",
                "ip_reputation"
            ]
            
            for table in tables:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = %s
                    )
                """, (table,))
                exists = cur.fetchone()[0]
                if exists:
                    print(f"✅ Таблица {table} существует")
                else:
                    print(f"⚠️  Таблица {table} не найдена (может быть создана позже)")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Ошибка проверки таблиц: {e}")
        return False

def create_admin_user():
    """Создает администратора по умолчанию (если нужно)"""
    from app.core.config import settings
    from app.core.security import hash_password
    
    print(f"\n📝 Информация о пользователе по умолчанию:")
    print(f"   Username: {settings.ADMIN_DEFAULT_USER}")
    print(f"   Password: {settings.ADMIN_DEFAULT_PASSWORD}")
    print(f"   Role: admin")
    print(f"\n⚠️  ВНИМАНИЕ: Измените пароль по умолчанию в production!")

def main():
    """Основная функция настройки"""
    print("=" * 60)
    print("Настройка админ-сервиса")
    print("=" * 60)
    
    # Проверка переменных окружения
    if not os.getenv("DATABASE_URL"):
        print("❌ DATABASE_URL не установлена в переменных окружения")
        print("   Установите её перед запуском:")
        print("   export DATABASE_URL='postgresql://user:***REMOVED***@host:port/database'")
        return False
    
    # Проверка подключения к БД
    if not check_database_connection():
        return False
    
    # Проверка таблиц
    check_tables()
    
    # Информация о пользователе
    create_admin_user()
    
    print("\n" + "=" * 60)
    print("✅ Настройка завершена!")
    print("=" * 60)
    print("\nДля запуска сервиса используйте:")
    print("  uvicorn app.main:app --host 0.0.0.0 --port 8001")
    print("\nИли через Docker:")
    print("  docker-compose up -d")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

