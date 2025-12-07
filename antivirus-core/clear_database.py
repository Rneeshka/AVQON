#!/usr/bin/env python3
"""
Скрипт для очистки базы данных URL
Использование:
    python clear_database.py --all          # Очистить все URL данные
    python clear_database.py --urls         # Очистить только malicious_urls
    python clear_database.py --hashes       # Очистить только malicious_hashes
    python clear_database.py --whitelist    # Очистить whitelist кэш
    python clear_database.py --blacklist    # Очистить blacklist кэш
    python clear_database.py --cache        # Очистить весь кэш (whitelist + blacklist)
"""
import sys
import os
import argparse

# Добавляем путь к приложению
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import db_manager

def main():
    parser = argparse.ArgumentParser(description='Очистка базы данных URL')
    parser.add_argument('--all', action='store_true', help='Очистить все URL данные (malicious_urls + кэш)')
    parser.add_argument('--urls', action='store_true', help='Очистить только malicious_urls')
    parser.add_argument('--hashes', action='store_true', help='Очистить только malicious_hashes')
    parser.add_argument('--whitelist', action='store_true', help='Очистить whitelist кэш')
    parser.add_argument('--blacklist', action='store_true', help='Очистить blacklist кэш')
    parser.add_argument('--cache', action='store_true', help='Очистить весь кэш (whitelist + blacklist)')
    parser.add_argument('--url', type=str, help='Удалить конкретный URL из базы данных')
    parser.add_argument('--full', action='store_true', help='ПОЛНАЯ очистка всех данных (кроме API ключей и аккаунтов)')
    parser.add_argument('--password', type=str, help='Пароль для полной очистки (обязательно с --full)')
    parser.add_argument('--confirm', action='store_true', help='Подтвердить очистку (обязательно для безопасности)')
    
    args = parser.parse_args()
    
    if not any([args.all, args.urls, args.hashes, args.whitelist, args.blacklist, args.cache, args.url, args.full]):
        parser.print_help()
        return
    
    # Для полной очистки требуется пароль
    ADMIN_PASSWORD = "90~kz=Ut!I123nikita12364"
    if args.full:
        if not args.password:
            print("❌ ОШИБКА: Для полной очистки требуется пароль!")
            print("Использование: python clear_database.py --full --password 'ПАРОЛЬ'")
            return
        if args.password != ADMIN_PASSWORD:
            print("❌ ОШИБКА: Неверный пароль!")
            return
        print("⚠️  ВНИМАНИЕ: Вы собираетесь ПОЛНОСТЬЮ очистить базу данных!")
        print("Это удалит ВСЕ данные (угрозы, кэш, IP репутацию, логи)")
        print("Сохранятся только: API ключи и аккаунты пользователей")
        if not args.confirm:
            print("Для подтверждения добавьте --confirm")
            return
    
    # Для удаления конкретного URL не требуется --confirm (это более безопасная операция)
    if not args.url and not args.full and not args.confirm:
        print("⚠️  ВНИМАНИЕ: Для безопасности необходимо указать --confirm")
        print("Пример: python clear_database.py --all --confirm")
        return
    
    try:
        if args.full:
            print("🚨 ПОЛНАЯ ОЧИСТКА базы данных...")
            results = db_manager.clear_all_database_data()
            total = sum(results.values())
            print(f"✅ База данных полностью очищена!")
            print(f"Удалено записей:")
            for table, count in results.items():
                if count > 0:
                    print(f"   - {table}: {count}")
            print(f"Всего: {total} записей")
        
        elif args.url:
            print(f"Удаление URL из базы данных: {args.url}")
            removed_malicious = db_manager.remove_malicious_url(args.url)
            removed_blacklist = db_manager.remove_cached_blacklist_url(args.url)
            if removed_malicious or removed_blacklist:
                print(f"✅ URL удален из базы данных")
                if removed_malicious:
                    print(f"   - Удален из malicious_urls")
                if removed_blacklist:
                    print(f"   - Удален из cached_blacklist")
            else:
                print(f"⚠️  URL не найден в базе данных")
        
        elif args.all:
            print("Очистка всех URL данных...")
            result = db_manager.clear_all_url_data()
            url_count = db_manager.clear_malicious_hashes()
            print(f"✅ Очищено:")
            print(f"   - {result['malicious_urls']} вредоносных URL")
            print(f"   - {result['cached_whitelist']} whitelist записей")
            print(f"   - {result['cached_blacklist']} blacklist записей")
            print(f"   - {url_count} вредоносных хэшей")
        
        elif args.urls:
            count = db_manager.clear_malicious_urls()
            print(f"✅ Очищено {count} вредоносных URL")
        
        elif args.hashes:
            count = db_manager.clear_malicious_hashes()
            print(f"✅ Очищено {count} вредоносных хэшей")
        
        elif args.whitelist:
            count = db_manager.clear_cached_whitelist()
            print(f"✅ Очищено {count} записей из whitelist")
        
        elif args.blacklist:
            count = db_manager.clear_cached_blacklist()
            print(f"✅ Очищено {count} записей из blacklist")
        
        elif args.cache:
            whitelist_count = db_manager.clear_cached_whitelist()
            blacklist_count = db_manager.clear_cached_blacklist()
            print(f"✅ Очищено {whitelist_count} whitelist и {blacklist_count} blacklist записей")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

