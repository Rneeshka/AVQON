"""
Репозиторий для работы с базой данных
Использует db_manager из основного приложения
"""
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

# Добавляем путь к основному приложению для импорта db_manager
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "app"))

try:
    from database import db_manager
except ImportError:
    # Fallback: пытаемся импортировать из родительской директории
    import importlib.util
    db_path = Path(__file__).parent.parent.parent.parent / "app" / "database.py"
    if db_path.exists():
        spec = importlib.util.spec_from_file_location("database", db_path)
        database_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(database_module)
        db_manager = database_module.db_manager
    else:
        db_manager = None
        logging.warning("Cannot import db_manager from main application")

logger = logging.getLogger(__name__)

# Проверяем, что db_manager доступен
if db_manager is None:
    logger.warning("db_manager is None - database features will be unavailable")


class AdminRepository:
    """
    Репозиторий для административных операций
    Использует существующий db_manager
    """
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Получает статистику базы данных"""
        if db_manager is None:
            logger.error("db_manager is not available")
            return {}
        return db_manager.get_database_stats()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Получает статистику кэша"""
        if db_manager is None:
            logger.error("db_manager is not available")
            return {}
        return db_manager.get_cache_stats()
    
    def get_all_threats(self) -> List[Dict[str, Any]]:
        """Получает все угрозы"""
        if db_manager is None:
            logger.error("db_manager is not available")
            return []
        return db_manager.get_all_threats()
    
    def get_all_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Получает логи запросов"""
        if db_manager is None:
            logger.error("db_manager is not available")
            return []
        return db_manager.get_all_logs()[:limit]
    
    def get_all_cached_whitelist(self, limit: int = 500) -> List[Dict[str, Any]]:
        """Получает все записи whitelist"""
        return db_manager.get_all_cached_whitelist(limit=limit)
    
    def get_all_cached_blacklist(self, limit: int = 500) -> List[Dict[str, Any]]:
        """Получает все записи blacklist"""
        return db_manager.get_all_cached_blacklist(limit=limit)
    
    def list_ip_reputation(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Получает список IP репутации"""
        return db_manager.list_ip_reputation(limit)
    
    def get_api_keys(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Получает список API ключей"""
        if db_manager is None:
            logger.error("db_manager is not available")
            return []
        try:
            with db_manager._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT api_key, name, is_active, access_level, rate_limit_daily, rate_limit_hourly,
                           requests_total, requests_today, requests_hour, created_at, last_used, expires_at,
                           api_keys.user_id, 
                           COALESCE(
                               (SELECT username FROM accounts WHERE accounts.id = api_keys.user_id),
                               (SELECT username FROM users WHERE users.user_id = api_keys.user_id)
                           ) as username,
                           COALESCE(
                               (SELECT email FROM accounts WHERE accounts.id = api_keys.user_id),
                               (SELECT email FROM users WHERE users.user_id = api_keys.user_id)
                           ) as email,
                           (SELECT password_hash FROM accounts WHERE accounts.id = api_keys.user_id) as password_hash
                    FROM api_keys
                    ORDER BY created_at DESC
                    LIMIT %s
                """, (limit,))
                return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            logger.error(f"Error getting API keys: {e}")
            return []
    
    def create_api_key(
        self,
        name: str,
        description: str = "",
        access_level: str = "premium",
        daily_limit: int = 10000,
        hourly_limit: int = 10000,
        expires_days: int = 30
    ) -> Optional[str]:
        """Создает новый API ключ"""
        if db_manager is None:
            logger.error("db_manager is not available")
            return None
        return db_manager.create_api_key(
            name=name,
            description=description,
            access_level=access_level,
            daily_limit=daily_limit,
            hourly_limit=hourly_limit,
            expires_days=expires_days
        )
    
    def extend_api_key(self, api_key: str, extend_days: int) -> bool:
        """Продлевает API ключ"""
        if db_manager is None:
            logger.error("db_manager is not available")
            return False
        return db_manager.extend_api_key(api_key, extend_days)
    
    def add_malicious_url(
        self,
        url: str,
        threat_type: str,
        description: str,
        severity: str = "medium"
    ) -> bool:
        """Добавляет вредоносный URL"""
        try:
            return db_manager.add_malicious_url(url, threat_type, description, severity)
        except Exception as e:
            logger.error(f"Error adding malicious URL: {e}")
            return False
    
    def add_malicious_hash(
        self,
        file_hash: str,
        threat_type: str,
        description: str,
        severity: str = "medium"
    ) -> bool:
        """Добавляет вредоносный хэш"""
        try:
            return db_manager.add_malicious_hash(file_hash, threat_type, description, severity)
        except Exception as e:
            logger.error(f"Error adding malicious hash: {e}")
            return False
    
    def search_urls_in_database(self, query: str, limit: int = 50) -> Dict[str, List[Dict[str, Any]]]:
        """Ищет URL в базе данных"""
        return db_manager.search_urls_in_database(query, limit=limit)
    
    def remove_malicious_url(self, url: str) -> bool:
        """Удаляет вредоносный URL"""
        return db_manager.remove_malicious_url(url)
    
    def remove_cached_blacklist_url(self, url: str) -> bool:
        """Удаляет URL из blacklist кэша"""
        return db_manager.remove_cached_blacklist_url(url)
    
    def mark_url_as_safe(self, url: str) -> bool:
        """Помечает URL как безопасный"""
        return db_manager.mark_url_as_safe(url)
    
    def clear_malicious_urls(self) -> int:
        """Очищает все вредоносные URL"""
        return db_manager.clear_malicious_urls()
    
    def clear_malicious_hashes(self) -> int:
        """Очищает все вредоносные хэши"""
        return db_manager.clear_malicious_hashes()
    
    def clear_all_url_data(self) -> Dict[str, int]:
        """Очищает все URL данные"""
        return db_manager.clear_all_url_data()
    
    def clear_cached_whitelist(self) -> int:
        """Очищает whitelist кэш"""
        return db_manager.clear_cached_whitelist()
    
    def clear_cached_blacklist(self) -> int:
        """Очищает blacklist кэш"""
        return db_manager.clear_cached_blacklist()
    
    def clear_all_database_data(self) -> Dict[str, Any]:
        """Очищает все данные базы данных"""
        return db_manager.clear_all_database_data()
    
    def get_cached_entries(self, store: str, limit: int) -> List[Dict[str, Any]]:
        """Получает записи из кэша"""
        return db_manager.get_cached_entries(store, limit)
    
    def save_whitelist_entry(self, url: str, result: Dict[str, Any]) -> bool:
        """Сохраняет запись в whitelist"""
        return db_manager.save_whitelist_entry(url, result)
    
    def save_blacklist_entry(self, url: str, result: Dict[str, Any]) -> bool:
        """Сохраняет запись в blacklist"""
        return db_manager.save_blacklist_entry(url, result)
    
    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Проверяет URL в базе"""
        return db_manager.check_url(url)
    
    def check_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Проверяет домен в базе"""
        return db_manager.check_domain(domain)
    
    def get_all_reviews(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Получает все отзывы"""
        if db_manager is None:
            return []
        return db_manager.get_all_reviews(limit=limit)
    
    def get_review_stats(self) -> Dict[str, Any]:
        """Получает статистику отзывов"""
        if db_manager is None:
            return {"total": 0, "average_rating": 0.0, "rating_distribution": {}}
        return db_manager.get_review_stats()
    
    def get_chart_data(self) -> Dict[str, Any]:
        """Получает данные для графиков"""
        if db_manager is None:
            return {
                "requests_over_time": [],
                "status_codes": {},
                "threat_types": {},
                "cache_ratio": {"hits": 0, "misses": 0},
                "api_key_usage": []
            }
        
        try:
            with db_manager._get_connection() as conn:
                cursor = conn.cursor()
                
                # Распределение угроз по типам
                threats = self.get_all_threats()
                threat_types = {}
                for threat in threats:
                    threat_type = threat.get("type", "unknown")
                    threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                
                # Пытаемся использовать таблицу request_logs (основная таблица)
                # Запросы по времени (последние 7 дней, группировка по дням)
                try:
                    cursor.execute("""
                        SELECT DATE(timestamp) as date, COUNT(*) as count
                        FROM request_logs
                        WHERE timestamp >= NOW() - INTERVAL '7 days'
                        GROUP BY DATE(timestamp)
                        ORDER BY date ASC
                    """)
                    requests_over_time = [{"date": str(row["date"]), "count": row["count"]} for row in cursor.fetchall()]
                    
                    # Распределение по статус-кодам
                    cursor.execute("""
                        SELECT status_code, COUNT(*) as count
                        FROM request_logs
                        WHERE timestamp >= NOW() - INTERVAL '7 days'
                        GROUP BY status_code
                        ORDER BY count DESC
                    """)
                    status_codes = {str(row["status_code"]): row["count"] for row in cursor.fetchall()}
                    
                    api_key_usage = []
                except Exception as e:
                    logger.warning(f"Error querying request_logs, trying logs table: {e}")
                    # Fallback на logs таблицу если существует
                    try:
                        cursor.execute("""
                            SELECT DATE(created_at) as date, COUNT(*) as count
                            FROM logs
                            WHERE created_at >= NOW() - INTERVAL '7 days'
                            GROUP BY DATE(created_at)
                            ORDER BY date ASC
                        """)
                        requests_over_time = [{"date": str(row["date"]), "count": row["count"]} for row in cursor.fetchall()]
                        
                        cursor.execute("""
                            SELECT status_code, COUNT(*) as count
                            FROM logs
                            WHERE created_at >= NOW() - INTERVAL '7 days'
                            GROUP BY status_code
                            ORDER BY count DESC
                        """)
                        status_codes = {str(row["status_code"]): row["count"] for row in cursor.fetchall()}
                        api_key_usage = []
                    except Exception:
                        requests_over_time = []
                        status_codes = {}
                        api_key_usage = []
                
                return {
                    "requests_over_time": requests_over_time,
                    "status_codes": status_codes,
                    "threat_types": threat_types,
                    "cache_ratio": {},  # Будет заполнено из cache_stats
                    "api_key_usage": api_key_usage
                }
        except Exception as e:
            logger.error(f"Error getting chart data: {e}")
            return {
                "requests_over_time": [],
                "status_codes": {},
                "threat_types": {},
                "cache_ratio": {"hits": 0, "misses": 0},
                "api_key_usage": []
            }

