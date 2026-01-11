"""
Сервисный слой для административных операций
"""
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

# Добавляем путь к основному приложению
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "app"))

try:
    from services import analysis_service
except ImportError:
    analysis_service = None

from app.db.repositories import AdminRepository

logger = logging.getLogger(__name__)


class AdminService:
    """
    Сервис для административных операций
    """
    
    def __init__(self, repository: AdminRepository):
        self.repository = repository
        self.analysis_service = analysis_service
    
    async def refresh_cache_entries(
        self,
        target: str,
        limit: int
    ) -> Dict[str, int]:
        """
        Обновляет записи кэша через перепроверку URL
        """
        limit = max(1, min(limit, 50))
        targets = []
        target = target.lower()
        
        if target in ("whitelist", "all"):
            targets.append("whitelist")
        if target in ("blacklist", "all"):
            targets.append("blacklist")
        if not targets:
            targets = ["all"]
        if "all" in targets:
            targets = ["whitelist", "blacklist"]
        
        summary = {
            "processed": 0,
            "whitelist": 0,
            "blacklist": 0,
            "errors": 0
        }
        
        entries = []
        for store in targets:
            entries.extend(self.repository.get_cached_entries(store, limit))
        
        entries = entries[:limit]
        
        if not self.analysis_service:
            logger.error("Analysis service not available")
            return summary
        
        for entry in entries:
            url = entry.get("url")
            payload = entry.get("payload") or {}
            
            if not url:
                url = payload.get("url")
            if not url:
                domain = entry.get("domain") or payload.get("domain")
                if domain:
                    url = f"https://{domain}"
            if not url:
                summary["errors"] += 1
                continue
            
            try:
                result = await self.analysis_service.analyze_url(
                    url,
                    use_external_apis=True
                )
                summary["processed"] += 1
                
                if result.get("safe") is True:
                    self.repository.save_whitelist_entry(url, result)
                    summary["whitelist"] += 1
                elif result.get("safe") is False:
                    self.repository.save_blacklist_entry(url, result)
                    summary["blacklist"] += 1
            except Exception as exc:
                summary["errors"] += 1
                logger.warning(f"Cache refresh failed for {url}: {exc}")
        
        return summary
    
    async def recheck_url(self, url: str) -> Dict[str, Any]:
        """
        Перепроверяет URL (игнорирует БД)
        """
        if not self.analysis_service:
            return {
                "success": False,
                "message": "Analysis service not available"
            }
        
        try:
            # Удаляем из БД и кэша
            self.repository.mark_url_as_safe(url)
            
            # Делаем новый анализ
            result = await self.analysis_service.analyze_url(
                url,
                use_external_apis=True,
                ignore_database=True
            )
            
            if result.get("safe") is True:
                self.repository.save_whitelist_entry(url, result)
                return {
                    "success": True,
                    "message": "URL перепроверен и помечен как безопасный",
                    "result": result
                }
            elif result.get("safe") is False:
                self.repository.save_blacklist_entry(url, result)
                return {
                    "success": True,
                    "message": f"URL перепроверен и все еще помечен как опасный: {result.get('threat_type', 'unknown')}",
                    "result": result
                }
            else:
                return {
                    "success": True,
                    "message": "URL перепроверен, результат неопределенный",
                    "result": result
                }
        except Exception as e:
            logger.error(f"Recheck URL error: {e}")
            return {
                "success": False,
                "message": f"Ошибка перепроверки: {str(e)}"
            }
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """
        Получает статистику для дашборда
        """
        db_stats = self.repository.get_database_stats()
        cache_stats = self.repository.get_cache_stats()
        
        return {
            **db_stats,
            **cache_stats,
            "total_cache_entries": (
                cache_stats.get("whitelist_entries", 0) +
                cache_stats.get("blacklist_entries", 0)
            ),
            "total_cache_hits": (
                cache_stats.get("whitelist_hits", 0) +
                cache_stats.get("blacklist_hits", 0)
            )
        }
    
    def get_threats_by_type(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Группирует угрозы по типам
        """
        threats = self.repository.get_all_threats()
        
        result = {
            "hash": [],
            "url": [],
            "ip": [],
            "domain": []
        }
        
        for threat in threats:
            threat_type = threat.get("type", "url")
            if threat_type in result:
                result[threat_type].append(threat)
        
        return result

