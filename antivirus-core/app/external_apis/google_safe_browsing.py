# app/external_apis/google_safe_browsing.py
from .base_client import BaseAPIClient
from typing import Dict, Any, Optional, List
from app.config import config

class GoogleSafeBrowsingClient(BaseAPIClient):
    """Клиент для Google Safe Browsing API"""
    
    def __init__(self):
        super().__init__(config.GOOGLE_SAFE_BROWSING_API, config.GOOGLE_SAFE_BROWSING_KEY)
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json"
        }
    
    async def check_urls(self, urls: List[str]) -> Optional[Dict[str, Any]]:
        """Проверка списка URL через Google Safe Browsing"""
        endpoint = f"/threatMatches:find?key={self.api_key}"
        
        threat_types = [
            "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", 
            "POTENTIALLY_HARMFUL_APPLICATION"
        ]
        
        data = {
            "client": {
                "clientId": "antivirus-core-api",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": threat_types,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls]
            }
        }
        
        return await self._make_request("POST", endpoint, data=data)
    
    def parse_google_result(self, result: Dict[str, Any], original_url: str) -> Dict[str, Any]:
        """Парсинг результатов Google Safe Browsing"""
        # КРИТИЧНО: Если result пустой или None, это может означать ошибку, а не безопасность
        if not result:
            return {"safe": None, "external_scan": "failed", "details": "Google Safe Browsing: No response", "confidence": 0}
        
        # Если нет поля 'matches', это означает, что URL безопасен (Google возвращает пустой объект для безопасных URL)
        if 'matches' not in result:
            return {"safe": True, "external_scan": "google_safe_browsing", "confidence": 85, "details": "Google Safe Browsing: No threats detected"}
        
        matches = result['matches']
        # Google Safe Browsing может возвращать частичные совпадения URL
        # Проверяем все совпадения, а не только точные
        threats_found = []
        for match in matches:
            threat_url = match.get('threat', {}).get('url', '')
            # Проверяем точное совпадение или совпадение домена
            if threat_url == original_url or self._url_matches(threat_url, original_url):
                threats_found.append(match)
        
        if not threats_found:
            return {"safe": True, "external_scan": "clean", "confidence": 70}
        
        threat_types = [match.get('threatType', 'unknown') for match in threats_found]
        platform_types = [match.get('platformType', 'unknown') for match in threats_found]
        
        return {
            "safe": False,
            "threat_type": "malicious",
            "details": f"Google Safe Browsing: {', '.join(set(threat_types))} detected",
            "external_scan": "google_safe_browsing",
            "threats": threats_found,
            "confidence": 90,  # Google Safe Browsing имеет высокую точность
            "raw_data": {
                "threat_types": threat_types,
                "platform_types": platform_types
            }
        }
    
    def _url_matches(self, threat_url: str, original_url: str) -> bool:
        """Проверяет, соответствует ли URL угрозы исходному URL"""
        try:
            from urllib.parse import urlparse
            threat_parsed = urlparse(threat_url)
            original_parsed = urlparse(original_url)
            
            # Сравниваем домены
            return threat_parsed.netloc.lower() == original_parsed.netloc.lower()
        except:
            return False