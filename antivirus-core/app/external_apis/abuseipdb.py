# app/external_apis/abuseipdb.py
from .base_client import BaseAPIClient
from typing import Dict, Any, Optional
from app.config import config

class AbuseIPDBClient(BaseAPIClient):
    """Клиент для AbuseIPDB API"""
    
    def __init__(self):
        super().__init__(config.ABUSEIPDB_API, config.ABUSEIPDB_API_KEY)
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "Key": self.api_key,
            "Accept": "application/json"
        }
    
    async def check_ip(self, ip_address: str, max_age_days: int = 30) -> Optional[Dict[str, Any]]:
        """Проверка IP адреса через AbuseIPDB"""
        endpoint = "/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": True
        }
        
        return await self._make_request("GET", endpoint, params=params)
    
    def parse_abuseipdb_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Парсинг результатов AbuseIPDB"""
        if not result or 'data' not in result:
            return {"safe": True, "reputation": "unknown"}
        
        data = result['data']
        abuse_confidence = data.get('abuseConfidenceScore', 0)
        total_reports = data.get('totalReports', 0)
        country = data.get('countryCode', 'Unknown')
        
        # Определяем уровень угрозы
        threat_level = "clean"
        if abuse_confidence > 80:
            threat_level = "malicious"
        elif abuse_confidence > 50:
            threat_level = "suspicious"
        elif total_reports > 10:
            threat_level = "suspicious"
        
        return {
            "safe": threat_level == "clean",
            "threat_type": "suspicious_ip" if threat_level != "clean" else None,
            "details": f"AbuseIPDB: {abuse_confidence}% abuse confidence ({total_reports} reports)",
            "external_scan": "abuseipdb",
            "reputation_score": 100 - abuse_confidence,
            "raw_data": {
                "abuse_confidence": abuse_confidence,
                "total_reports": total_reports,
                "country": country,
                "isp": data.get('isp', 'Unknown')
            }
        }