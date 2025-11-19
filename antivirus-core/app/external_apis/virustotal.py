# app/external_apis/virustotal.py
from .base_client import BaseAPIClient
from typing import Dict, Any, Optional, List
from app.config import config
from app.logger import logger

class VirusTotalClient(BaseAPIClient):
    """Клиент для VirusTotal API"""
    
    def __init__(self):
        super().__init__(config.VIRUSTOTAL_URL_API, config.VIRUSTOTAL_API_KEY)
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
    
    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Проверка URL через VirusTotal"""
        if not self._check_rate_limit(config.VIRUSTOTAL_HOURLY_LIMIT):
            logger.warning("VirusTotal rate limit exceeded")
            return None
        
        # Используем правильный подход VirusTotal API v3
        import hashlib
        import base64
        
        # Создаем хэш URL для VirusTotal (SHA-256)
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        # Пробуем получить информацию о URL по хэшу
        endpoint = f"/urls/{url_hash}"
        response = await self._make_request("GET", endpoint)
        
        if response and 'data' in response:
            logger.info(f"Found URL in VirusTotal database: {url}")
            return response
        else:
            # Если URL не найден в базе, отправляем на анализ
            logger.info(f"URL not found in VirusTotal database, submitting for analysis: {url}")
            endpoint = "/urls"
            data = {"url": url}
            response = await self._make_request("POST", endpoint, data=data)
            
            if response and 'data' in response:
                analysis_id = response['data']['id']
                logger.info(f"URL submitted for analysis, ID: {analysis_id}")
                # Получаем результаты анализа
                return await self._get_analysis(analysis_id)
            else:
                logger.error(f"VirusTotal URL submission failed: {response}")
                return None
    
    async def _get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Получение результатов анализа"""
        endpoint = f"/analyses/{analysis_id}"
        return await self._make_request("GET", endpoint)
    
    async def check_file_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Проверка файла по хэшу через VirusTotal"""
        if not self._check_rate_limit(config.VIRUSTOTAL_HOURLY_LIMIT):
            logger.warning("VirusTotal rate limit exceeded")
            return None
        
        endpoint = f"/files/{file_hash}"
        return await self._make_request("GET", endpoint)
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Проверка IP адреса через VirusTotal"""
        if not self._check_rate_limit(config.VIRUSTOTAL_HOURLY_LIMIT):
            logger.warning("VirusTotal rate limit exceeded")
            return None
        
        endpoint = f"/ip_addresses/{ip_address}"
        return await self._make_request("GET", endpoint)
    
    def parse_virustotal_result(self, result: Dict[str, Any], check_type: str) -> Dict[str, Any]:
        """Парсинг результатов VirusTotal в наш формат"""
        if not result or 'data' not in result:
            return {"safe": None, "external_scan": "failed", "details": "VirusTotal: No data available"}
        
        data = result['data']
        attributes = data.get('attributes', {})
        
        # Статистика обнаружений
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        # Определяем уровень угрозы
        threat_level = "clean"
        if malicious > 5:
            threat_level = "malicious"
        elif malicious > 0:
            threat_level = "suspicious"
        elif suspicious > 2:
            threat_level = "suspicious"
        
        # КРИТИЧНО: Если нет данных (total == 0), возвращаем None (неизвестно)
        if total == 0:
            return {
                "safe": None,
                "threat_type": None,
                "details": "VirusTotal: No analysis data available",
                "external_scan": "virustotal",
                "confidence": 0
            }
        
        # Вычисляем уверенность на основе количества детекций
        if malicious == 0:
            confidence = 85  # Высокая уверенность в чистоте
        else:
            confidence = min(95, 60 + (malicious * 5))  # Уверенность растет с количеством детекций
        
        return {
            "safe": threat_level == "clean",
            "threat_type": threat_level if threat_level != "clean" else None,
            "details": f"VirusTotal: {malicious}/{total} engines detected threats",
            "external_scan": "virustotal",
            "confidence": confidence,
            "raw_data": {
                "malicious_detections": malicious,
                "suspicious_detections": suspicious,
                "total_engines": total
            }
        }