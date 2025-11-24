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
        stats = attributes.get('last_analysis_stats', {}) or {}
        malicious = int(stats.get('malicious', 0) or 0)
        suspicious = int(stats.get('suspicious', 0) or 0)
        undetected = int(stats.get('undetected', 0) or 0)
        harmless = int(stats.get('harmless', 0) or 0)
        total = sum(stats.values()) if stats else 0
        
        analysis_results = attributes.get('last_analysis_results', {}) or {}
        detected_by_results = 0
        total_results_entries = 0
        if isinstance(analysis_results, dict):
            MALICIOUS_CATEGORIES = {"malicious", "suspicious", "phishing", "ransomware", "malware"}
            for engine, engine_data in analysis_results.items():
                if not isinstance(engine_data, dict):
                    continue
                total_results_entries += 1
                category = (engine_data.get('category') or '').lower()
                result = (engine_data.get('result') or '').lower()
                if category in MALICIOUS_CATEGORIES or result in MALICIOUS_CATEGORIES:
                    detected_by_results += 1
        if detected_by_results > malicious:
            malicious = detected_by_results
        if total_results_entries > total:
            total = total_results_entries
        
        detection_ratio = f"{malicious}/{total or 0}"
        
        logger.info(
            "[VirusTotal] Raw stats: malicious=%s suspicious=%s undetected=%s harmless=%s total=%s ratio=%s (results=%s)",
            malicious, suspicious, undetected, harmless, total, detection_ratio, detected_by_results
        )
        
        # КРИТИЧНО: Если нет данных (total == 0), возвращаем None (неизвестно)
        if total == 0:
            logger.warning("[VirusTotal] No analysis stats available for result: %s", result)
            return {
                "safe": None,
                "threat_type": None,
                "details": "VirusTotal: No analysis data available",
                "external_scan": "virustotal",
                "confidence": 0,
                "detection_ratio": detection_ratio
            }
        
        # КРИТИЧНО: Любое количество детекций => угрозa
        has_detection = malicious > 0 or suspicious > 0
        safe = not has_detection
        threat_type = "malicious" if has_detection else None
        
        # Уверенность: базовая 85 для чистых, растет с количеством детектов
        if has_detection:
            confidence = min(99, 70 + (malicious + suspicious) * 5)
        else:
            confidence = 85
        
        details = (
            f"VirusTotal detections: {detection_ratio} malicious, {suspicious} suspicious"
            if has_detection else
            f"VirusTotal clean: {detection_ratio}"
        )
        
        parsed = {
            "safe": safe,
            "threat_type": threat_type,
            "details": details,
            "external_scan": "virustotal",
            "confidence": confidence,
            "detection_ratio": detection_ratio,
            "raw_data": {
                "malicious_detections": malicious,
                "suspicious_detections": suspicious,
                "undetected": undetected,
                "total_engines": total
            }
        }
        
        logger.info("[VirusTotal] Parsed result: %s", parsed)
        return parsed