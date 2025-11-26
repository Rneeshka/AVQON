# app/external_apis/virustotal.py
import asyncio
import urllib.parse
from typing import Dict, Any, Optional, List
from .base_client import BaseAPIClient
from app.config import config
from app.logger import logger

class VirusTotalClient(BaseAPIClient):
    """Клиент для VirusTotal API"""
    
    def __init__(self):
        super().__init__(config.VIRUSTOTAL_URL_API, config.VIRUSTOTAL_API_KEY)
    
    def _get_headers(self) -> Dict[str, str]:
        # Базовые заголовки. Content-Type переопределяем при необходимости.
        return {
            "x-apikey": self.api_key,
        }
    
    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Проверка URL через VirusTotal"""
        if not self._check_rate_limit(config.VIRUSTOTAL_HOURLY_LIMIT):
            logger.warning("VirusTotal rate limit exceeded")
            return None
        
        # Согласно API v3, идентификатор URL — это base64 без паддинга
        url_id = self._encode_url_id(url)
        endpoint = f"/urls/{url_id}"
        response = await self._make_request("GET", endpoint)
        
        if response and 'data' in response:
            logger.info(f"Found URL in VirusTotal database: {url}")
            return response
        
        # Если URL не найден — отправляем новый анализ и ждём результатов
        logger.info(f"URL not found in VirusTotal database, submitting for analysis: {url}")

        if not self.session:
            logger.error("VirusTotal session is not initialized")
            return None

        submit_url = f"{self.base_url}/urls"
        # КРИТИЧНО: VirusTotal v3 ожидает application/x-www-form-urlencoded
        form_body = f"url={urllib.parse.quote(url, safe='')}"
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            async with self.session.post(submit_url, data=form_body, headers=headers) as resp:
                text = await resp.text()
                if resp.status in (200, 201):
                    try:
                        submit_resp = await resp.json()
                    except Exception:
                        logger.error(f"VirusTotal submit JSON parse error: {text}")
                        return None
                    if submit_resp and 'data' in submit_resp:
                        analysis_id = submit_resp['data']['id']
                        logger.info(f"URL submitted for analysis, ID: {analysis_id}")
                        return await self._poll_analysis(analysis_id)
                    logger.error(f"VirusTotal URL submission response without data: {submit_resp}")
                    return None
                else:
                    logger.error(f"VirusTotal URL submission failed: HTTP {resp.status}, body={text}")
                    return None
        except Exception as e:
            logger.error(f"VirusTotal URL submission exception: {e}", exc_info=True)
            return None
    
    async def _poll_analysis(self, analysis_id: str, max_attempts: int = 5, delay_seconds: float = 1.5) -> Optional[Dict[str, Any]]:
        """Периодически запрашивает результат анализа, пока он не завершится"""
        endpoint = f"/analyses/{analysis_id}"
        last_response = None
        for attempt in range(max_attempts):
            last_response = await self._make_request("GET", endpoint)
            status = last_response.get('data', {}).get('attributes', {}).get('status')
            logger.info(f"VirusTotal analysis status ({analysis_id}): {status} (attempt {attempt + 1}/{max_attempts})")
            if status == 'completed' or status == 'finished':
                return last_response
            await asyncio.sleep(delay_seconds * (attempt + 1))
        logger.warning(f"VirusTotal analysis did not finish in time: {analysis_id}")
        return last_response

    def _encode_url_id(self, url: str) -> str:
        import base64
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return encoded
    
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
        
        # КРИТИЧНО: Если нет данных (total == 0), консервативный подход - считаем опасным
        if total == 0:
            logger.warning("[VirusTotal] No analysis stats available for result: %s, using conservative approach (unsafe)", result)
            return {
                "safe": False,
                "threat_type": "suspicious",
                "details": "VirusTotal: No analysis data available - conservative security approach",
                "external_scan": "virustotal",
                "confidence": 40,
                "detection_ratio": detection_ratio
            }

        # Консервативный движок риска ("when in doubt, block it")
        harmless_ratio = harmless / total if total > 0 else 0.0
        undetected_ratio = undetected / total if total > 0 else 0.0

        # Любые детекции => опасно
        has_detection = malicious > 0 or suspicious > 0

        # Пытаемся оценить "молодость" домена/URL по дате первого анализа
        is_young = False
        try:
            first_submission = attributes.get("first_submission_date") or attributes.get("creation_date")
            if isinstance(first_submission, (int, float)):
                import time
                age_days = (time.time() - float(first_submission)) / 86400.0
                if age_days < 90:
                    is_young = True
        except Exception:
            # Если не можем определить возраст, просто игнорируем этот признак
            is_young = False

        # Правила:
        # - malicious >= 1 или suspicious >= 1 → UNSAFE
        # - undetected > 30% → UNSAFE
        # - очень молодой ресурс (<90 дней) → UNSAFE
        # - только если harmless >= 80% и нет детекций → SAFE

        if has_detection or undetected_ratio > 0.3 or is_young:
            safe = False
            threat_type = "malicious"
            if not has_detection and (undetected_ratio > 0.3 or is_young):
                threat_type = "suspicious"
        elif harmless_ratio >= 0.8 and not has_detection:
            safe = True
            threat_type = None
        else:
            # Не достаточно сигналов для уверенного SAFE -> консервативный подход (опасно)
            safe = False
            threat_type = "suspicious"

        if has_detection:
            confidence = min(99, 70 + (malicious + suspicious) * 5)
        elif safe is True:
            confidence = 90  # высокое доверие только при "чистых" результатах
        elif safe is False:
            confidence = 70  # подозрительно, но без явных детекций
        else:
            confidence = 0

        if has_detection:
            details = f"VirusTotal detections: {detection_ratio} malicious, {suspicious} suspicious"
        elif safe is True:
            details = f"VirusTotal clean (harmless={harmless}, undetected={undetected}, ratio={detection_ratio})"
        elif safe is False:
            details = f"VirusTotal uncertain but treated as unsafe (undetected_ratio={undetected_ratio:.2f}, young={is_young})"
        else:
            details = "VirusTotal result unclear, treated as unknown"

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
                "harmless": harmless,
                "total_engines": total,
                "undetected_ratio": undetected_ratio,
                "harmless_ratio": harmless_ratio,
                "is_young": is_young,
            }
        }

        logger.info("[VirusTotal] Parsed result (conservative): %s", parsed)
        return parsed