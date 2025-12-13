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
        
        # КРИТИЧНО: Если response не None и содержит data - URL найден в базе
        if response and 'data' in response:
            logger.info(f"Found URL in VirusTotal database: {url}")
            return response
        
        # КРИТИЧНО: Если response None (404 или другая ошибка) - URL не найден, отправляем на анализ
        # Если response есть, но нет 'data' - тоже считаем что не найден
        logger.info(f"URL not found in VirusTotal database (response: {response is not None}), submitting for analysis: {url}")

        if not self.session:
            logger.error("VirusTotal session is not initialized")
            return None

        submit_url = f"{self.base_url}/urls"
        # КРИТИЧНО: VirusTotal v3 ожидает application/x-www-form-urlencoded
        # Используем aiohttp.FormData для правильной кодировки
        from aiohttp import FormData
        form_data = FormData()
        form_data.add_field('url', url)
        headers = {
            "x-apikey": self.api_key,
        }

        try:
            async with self.session.post(submit_url, data=form_data, headers=headers) as resp:
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
        
        # КРИТИЧНО: Если нет данных (total == 0), возвращаем None (неизвестно)
        # Это позволит использовать эвристику вместо автоматического "опасно"
        if total == 0:
            logger.warning("[VirusTotal] No analysis stats available for result: %s, returning None for heuristic fallback", result)
            return {
                "safe": None,
                "threat_type": None,
                "details": "VirusTotal: No analysis data available",
                "external_scan": "virustotal",
                "confidence": 0,
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

        # Правила (исправленная логика - приоритет harmless над undetected):
        # - malicious >= 1 или suspicious >= 1 → UNSAFE (явные угрозы)
        # - если harmless >= 60% и нет детекций → SAFE (даже если молодой или много undetected)
        # - undetected > 70% И harmless < 30% → UNSAFE (слишком много неизвестного при малом количестве безопасных)
        # - очень молодой ресурс (<90 дней) + undetected > 50% И harmless < 40% → UNSAFE (подозрительно)
        # - иначе → SAFE (если нет явных угроз, считаем безопасным)

        if has_detection:
            # Явные детекции - всегда опасно
            safe = False
            threat_type = "malicious"
        elif harmless_ratio >= 0.6 and not has_detection:
            # КРИТИЧНО: Если большинство говорит "безопасно" - считаем безопасным
            # Даже если ресурс молодой или есть undetected
            safe = True
            threat_type = None
        elif undetected_ratio > 0.7 and harmless_ratio < 0.3:
            # Слишком много неизвестного при малом количестве безопасных - подозрительно
            safe = False
            threat_type = "suspicious"
        elif is_young and undetected_ratio > 0.5 and harmless_ratio < 0.4:
            # Молодой ресурс с большим процентом неизвестного И малым количеством безопасных - подозрительно
            safe = False
            threat_type = "suspicious"
        else:
            # Нет явных угроз - считаем безопасным
            safe = True
            threat_type = None

        if has_detection:
            confidence = min(99, 70 + (malicious + suspicious) * 5)
        elif safe is True:
            confidence = 90  # высокое доверие только при "чистых" результатах
        elif safe is False:
            confidence = 70  # подозрительно, но без явных детекций
        else:
            confidence = 0

        # КРИТИЧНО: Формируем детали на русском, без упоминания VirusTotal
        if has_detection:
            if malicious > 0:
                details = f"Обнаружено вредоносное ПО ({malicious} антивирусов)"
            elif suspicious > 0:
                details = f"Обнаружены подозрительные признаки ({suspicious} антивирусов)"
            else:
                details = "Обнаружены угрозы безопасности"
        elif safe is True:
            details = f"Проверено {total} антивирусами, угроз не обнаружено"
        elif safe is False:
            if is_young:
                details = "Новый ресурс с недостаточным количеством проверок"
            else:
                details = "Недостаточно данных для подтверждения безопасности"
        else:
            details = "Результат проверки неопределенный"

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