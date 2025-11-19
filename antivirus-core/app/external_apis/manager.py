# app/external_apis/manager.py
from typing import Dict, Any, List, Optional
import asyncio
from app.logger import logger
from app.config import config
from .virustotal import VirusTotalClient
from .google_safe_browsing import GoogleSafeBrowsingClient
from .abuseipdb import AbuseIPDBClient

class ExternalAPIManager:
    """Менеджер для координации проверок через внешние API"""
    
    def __init__(self):
        self.virustotal = VirusTotalClient()
        self.google_safe_browsing = GoogleSafeBrowsingClient()
        self.abuseipdb = AbuseIPDBClient()
        # Автовключение клиентов по наличию ключей окружения
        self.enabled_apis = {
            'virustotal': bool(config.VIRUSTOTAL_API_KEY and 'your_virustotal_key_here' not in config.VIRUSTOTAL_API_KEY),
            'google_safe_browsing': bool(config.GOOGLE_SAFE_BROWSING_KEY and 'your_google_key_here' not in config.GOOGLE_SAFE_BROWSING_KEY), 
            'abuseipdb': bool(config.ABUSEIPDB_API_KEY and 'your_abuseipdb_key_here' not in config.ABUSEIPDB_API_KEY)
        }
    
    async def check_url_multiple_apis(self, url: str) -> Dict[str, Any]:
        """Проверка URL через несколько внешних API"""
        results = {}
        tasks = []
        api_names = []
        
        # Создаем задачи для включенных API
        if self.enabled_apis['virustotal']:
            tasks.append(self._safe_api_call_with_context(self.virustotal, 'check_url', url, api_name='virustotal'))
            api_names.append('virustotal')
        
        if self.enabled_apis['google_safe_browsing']:
            tasks.append(self._safe_api_call_with_context(self.google_safe_browsing, 'check_urls', [url], api_name='google_safe_browsing'))
            api_names.append('google_safe_browsing')
        
        if self.enabled_apis['abuseipdb']:
            # AbuseIPDB не поддерживает URL проверки, пропускаем
            pass
        
        # Выполняем все проверки параллельно
        if tasks:
            api_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Обрабатываем результаты
            for name, result in zip(api_names, api_results):
                if isinstance(result, Exception):
                    logger.error(f"{name} check failed: {result}")
                    results[name] = {"error": str(result)}
                else:
                    results[name] = result
        
        return self._combine_external_results(results, url)
    
    async def _safe_api_call_with_context(self, client, method_name, *args, api_name: str):
        """Безопасный вызов API с контекстным менеджером и улучшенной обработкой ошибок"""
        max_retries = 2
        for attempt in range(max_retries):
            try:
                async with client as c:
                    method = getattr(c, method_name)
                    result = await method(*args)
                    return result
            except asyncio.TimeoutError as e:
                logger.warning(f"{api_name} API timeout (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(0.5 * (attempt + 1))
            except Exception as e:
                error_type = type(e).__name__
                logger.error(f"{api_name} API error (attempt {attempt + 1}/{max_retries}): {error_type}: {e}")
                # Для сетевых ошибок делаем retry
                if "connection" in str(e).lower() or "timeout" in str(e).lower():
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                raise
    
    async def check_file_hash_multiple_apis(self, file_hash: str) -> Dict[str, Any]:
        """Проверка файла по хэшу через внешние API"""
        if not self.enabled_apis['virustotal']:
            return {"safe": None, "external_scan": "disabled", "details": "External API disabled"}
        
        async with self.virustotal as vt:
            try:
                result = await vt.check_file_hash(file_hash)
                parsed_result = vt.parse_virustotal_result(result, "file")
                return parsed_result
            except Exception as e:
                logger.error(f"VirusTotal file check failed: {e}")
                return {"safe": None, "external_scan": "failed", "details": f"VirusTotal check failed: {str(e)}"}
    
    async def check_ip_multiple_apis(self, ip_address: str) -> Dict[str, Any]:
        """Проверка IP адреса через внешние API"""
        results = {}
        
        async with self.virustotal as vt, self.abuseipdb as abuse:
            tasks = []
            api_names = []
            
            if self.enabled_apis['virustotal']:
                tasks.append(self._safe_api_call(vt.check_ip, ip_address, api_name='virustotal'))
                api_names.append('virustotal')
            
            if self.enabled_apis['abuseipdb']:
                tasks.append(self._safe_api_call(abuse.check_ip, ip_address, api_name='abuseipdb'))
                api_names.append('abuseipdb')
            
            api_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for name, result in zip(api_names, api_results):
                if isinstance(result, Exception):
                    logger.error(f"{name} IP check failed: {result}")
                    results[name] = {"error": str(result)}
                else:
                    results[name] = result
        
        combined = self._combine_ip_results(results, ip_address)
        # Автосохранение репутации IP в базу
        try:
            from app.database import db_manager
            db_manager.upsert_ip_reputation(
                ip=ip_address,
                threat_type=combined.get('threat_type'),
                reputation_score=combined.get('external_scans', {}).get('abuseipdb', {}).get('reputation_score') or combined.get('confidence'),
                details=combined.get('details', ''),
                source='external_apis'
            )
        except Exception as e:
            logger.error(f"Failed to persist IP reputation: {e}")
        return combined
    
    async def _safe_api_call(self, coroutine, *args, api_name: str):
        """Безопасный вызов API с обработкой ошибок"""
        try:
            return await coroutine(*args)
        except Exception as e:
            logger.error(f"{api_name} API error: {e}")
            raise
    
    def _combine_external_results(self, results: Dict[str, Any], original_url: str) -> Dict[str, Any]:
        """Объединение результатов от разных API"""
        logger.info(f"🔍 Combining external results for {original_url}: {results}")
        
        # Парсим результаты каждого API
        parsed_results = {}
        
        if 'virustotal' in results and results['virustotal']:
            try:
                parsed_results['virustotal'] = self.virustotal.parse_virustotal_result(
                    results['virustotal'], "url"
                )
                logger.info(f"🔍 VirusTotal parsed result: {parsed_results['virustotal']}")
            except Exception as vt_error:
                logger.error(f"VirusTotal parsing failed: {vt_error}", exc_info=True)
        
        if 'google_safe_browsing' in results and results['google_safe_browsing']:
            try:
                parsed_results['google'] = self.google_safe_browsing.parse_google_result(
                    results['google_safe_browsing'], original_url
                )
                logger.info(f"🔍 Google Safe Browsing parsed result: {parsed_results['google']}")
            except Exception as gsb_error:
                logger.error(f"Google Safe Browsing parsing failed: {gsb_error}", exc_info=True)
        
        # Определяем общий вердикт
        safe_count = 0
        unsafe_count = 0
        total_checks = 0
        threats = []
        details = []
        
        for api_name, result in parsed_results.items():
            if result and isinstance(result, dict):
                # КРИТИЧНО: Проверяем safe явно, не используя default True
                result_safe = result.get('safe')
                if result_safe is False:
                    unsafe_count += 1
                    threats.append(f"{api_name}: {result.get('threat_type', 'unknown')}")
                    detail = result.get('details', '')
                    if detail:
                        details.append(detail)
                elif result_safe is True:
                    safe_count += 1
                # Если safe не определен (None), не считаем ни safe, ни unsafe
            total_checks += 1
        
        # КРИТИЧНО: Если хотя бы один API обнаружил угрозу - считаем опасным
        # Если нет проверок или все вернули None - возвращаем None (неизвестно)
        if unsafe_count > 0:
            is_safe = False
        elif safe_count > 0 and unsafe_count == 0:
            is_safe = True
        else:
            # Нет результатов или все вернули None
            is_safe = None
        
        # КРИТИЧНО: Определяем threat_type только если точно известно, что небезопасно
        threat_type = None
        if is_safe is False:
            threat_type = "malicious"
        elif is_safe is None:
            threat_type = None  # Неизвестно
        
        final_result = {
            "safe": is_safe,
            "threat_type": threat_type,
            "details": " | ".join(details) if details else ("All external scans clean" if is_safe is True else "Unable to determine safety"),
            "external_scans": parsed_results,
            "confidence": self._calculate_confidence(parsed_results) if parsed_results else 0
        }
        
        logger.info(f"🔍 Final external API result for {original_url}: {final_result}")
        return final_result
    
    def _combine_ip_results(self, results: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Объединение результатов проверки IP"""
        parsed_results = {}
        
        if 'virustotal' in results and results['virustotal']:
            parsed_results['virustotal'] = self.virustotal.parse_virustotal_result(
                results['virustotal'], "ip"
            )
        
        if 'abuseipdb' in results and results['abuseipdb']:
            parsed_results['abuseipdb'] = self.abuseipdb.parse_abuseipdb_result(
                results['abuseipdb']
            )
        
        # Логика объединения для IP
        is_safe = True
        threats = []
        details = []
        
        for api_name, result in parsed_results.items():
            if not result.get('safe', True):
                is_safe = False
                threats.append(f"{api_name}: {result.get('threat_type', 'suspicious')}")
                details.append(result.get('details', ''))
        
        return {
            "safe": is_safe,
            "threat_type": "suspicious_ip" if not is_safe else None,
            "details": " | ".join(details) if details else "IP reputation clean",
            "external_scans": parsed_results
        }
    
    def _calculate_confidence(self, results: Dict[str, Any]) -> int:
        """Вычисление общей уверенности на основе внешних сканов"""
        if not results:
            return 0
        
        confidence_scores = []
        for result in results.values():
            if 'confidence' in result:
                confidence_scores.append(result['confidence'])
            elif 'reputation_score' in result:
                confidence_scores.append(result['reputation_score'])
            else:
                # Если нет явного score, используем бинарную логику
                confidence_scores.append(100 if result.get('safe', True) else 0)
        
        return sum(confidence_scores) // len(confidence_scores) if confidence_scores else 50

# Глобальный экземпляр менеджера
external_api_manager = ExternalAPIManager()