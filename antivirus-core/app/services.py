# app/services.py (ОБНОВЛЕННАЯ ВЕРСИЯ)
import asyncio
import hashlib
import time
import re
import os
import tempfile
import subprocess
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from app.database import db_manager
from app.external_apis.manager import external_api_manager
from app.logger import logger
from app.validators import security_validator
from app.cache import disk_cache

class AnalysisService:
    """
    Улучшенный сервис анализа с интеграцией внешних API
    """
    
    def __init__(self, use_external_apis: bool = True):
        self.use_external_apis = use_external_apis
        # Простой in-memory кэш: ключ -> (истекает_в_мс, результат)
        self._cache: Dict[str, Any] = {}
        self._cache_ttl_seconds = 300
        # КРИТИЧНО: Очищаем старые данные с source: local_only при инициализации
        try:
            disk_cache.delete_by_source("local_only")
        except Exception as e:
            logger.warning(f"Failed to clean old cache entries: {e}")
        # YARA правила (простые сигнатуры)
        self._yara_rules = self._load_yara_rules()

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        # Сначала проверяем in-memory кэш
        item = self._cache.get(key)
        if item:
            expires_at_ms, value = item
            if time.time() * 1000 > expires_at_ms:
                self._cache.pop(key, None)
                return None
            # КРИТИЧНО: Проверяем что кэшированный результат валиден
            # Игнорируем результаты с safe: True если source не "combined" или "external_apis"
            # Также игнорируем любые результаты с source: "local_only" (старые данные)
            if value and isinstance(value, dict):
                cached_safe = value.get("safe")
                cached_source = value.get("source", "")
                if cached_source == "local_only":
                    logger.warning(f"Ignoring cached result with invalid source=local_only for {key}")
                    self._cache.pop(key, None)
                    disk_cache.delete(key)
                    return None
                elif cached_safe is True and cached_source not in ("combined", "external_apis"):
                    logger.warning(f"Ignoring cached safe=True result with source={cached_source} for {key}")
                    self._cache.pop(key, None)
                    disk_cache.delete(key)
                    return None
            return value
        
        # Затем проверяем диск-кэш
        disk_result = disk_cache.get(key)
        if disk_result:
            # КРИТИЧНО: Проверяем что кэшированный результат валиден
            # Игнорируем результаты с safe: True если source не "combined" или "external_apis"
            # Также игнорируем любые результаты с source: "local_only" (старые данные)
            if disk_result and isinstance(disk_result, dict):
                cached_safe = disk_result.get("safe")
                cached_source = disk_result.get("source", "")
                if cached_source == "local_only":
                    logger.warning(f"Ignoring cached result with invalid source=local_only for {key}")
                    disk_cache.delete(key)
                    return None
                elif cached_safe is True and cached_source not in ("combined", "external_apis"):
                    logger.warning(f"Ignoring cached safe=True result with source={cached_source} for {key}")
                    disk_cache.delete(key)
                    return None
            # Восстанавливаем в in-memory кэш
            self._cache_set(key, disk_result)
            return disk_result
        
        return None

    def _cache_set(self, key: str, value: Dict[str, Any]):
        expires_at_ms = int(time.time() * 1000 + self._cache_ttl_seconds * 1000)
        self._cache[key] = (expires_at_ms, value)
        # Также сохраняем в диск-кэш
        disk_cache.set(key, value, self._cache_ttl_seconds)

    def _load_yara_rules(self) -> List[Dict[str, Any]]:
        """Загружает простые YARA-подобные правила для детектирования"""
        return [
            {
                "name": "suspicious_pe_header",
                "pattern": b"MZ",
                "description": "Windows PE executable detected",
                "threat_score": 20
            },
            {
                "name": "powershell_script",
                "pattern": b"powershell",
                "description": "PowerShell script detected",
                "threat_score": 30
            },
            {
                "name": "base64_encoded",
                "pattern": b"base64",
                "description": "Base64 encoded content detected",
                "threat_score": 15
            },
            {
                "name": "suspicious_urls",
                "pattern": b"http://",
                "description": "HTTP URLs detected (potentially suspicious)",
                "threat_score": 10
            }
        ]

    def _scan_with_yara_rules(self, file_content: bytes) -> Dict[str, Any]:
        """Сканирование файла с помощью простых YARA-подобных правил"""
        detected_rules = []
        total_threat_score = 0
        
        for rule in self._yara_rules:
            if rule["pattern"] in file_content:
                detected_rules.append({
                    "rule_name": rule["name"],
                    "description": rule["description"],
                    "threat_score": rule["threat_score"]
                })
                total_threat_score += rule["threat_score"]
        
        return {
            "detected_rules": detected_rules,
            "total_threat_score": total_threat_score,
            "is_suspicious": total_threat_score > 50
        }
    
    async def analyze_url(self, url: str, use_external_apis: bool = None) -> Dict[str, Any]:
        """Улучшенный анализ URL с внешними API"""
        try:
            logger.info(f"🔍 Analyzing URL: {url}")
            # Нормализация URL
            try:
                from urllib.parse import urlsplit, urlunsplit
                parts = urlsplit(url)
                normalized_netloc = parts.netloc.lower()
                url = urlunsplit((parts.scheme, normalized_netloc, parts.path, parts.query, ""))
            except Exception:
                pass
            
            # КРИТИЧНО: Кэш - но НЕ возвращаем кэшированные результаты с safe: True
            # если они были созданы без проверки внешних API
            cache_key = f"url:{url}"
            cached = self._cache_get(cache_key)
            if cached is not None:
                # КРИТИЧНО: Если кэшированный результат имеет safe: True, но source не "combined" или "external_apis",
                # значит он был создан без проверки внешних API - игнорируем его
                # Также игнорируем любые результаты с source: "local_only" (старые данные)
                cached_safe = cached.get("safe")
                cached_source = cached.get("source", "")
                if cached_source == "local_only":
                    logger.warning(f"Ignoring cached result with invalid source=local_only for {url}, re-analyzing")
                    # Удаляем из кэша и продолжаем анализ
                    self._cache.pop(cache_key, None)
                    disk_cache.delete(cache_key)
                elif cached_safe is True and cached_source not in ("combined", "external_apis"):
                    logger.warning(f"Ignoring cached safe=True result with source={cached_source} for {url}, re-analyzing")
                    # Удаляем из кэша и продолжаем анализ
                    self._cache.pop(cache_key, None)
                    disk_cache.delete(cache_key)
                else:
                    return cached
            
            # 1. Проверка в локальной базе данных
            try:
                url_threat = db_manager.check_url(url)
                if url_threat:
                    return {
                        "safe": False,
                        "threat_type": url_threat["threat_type"],
                        "details": f"Local database: {url_threat['description']}",
                        "source": "local_db"
                    }
            except Exception as db_error:
                logger.warning(f"Database check failed: {db_error}")
            
            # 2. Проверка домена в локальной базе
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # КРИТИЧНО: НЕ используем кэш clean-доменов, так как это может пропускать опасные URL
            # Кэш clean-доменов отключен для более точной проверки
            # domain_cache_key = f"domain-clean:{domain}"
            # recently_clean = self._cache_get(domain_cache_key)
            # if recently_clean:
            #     result = {
            #         "safe": True,
            #         "threat_type": None,
            #         "details": "Domain recently verified as clean",
            #         "source": "cache",
            #         "confidence": 80
            #     }
            #     self._cache_set(cache_key, result)
            #     return result
            
            try:
                domain_threats = db_manager.check_domain(domain)
                if domain_threats:
                    return {
                        "safe": False,
                        "threat_type": domain_threats[0]["threat_type"],
                        "details": f"Domain {domain} has {len(domain_threats)} known threats",
                        "source": "local_db"
                    }
            except Exception as db_error:
                logger.warning(f"Database domain check failed: {db_error}")
            
            # 3. Проверка через внешние API (если включено)
            external_result = None
            should_use_external = use_external_apis if use_external_apis is not None else self.use_external_apis
            if should_use_external:
                try:
                    logger.info(f"🔍 Checking external APIs for: {url}")
                    external_result = await asyncio.wait_for(
                        external_api_manager.check_url_multiple_apis(url), 
                        timeout=8.0
                    )
                    logger.info(f"🔍 External API result: safe={external_result.get('safe')}, threat_type={external_result.get('threat_type')}")
                    
                    # КРИТИЧНО: Проверяем safe явно, не используя default True
                    external_safe = external_result.get("safe")
                    if external_safe is False or (external_safe is None and external_result.get("threat_type")):
                        logger.warning(f"🚨 External APIs detected threat for {url}: {external_result}")
                        try:
                            threat_type = external_result.get("threat_type", "malware")
                            if threat_type == "malicious":
                                threat_type = "malware"
                            db_manager.add_malicious_url(
                                url,
                                threat_type,
                                external_result.get("details", "Detected by external scan"),
                            )
                        except Exception as save_err:
                            logger.error(f"Failed to persist URL threat: {save_err}")
                        return {
                            **external_result,
                            "safe": False,  # Явно устанавливаем False
                            "source": "external_apis",
                            "confidence": external_result.get("confidence", 80)
                        }
                    elif external_safe is True:
                        logger.info(f"✅ External APIs found {url} to be safe")
                    else:
                        logger.warning(f"⚠️ External APIs returned unclear result for {url}: safe={external_safe}")
                except asyncio.TimeoutError:
                    logger.error(f"External API check timed out for {url}")
                except Exception as e:
                    logger.error(f"External API check failed: {e}", exc_info=True)
            
            # 4. Локальная эвристика
            heuristic_result = self._url_heuristic_analysis(url, domain)
            
            # 5. Объединяем результаты - ПРИОРИТЕТ ВНЕШНИМ API
            # КРИТИЧНО: Проверяем safe явно, не используя default True
            
            # КРИТИЧНО: Если внешние API не использовались (should_use_external = False), 
            # НЕ возвращаем результат из эвристики - всегда возвращаем safe: None
            if not should_use_external:
                logger.warning(f"External APIs disabled for {url}, returning unknown")
                result = {
                    "safe": None,
                    "threat_type": None,
                    "details": "External APIs disabled - unable to determine safety",
                    "source": "unknown",
                    "confidence": 0,
                    "external_scans": {}
                }
                self._cache_set(cache_key, result)
                return result
            
            # КРИТИЧНО: Если внешние API не вернули результат (external_result is None), 
            # НЕ возвращаем результат из эвристики - всегда возвращаем safe: None
            if not external_result:
                logger.warning(f"External APIs did not return result for {url}, returning unknown")
                result = {
                    "safe": None,
                    "threat_type": None,
                    "details": "External APIs did not return result - unable to determine safety",
                    "source": "unknown",
                    "confidence": 0,
                    "external_scans": {}
                }
                self._cache_set(cache_key, result)
                return result
            
            # КРИТИЧНО: Обрабатываем результат внешних API
            external_safe = external_result.get("safe")
            if external_safe is False or (external_safe is None and external_result.get("threat_type")):
                result = {
                    **external_result,
                    "safe": False,  # Явно устанавливаем False
                    "source": "external_apis",
                    "confidence": external_result.get("confidence", 80)
                }
                self._cache_set(cache_key, result)
                return result
            
            heuristic_safe = heuristic_result.get("safe")
            if heuristic_safe is False:
                result = {
                    **heuristic_result,
                    "source": "heuristic",
                    "external_scans": external_result.get("external_scans", {}) if external_result else {}
                }
                self._cache_set(cache_key, result)
                return result
            
            # КРИТИЧНО: Если внешние API вернули safe=True, считаем безопасным
            # НО только если есть результаты от всех включенных API
            if external_result and external_result.get("safe") is True:
                # Проверяем что все включенные API вернули результат
                external_scans = external_result.get("external_scans", {})
                enabled_apis = [name for name, enabled in external_api_manager.enabled_apis.items() if enabled]
                # Проверяем что есть результаты от всех включенных API
                if enabled_apis and all(api_name in external_scans for api_name in enabled_apis):
                    result = {
                        "safe": True,
                        "threat_type": None,
                        "details": "URL appears to be safe (local + external verification)",
                        "source": "combined",
                        "external_scans": external_scans,
                        "confidence": max(heuristic_result.get("confidence", 50), 
                                        external_result.get("confidence", 50))
                    }
                    self._cache_set(cache_key, result)
                    return result
                else:
                    # Не все API вернули результат - считаем неизвестным
                    logger.warning(f"Not all external APIs returned results for {url}, treating as unknown")
                    result = {
                        "safe": None,
                        "threat_type": None,
                        "details": "Unable to determine safety (not all external APIs returned results)",
                        "source": "unknown",
                        "confidence": 0,
                        "external_scans": external_scans
                    }
                    self._cache_set(cache_key, result)
                    return result
            
            # КРИТИЧНО: Если external_result есть, но safe не True и не False - это None или ошибка
            # В этом случае НЕ возвращаем результат из эвристики - возвращаем safe: None
            if external_result and external_result.get("safe") is None:
                logger.warning(f"External APIs returned None for {url}, treating as unknown")
                result = {
                    "safe": None,
                    "threat_type": None,
                    "details": "External APIs returned unclear result",
                    "source": "unknown",
                    "confidence": 0,
                    "external_scans": external_result.get("external_scans", {})
                }
                self._cache_set(cache_key, result)
                return result
            
            # КРИТИЧНО: Эвристика не должна возвращать safe=True без внешних API
            # Если внешние API не использовались или не вернули результат, считаем неизвестным
            if not external_result or external_result.get("safe") is None:
                # КРИТИЧНО: Если внешние API не использовались или не вернули результат, НЕ считаем безопасным
                # Всегда возвращаем safe: None (неизвестно), а НЕ safe: True
                result = {
                    "safe": None,  # КРИТИЧНО: НЕ True, а None!
                    "threat_type": None,
                    "details": "Unable to determine safety (external APIs unavailable or returned unclear result)",
                    "source": "unknown",
                    "confidence": 0,
                    "external_scans": external_result.get("external_scans", {}) if external_result else {}
                }
                self._cache_set(cache_key, result)
                return result
            
            # КРИТИЧНО: Если эвристика вернула safe=True И внешние API тоже safe=True, считаем безопасным
            # НО только если есть результаты от всех включенных API
            if heuristic_safe is True and external_result.get("safe") is True:
                external_scans = external_result.get("external_scans", {})
                enabled_apis = [name for name, enabled in external_api_manager.enabled_apis.items() if enabled]
                # Проверяем что есть результаты от всех включенных API
                if enabled_apis and all(api_name in external_scans for api_name in enabled_apis):
                    result = {
                        "safe": True,
                        "threat_type": None,
                        "details": "URL appears to be safe (local + external verification)",
                        "source": "combined",
                        "confidence": max(heuristic_result.get("confidence", 50), 
                                        external_result.get("confidence", 50)),
                        "external_scans": external_scans
                    }
                    self._cache_set(cache_key, result)
                    return result
                else:
                    # Не все API вернули результат - считаем неизвестным
                    logger.warning(f"Not all external APIs returned results for {url}, treating as unknown")
                    result = {
                        "safe": None,
                        "threat_type": None,
                        "details": "Unable to determine safety (not all external APIs returned results)",
                        "source": "unknown",
                        "confidence": 0,
                        "external_scans": external_scans
                    }
                    self._cache_set(cache_key, result)
                    return result
            
            # КРИТИЧНО: Если ничего не определено, возвращаем None (неизвестно)
            # НИКОГДА не возвращаем safe: True по умолчанию!
            result = {
                "safe": None,  # КРИТИЧНО: Всегда None, никогда True!
                "threat_type": None,
                "details": "Unable to determine safety - external API verification required",
                "source": "unknown",
                "confidence": 0,
                "external_scans": external_result.get("external_scans", {}) if external_result else {}
            }
            self._cache_set(cache_key, result)
            logger.warning(f"Final fallback for {url}: returning safe=None (unknown)")
            return result
                
        except Exception as e:
            logger.error(f"❌ URL analysis error: {e}", exc_info=True)
            return {
                "safe": None,  # Неизвестно при ошибке, не безопасно по умолчанию
                "threat_type": None,
                "details": f"Analysis error: {type(e).__name__}",
                "source": "error"
            }
    
    async def analyze_file_hash(self, file_hash: str, use_external_apis: bool = None) -> Dict[str, Any]:
        """Улучшенная проверка файла по хэшу с внешними API"""
        try:
            logger.info(f"🔍 Analyzing file hash with external APIs: {file_hash}")
            cache_key = f"hash:{file_hash}"
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached
            
            # 1. Локальная проверка с обработкой ошибок БД
            try:
                hash_threat = db_manager.check_hash(file_hash)
            except Exception as db_error:
                logger.warning(f"Database hash check failed for {file_hash}, retrying: {db_error}")
                import asyncio
                await asyncio.sleep(0.1)
                try:
                    hash_threat = db_manager.check_hash(file_hash)
                except Exception as retry_error:
                    logger.error(f"Database hash check failed after retry: {retry_error}")
                    hash_threat = None
            
            if hash_threat:
                return {
                    "safe": False,
                    "threat_type": hash_threat["threat_type"],
                    "details": hash_threat["description"],
                    "source": "local_db"
                }
            
            # 2. Проверка через VirusTotal
            should_use_external = use_external_apis if use_external_apis is not None else self.use_external_apis
            if should_use_external:
                try:
                    external_result = await external_api_manager.check_file_hash_multiple_apis(file_hash)
                    
                    if not external_result.get("safe", True):
                        # Сохраняем угрозу в локальную базу для будущих проверок
                        db_manager.add_malicious_hash(
                            file_hash, 
                            external_result.get("threat_type", "malware"),
                            f"Detected by external scan: {external_result.get('details', '')}"
                        )
                        
                        return {
                            **external_result,
                            "source": "external_apis"
                        }
                    
                    # Если файл чистый по внешним проверкам
                    result = {
                        "safe": True,
                        "threat_type": None,
                        "details": "File hash not found in any malware database",
                        "source": "external_apis",
                        "confidence": external_result.get("confidence", 90)
                    }
                    self._cache_set(cache_key, result)
                    return result
                    
                except Exception as e:
                    logger.error(f"External file hash check failed: {e}")
                    # Продолжаем с локальным результатом
            
            # КРИТИЧНО: Локальный результат если внешние API недоступны
            # НЕ устанавливаем safe: True - возвращаем None (неизвестно)
            result = {
                "safe": None,  # КРИТИЧНО: Неизвестно, а не безопасно!
                "threat_type": None,
                "details": "File hash not found in local malware database, but external API verification required",
                "source": "local_db_only"
            }
            self._cache_set(cache_key, result)
            return result
            
        except Exception as e:
            # КРИТИЧНО: Детальное логирование ошибок анализа файла
            import traceback
            error_trace = traceback.format_exc()
            error_type = type(e).__name__
            
            logger.error(
                f"❌ File hash analysis error for {file_hash}:\n"
                f"  Type: {error_type}\n"
                f"  Message: {str(e)}\n"
                f"  Traceback:\n{error_trace}",
                exc_info=True
            )
            
            # Возвращаем безопасный результат вместо падения
            return {
                "safe": None,  # None означает "неизвестно"
                "threat_type": "analysis_error",
                "details": f"Analysis temporarily unavailable: {error_type}",
                "source": "error"
            }
    
    # ... остальные методы остаются аналогичными, но с добавлением async/await ...

    async def analyze_uploaded_file(self, file_content: bytes, original_filename: str) -> Dict[str, Any]:
        """Анализ загруженного файла: вычисление SHA-256/MD5/SHA1, базовая типизация и проверка по базам/внешним API."""
        try:
            sanitized_name = security_validator.sanitize_filename(original_filename)
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            md5_hash = hashlib.md5(file_content).hexdigest()
            sha1_hash = hashlib.sha1(file_content).hexdigest()

            # Простейшая идентификация типа файла
            file_type = "unknown"
            if file_content.startswith(b"PK\x03\x04"):
                file_type = "zip_archive"
            elif file_content.startswith(b"MZ"):
                file_type = "win_pe"
            elif file_content.startswith(b"%PDF"):
                file_type = "pdf"
            elif file_content.startswith(b"#!/bin/bash") or file_content.startswith(b"#!/bin/sh"):
                file_type = "shell_script"
            elif b"powershell" in file_content.lower():
                file_type = "powershell_script"

            # YARA-сканирование
            yara_result = self._scan_with_yara_rules(file_content)

            # Проверка по sha256
            hash_result = await self.analyze_file_hash(sha256_hash)

            # Поведенческий анализ
            behavioral_score = self._behavioral_analysis(file_content, file_type)

            # Объединяем результаты
            final_safe = hash_result.get("safe", True) and not yara_result["is_suspicious"] and behavioral_score < 50
            final_threat_type = None
            if not hash_result.get("safe", True):
                final_threat_type = hash_result.get("threat_type", "malware")
            elif yara_result["is_suspicious"]:
                final_threat_type = "suspicious_content"
            elif behavioral_score >= 50:
                final_threat_type = "suspicious_behavior"

            # Создаем базовый результат
            base_result = {
                "filename": sanitized_name,
                "file_hash": sha256_hash,
                "md5": md5_hash,
                "sha1": sha1_hash,
                "file_type": file_type,
                "safe": final_safe,
                "threat_type": final_threat_type,
                "details": hash_result.get("details", ""),
                "source": "combined_analysis",
                "yara_detections": yara_result["detected_rules"],
                "behavioral_score": behavioral_score,
                "confidence": self._calculate_confidence(hash_result, yara_result, behavioral_score)
            }
            
            # Добавляем взвешенную оценку риска
            risk_assessment = self._calculate_risk_score(base_result)
            base_result.update(risk_assessment)
            
            return base_result
        except Exception as e:
            # КРИТИЧНО: Детальное логирование ошибок анализа загруженного файла
            import traceback
            error_trace = traceback.format_exc()
            error_type = type(e).__name__
            
            logger.error(
                f"❌ Uploaded file analysis error for {original_filename}:\n"
                f"  Type: {error_type}\n"
                f"  Message: {str(e)}\n"
                f"  Traceback:\n{error_trace}",
                exc_info=True
            )
            
            # Возвращаем безопасный результат вместо падения
            return {
                "filename": original_filename,
                "safe": None,  # None означает "неизвестно"
                "threat_type": "analysis_error",
                "details": f"Analysis temporarily unavailable: {error_type}",
                "source": "error",
            }

    def _url_heuristic_analysis(self, url: str, domain: str) -> Dict[str, Any]:
        """Смягчённая эвристика анализа URL для снижения ложных срабатываний"""
        threat_score = 0
        details = []
        
        # КРИТИЧНО: Проверка на известные опасные паттерны в URL
        url_lower = url.lower()
        dangerous_patterns = [
            ('eicar', 'malware', 'EICAR test file'),
            ('testfile', 'malware', 'Test malware file'),
            ('malware-test', 'malware', 'Malware test file'),
            ('virus-test', 'malware', 'Virus test file'),
            ('download-anti-malware-testfile', 'malware', 'Anti-malware test file download'),
        ]
        
        for pattern, threat_type, description in dangerous_patterns:
            if pattern in url_lower:
                logger.warning(f"🚨 Dangerous pattern detected in URL: {pattern} - {url}")
                return {
                    "safe": False,
                    "threat_type": threat_type,
                    "details": f"Known dangerous pattern detected: {description}",
                    "threat_score": 100,
                    "confidence": 95
                }
        
        # КРИТИЧНО: Защита от неопределенного домена
        if not domain or domain == "unknown":
            # Если домен неизвестен, считаем неизвестным (недостаточно данных)
            return {
                "safe": None,  # Неизвестно, не безопасно по умолчанию
                "threat_type": None,
                "details": "Domain information unavailable",
                "threat_score": 0,
                "confidence": 0
            }

        # IP-адрес вместо домена — сильный сигнал, но редкий в нормальном серфинге
        try:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                threat_score += 50
                details.append("Uses IP address instead of domain")
        except Exception:
            pass  # Игнорируем ошибки проверки IP

        # Очень длинные URL — учитываем только экстремальные случаи
        if len(url) > 300:
            threat_score += 20
            details.append("URL is extremely long")
        elif len(url) > 200:
            threat_score += 10
            details.append("URL is very long")

        # Много поддоменов — повышаем пороги
        try:
            subdomain_count = len(domain.split('.'))
            if subdomain_count > 6:
                threat_score += 20
                details.append("Too many subdomains (>6)")
            elif subdomain_count > 4:
                threat_score += 10
                details.append("Many subdomains (>4)")
        except Exception:
            pass  # Игнорируем ошибки подсчета поддоменов

        # Дефисы в домене больше не считаем признаком сами по себе

        # Подозрительные TLD — оставляем как слабый сигнал
        try:
            suspicious_tlds = {"zip", "review", "click", "xyz", "top", "work"}
            tld = domain.split('.')[-1] if '.' in domain else ''
            if tld in suspicious_tlds:
                threat_score += 10
                details.append(f"Suspicious TLD: .{tld}")
        except Exception:
            pass  # Игнорируем ошибки определения TLD

        # Наличие '@' в URL — сильный сигнал
        if '@' in url:
            threat_score += 30
            details.append("Contains '@' symbol in URL")

        # Количество параметров — учитываем только очень большое число
        try:
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(url).query)
            if len(q) > 30:
                threat_score += 20
                details.append("Too many query parameters (>30)")
            elif len(q) > 20:
                threat_score += 10
                details.append("Many query parameters (>20)")
        except Exception:
            pass
        
        # Гораздо более высокий порог срабатывания, чтобы не метить обычные сайты
        try:
            if threat_score >= 70:
                return {
                    "safe": False,
                    "threat_type": "suspicious",
                    "details": f"Heuristic detection: {', '.join(details) if details else 'Multiple suspicious indicators'}",
                    "threat_score": threat_score,
                    "confidence": min(95, 50 + threat_score)  # Higher confidence for higher threat scores
                }

            # КРИТИЧНО: Эвристика не должна возвращать safe: True без внешних API
            # Возвращаем None (неизвестно), чтобы требовать проверку внешними API
            return {
                "safe": None,  # Неизвестно, не безопасно по умолчанию
                "threat_type": None,
                "details": "Heuristic analysis passed, but external API verification required",
                "threat_score": threat_score,
                "confidence": 0  # Низкая уверенность без внешних API
            }
        except Exception as e:
            logger.error(f"Error in heuristic analysis result generation: {e}", exc_info=True)
            # Fallback: считаем неизвестным при ошибке
            return {
                "safe": None,  # Неизвестно, не безопасно по умолчанию
                "threat_type": None,
                "details": "Heuristic analysis completed with warnings",
                "threat_score": 0,
                "confidence": 50
            }

    def _behavioral_analysis(self, file_content: bytes, file_type: str) -> int:
        """Поведенческий анализ файла"""
        score = 0
        
        # Анализ размера файла
        if len(file_content) > 50 * 1024 * 1024:  # > 50MB
            score += 20
        elif len(file_content) < 100:  # < 100 bytes
            score += 15
        
        # Анализ энтропии (простая проверка)
        if self._calculate_entropy(file_content) > 7.5:
            score += 25  # Высокая энтропия может указывать на шифрование/упаковку
        
        # Анализ строк
        suspicious_strings = [
            b"cmd.exe", b"powershell", b"reg add", b"net user", 
            b"schtasks", b"wmic", b"rundll32", b"certutil"
        ]
        for suspicious in suspicious_strings:
            if suspicious in file_content.lower():
                score += 10
        
        # Анализ по типу файла
        if file_type == "win_pe":
            score += 5  # PE файлы потенциально опасны
        elif file_type == "powershell_script":
            score += 20  # PowerShell скрипты часто используются для атак
        elif file_type == "shell_script":
            score += 15  # Shell скрипты могут быть опасны
        
        return min(score, 100)  # Максимум 100 баллов

    def _calculate_entropy(self, data: bytes) -> float:
        """Вычисление энтропии данных"""
        if not data:
            return 0.0
        
        # Подсчет частоты байтов
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Вычисление энтропии: -sum(p * log2(p))
        import math
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy

    def _calculate_confidence(self, hash_result: Dict[str, Any], yara_result: Dict[str, Any], behavioral_score: int) -> int:
        """Вычисление общей уверенности в результате"""
        confidence_scores = []
        
        # Уверенность от хэш-проверки
        if hash_result.get("safe", True):
            confidence_scores.append(90)
        else:
            confidence_scores.append(95)  # Высокая уверенность в детектировании по хэшу
        
        # Уверенность от YARA
        if yara_result["is_suspicious"]:
            confidence_scores.append(80)
        else:
            confidence_scores.append(70)
        
        # Уверенность от поведенческого анализа
        if behavioral_score >= 50:
            confidence_scores.append(75)
        else:
            confidence_scores.append(85)
        
        return sum(confidence_scores) // len(confidence_scores)

    def _calculate_risk_score(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Взвешенная оценка риска с объяснениями"""
        risk_factors = []
        total_score = 0
        
        # Фактор 1: Хэш-проверка (вес 40%)
        if not results.get("safe", True):
            hash_score = 80
            risk_factors.append({
                "factor": "hash_database",
                "weight": 40,
                "score": hash_score,
                "description": "File hash found in malware database"
            })
            total_score += hash_score * 0.4
        
        # Фактор 2: YARA детекции (вес 30%)
        yara_detections = results.get("yara_detections", [])
        if yara_detections:
            yara_score = min(90, len(yara_detections) * 20)
            risk_factors.append({
                "factor": "yara_signatures",
                "weight": 30,
                "score": yara_score,
                "description": f"Detected {len(yara_detections)} suspicious patterns"
            })
            total_score += yara_score * 0.3
        
        # Фактор 3: Поведенческий анализ (вес 20%)
        behavioral_score = results.get("behavioral_score", 0)
        if behavioral_score > 0:
            risk_factors.append({
                "factor": "behavioral_analysis",
                "weight": 20,
                "score": behavioral_score,
                "description": f"Behavioral analysis score: {behavioral_score}"
            })
            total_score += behavioral_score * 0.2
        
        # Фактор 4: Тип файла (вес 10%)
        file_type = results.get("file_type", "unknown")
        type_scores = {
            "win_pe": 60,
            "powershell_script": 70,
            "shell_script": 50,
            "zip_archive": 30,
            "pdf": 20,
            "unknown": 10
        }
        type_score = type_scores.get(file_type, 10)
        risk_factors.append({
            "factor": "file_type",
            "weight": 10,
            "score": type_score,
            "description": f"File type: {file_type}"
        })
        total_score += type_score * 0.1
        
        # Определяем уровень риска
        if total_score >= 80:
            risk_level = "critical"
        elif total_score >= 60:
            risk_level = "high"
        elif total_score >= 40:
            risk_level = "medium"
        elif total_score >= 20:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        return {
            "risk_score": int(total_score),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "explanation": self._generate_risk_explanation(risk_level, risk_factors)
        }
    
    def _generate_risk_explanation(self, risk_level: str, risk_factors: List[Dict[str, Any]]) -> str:
        """Генерация объяснения уровня риска"""
        explanations = {
            "critical": "Критический риск: файл содержит известные вредоносные сигнатуры или демонстрирует крайне подозрительное поведение",
            "high": "Высокий риск: файл имеет множественные признаки вредоносности",
            "medium": "Средний риск: файл демонстрирует некоторые подозрительные характеристики",
            "low": "Низкий риск: файл имеет минимальные подозрительные признаки",
            "minimal": "Минимальный риск: файл не демонстрирует признаков вредоносности"
        }
        
        base_explanation = explanations.get(risk_level, "Неизвестный уровень риска")
        
        if risk_factors:
            factor_descriptions = [f["description"] for f in risk_factors if f["score"] > 20]
            if factor_descriptions:
                base_explanation += f". Основные факторы риска: {', '.join(factor_descriptions)}"
        
        return base_explanation

# Создаем экземпляр сервиса с включенными внешними API
analysis_service = AnalysisService(use_external_apis=True)