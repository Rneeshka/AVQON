# app/external_apis/urlscan.py
"""URLScan.io API client: поиск по домену/URL и вердикт (опционально по API-ключу)."""
import aiohttp
import asyncio
from urllib.parse import urlparse
from typing import Dict, Any, Optional

from app.logger import logger
from app.config import config


class URLScanClient:
    """Клиент URLScan.io: поиск существующих сканов по домену/URL."""

    def __init__(self):
        self.base_url = (config.URLSCAN_API or "https://urlscan.io/api/v1").rstrip("/")
        self.api_key = (getattr(config, "URLSCAN_API_KEY", None) or "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and "your_" not in self.api_key.lower())

    def _get_headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["API-Key"] = self.api_key
        return h

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15, sock_connect=5, sock_read=10),
            headers=self._get_headers(),
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if getattr(self, "_session", None):
            await self._session.close()

    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Поиск по домену URL в urlscan.io. Если найден скан с вердиктом malicious — возвращаем unsafe.
        Без API-ключа лимиты жёсткие; с ключом — включается в общую проверку.
        """
        if not url or not url.startswith(("http://", "https://")):
            return None
        try:
            parsed = urlparse(url)
            domain = (parsed.netloc or "").lower()
            if not domain:
                return None
        except Exception:
            return None

        session = getattr(self, "_session", None)
        if not session:
            return None

        # Поиск по домену за последние 7 дней (ограничиваем объём)
        q = f"domain:{domain}"
        try:
            async with session.get(
                f"{self.base_url}/search/",
                params={"q": q, "size": 10},
            ) as resp:
                if resp.status == 429:
                    logger.warning("URLScan rate limit (429)")
                    return {"safe": None, "external_scan": "urlscan", "details": "Rate limited", "confidence": 0}
                if resp.status != 200:
                    logger.warning("URLScan search status %s", resp.status)
                    return None
                data = await resp.json()
        except asyncio.TimeoutError:
            logger.warning("URLScan search timeout")
            return {"safe": None, "external_scan": "urlscan", "details": "Timeout", "confidence": 0}
        except Exception as e:
            logger.warning("URLScan search error: %s", e)
            return None

        return self._parse_search_result(data, url, domain)

    def _parse_search_result(
        self, data: Dict[str, Any], original_url: str, domain: str
    ) -> Dict[str, Any]:
        """Парсинг ответа Search API: ищем наш URL/домен и смотрим вердикты."""
        results = data.get("results") or []
        for item in results:
            page = item.get("page") or {}
            item_url = (page.get("url") or "").strip()
            item_domain = (page.get("domain") or "").lower()
            # Совпадение по домену или по URL
            if item_domain != domain and item_url != original_url:
                continue
            # Вердикт: в поиске может быть verdicts или task.verdicts
            verdicts = item.get("verdicts") or item.get("task", {}) or {}
            overall = verdicts.get("overall") or {}
            if isinstance(overall, dict):
                malicious = overall.get("malicious") is True
                score = overall.get("score") or 0
            else:
                malicious = False
                score = 0
            if malicious or (isinstance(score, (int, float)) and score > 0):
                return {
                    "safe": False,
                    "threat_type": "malicious",
                    "details": "URLScan.io: malicious or suspicious scan result",
                    "external_scan": "urlscan",
                    "confidence": 75,
                }
        # Ни одного вредоносного результата по этому домену/URL
        return {
            "safe": True,
            "external_scan": "urlscan",
            "details": "URLScan.io: no malicious scans found",
            "confidence": 65,
        }
