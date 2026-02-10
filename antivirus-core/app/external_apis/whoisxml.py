# app/external_apis/whoisxml.py
"""WhoisXML API client for domain WHOIS / domain age."""
import aiohttp
import asyncio
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.logger import logger
from app.config import config


# In-memory cache: domain -> (domain_age_days, timestamp); TTL 24 hours
_whois_cache: Dict[str, tuple[Optional[int], float]] = {}
_WHOIS_CACHE_TTL_SEC = 24 * 3600


def _parse_creation_date(data: Dict[str, Any]) -> Optional[datetime]:
    """Извлечь дату создания домена из ответа WhoisXML (разные форматы)."""
    if not data:
        return None
    # Вариант: WhoisRecord.registryData.domain.created или creationDate
    try:
        rec = data.get("WhoisRecord") or data.get("whoisRecord") or data
        reg = rec.get("registryData") or {}
        domain = reg.get("domain") or {}
        created_str = (
            domain.get("created")
            or domain.get("creationDate")
            or rec.get("creationDate")
            or rec.get("created")
            or data.get("creationDate")
        )
        if not created_str:
            return None
        s = created_str.strip()
        # Форматы: "2020-01-15T00:00:00Z", "2020-01-15", "15-Jan-2020"
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%d-%b-%Y"):
            try:
                if "%f" in fmt:
                    return datetime.strptime(s[:26], fmt)
                if "T" in fmt:
                    return datetime.strptime(s[:19], fmt)
                return datetime.strptime(s[:10], fmt)
            except ValueError:
                continue
        if "T" in s:
            s = s.split("T")[0]
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            pass
    except Exception as e:
        logger.debug("WhoisXML parse creation date: %s", e)
    return None


def _domain_age_days(created: datetime) -> int:
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - created
    return max(0, delta.days)


class WhoisXMLClient:
    """Клиент WhoisXML WHOIS API для возраста домена."""

    def __init__(self):
        self.base_url = config.WHOISXML_WHOIS_API
        self.api_key = (config.WHOISXML_API_KEY or "").strip()
        self.session: Optional[aiohttp.ClientSession] = None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and "your_" not in self.api_key.lower())

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=min(getattr(config, "REQUEST_TIMEOUT", 30), 15), sock_connect=5, sock_read=10)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def get_domain_age_days(self, domain: str) -> Optional[int]:
        """Возвращает возраст домена в днях или None при ошибке/отсутствии ключа."""
        if not domain or not self.enabled:
            return None
        domain = domain.lower().strip()
        now = time.time()
        cached = _whois_cache.get(domain)
        if cached is not None:
            age, ts = cached
            if now - ts < _WHOIS_CACHE_TTL_SEC:
                return age
        if not self.session:
            return None
        try:
            params = {
                "domainName": domain,
                "apiKey": self.api_key,
                "outputFormat": "JSON",
            }
            async with self.session.get(self.base_url, params=params) as resp:
                if resp.status != 200:
                    logger.warning("WhoisXML API status %s for %s", resp.status, domain)
                    _whois_cache[domain] = (None, now)
                    return None
                data = await resp.json()
        except asyncio.TimeoutError:
            logger.warning("WhoisXML API timeout for %s", domain)
            return None
        except Exception as e:
            logger.warning("WhoisXML API error for %s: %s", domain, e)
            _whois_cache[domain] = (None, now)
            return None
        created = _parse_creation_date(data)
        if created is None:
            _whois_cache[domain] = (None, now)
            return None
        age = _domain_age_days(created)
        _whois_cache[domain] = (age, now)
        return age
