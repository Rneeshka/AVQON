# app/ssl_info.py
"""Получение TLS-сертификата хоста (issuer, valid from/to). Без внешнего API."""
import ssl
import socket
import asyncio
import time
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from app.logger import logger

# Кэш: hostname -> (dict с ssl_*, timestamp); TTL 1 час
_ssl_cache: Dict[str, tuple[Dict[str, Any], float]] = {}
_SSL_CACHE_TTL = 3600.0


def _get_peer_cert_sync(hostname: str, port: int = 443, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Синхронно получить данные сертификата (issuer, notBefore, notAfter)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                issuer = dict(x[0] for x in cert.get("issuer", []))
                issuer_str = issuer.get("organizationName") or issuer.get("commonName") or ""
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                # Парсим даты в формате "Jan  1 00:00:00 2024 GMT"
                def parse_ssl_date(s: Optional[str]) -> Optional[str]:
                    if not s:
                        return None
                    try:
                        dt = datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
                        return dt.replace(tzinfo=timezone.utc).isoformat()
                    except ValueError:
                        return s
                return {
                    "ssl_issuer": issuer_str or None,
                    "ssl_valid_from": parse_ssl_date(not_before),
                    "ssl_valid_to": parse_ssl_date(not_after),
                }
    except ssl.SSLError as e:
        logger.debug("SSL error for %s: %s", hostname, e)
        return None
    except (socket.timeout, socket.gaierror, OSError) as e:
        logger.debug("Connection error for %s: %s", hostname, e)
        return None
    except Exception as e:
        logger.warning("TLS fetch error for %s: %s", hostname, e)
        return None


async def get_ssl_info(hostname: str, port: int = 443, use_cache: bool = True) -> Dict[str, Any]:
    """
    Асинхронно получить issuer и даты сертификата для hostname.
    Возвращает dict с ключами ssl_issuer, ssl_valid_from, ssl_valid_to (значения могут быть None).
    """
    if not hostname or not hostname.strip():
        return {"ssl_issuer": None, "ssl_valid_from": None, "ssl_valid_to": None}
    hostname = hostname.strip().lower()
    now = time.time()
    if use_cache:
        cached = _ssl_cache.get(hostname)
        if cached:
            data, ts = cached
            if now - ts < _SSL_CACHE_TTL:
                return data.copy()
    result = await asyncio.to_thread(_get_peer_cert_sync, hostname, port)
    if result:
        _ssl_cache[hostname] = (result, now)
        return result.copy()
    out = {"ssl_issuer": None, "ssl_valid_from": None, "ssl_valid_to": None}
    _ssl_cache[hostname] = (out, now)
    return out
