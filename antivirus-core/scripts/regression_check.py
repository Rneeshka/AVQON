#!/usr/bin/env python3
"""
Регрессионная проверка ключевых улучшений AVQON backend.

ВАЖНО: проверяем по WebSocket (`/ws`), а не по /check/url,
потому что только WS-ответ `analysis_result` содержит
полный payload с domain_metadata, meta.heuristics, threat_intel и т.п.

Что проверяем:
- WHOIS / возраст домена: domain_metadata.domain_age_days
- SSL/TLS: domain_metadata.ssl_issuer / ssl_valid_from / ssl_valid_to
- ML‑модель: domain_metadata.ml_score / ml_label
- TI + эвристика: meta.heuristics.riskScore / riskLevel / factors, meta.threat_intel.*

Скрипт НИЧЕГО не меняет в БД, только читает ответы.

Пример запуска:
  cd antivirus-core
  python3 scripts/regression_check.py --api-base http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from textwrap import shorten
from typing import Any, Dict, List
from urllib.parse import urlparse

try:
    import websockets  # type: ignore
except ImportError:
    print("Установи websockets: pip install websockets", file=sys.stderr)
    sys.exit(1)


DEFAULT_TEST_URLS: List[str] = [
    # Явно безопасные / крупные
    "https://www.google.com/",
    "https://github.com/",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://store.steampowered.com/",
    "https://www.netflix.com/",
    "https://spotify.com/",
    "https://discord.com/",
    "https://ru.wikipedia.org/wiki/Monster_Hunter",
    "https://monsterhunternow.com/",
    # Подозрительные / фишинговые по паттернам
    "http://evil-phishing-site.xyz/login/verify/account",
    "https://secure-login-bank.xyz/billing",
    "https://paypa1-secure-login.com/verify",
    "https://account-update.secure-service.com/signin",
    "https://login.secure-account12345.xyz/verify",
]


def hr(title: str | None = None) -> None:
    line = "=" * 80
    if not title:
        print(line)
        return
    print("\n" + line)
    print(title)
    print(line)


def s(text: str | None, length: int = 120) -> str:
    if not text:
        return ""
    return shorten(text.strip(), width=length, placeholder="...")


def describe_domain_meta(meta: Dict[str, Any] | None) -> str:
    if not meta:
        return "нет domain_metadata"
    parts: List[str] = []
    d = meta.get("domain")
    if d:
        parts.append(f"domain={d}")
    tld = meta.get("tld")
    if tld:
        parts.append(f"tld={tld}")
    if meta.get("subdomain_depth") is not None:
        parts.append(f"subdomains={meta['subdomain_depth']}")
    if meta.get("domain_age_days") is not None:
        parts.append(f"age={meta['domain_age_days']} дней")
    if meta.get("ssl_issuer"):
        parts.append(f"ssl_issuer={s(meta['ssl_issuer'], 60)}")
    if meta.get("ssl_valid_from") or meta.get("ssl_valid_to"):
        parts.append(
            f"ssl_valid={meta.get('ssl_valid_from', '?')} → {meta.get('ssl_valid_to', '?')}"
        )
    if meta.get("ml_score") is not None:
        parts.append(f"ml_score={meta['ml_score']:.3f}")
    if meta.get("ml_label"):
        parts.append(f"ml_label={meta['ml_label']}")
    src = meta.get("source")
    if src:
        parts.append(f"src={src}")
    return ", ".join(parts) if parts else "поля не заполнены"


def describe_heuristics(meta: Dict[str, Any] | None) -> str:
    if not meta:
        return "нет meta"
    heur = meta.get("heuristics")
    if not heur:
        return "нет meta.heuristics"
    score = heur.get("riskScore")
    lvl = heur.get("riskLevel")
    factors = heur.get("factors") or []
    txt = f"riskScore={score}, riskLevel={lvl}"
    if factors:
        top = "; ".join(factors[:3])
        if len(factors) > 3:
            top += f"; ... (+{len(factors) - 3} факторов)"
        txt += f"; factors=[{s(top, 160)}]"
    return txt


def describe_ti(meta: Dict[str, Any] | None) -> str:
    if not meta:
        return "нет meta"
    ti = meta.get("threat_intel")
    if not ti:
        return "нет meta.threat_intel"
    lines: List[str] = []
    if ti.get("blacklistHit"):
        sources: List[str] = []
        for h in ti.get("hits") or []:
            if h and h.get("source"):
                sources.append(h["source"])
        if sources:
            lines.append("blacklistHit: " + ", ".join(sorted(set(sources))))
        else:
            lines.append("blacklistHit: True")
    crowd = ti.get("crowd")
    if crowd and crowd.get("reports"):
        lines.append(
            f"crowd: reports={crowd.get('reports')}, score={crowd.get('score')}, recent24h={crowd.get('recent_reports_24h')}"
        )
    ipr = ti.get("ipReputation")
    if ipr and ipr.get("abuseConfidenceScore") is not None:
        lines.append(
            f"ipReputation: ip={ipr.get('ip')}, abuse={ipr.get('abuseConfidenceScore')}%, usage={ipr.get('usageType')}"
        )
    if not lines:
        return "нет значимых TI‑сигналов"
    return " | ".join(lines)


async def ws_analyze_url(ws_url: str, url: str, context: str = "link_check") -> Dict[str, Any]:
    """
    Отправляет analyze_url по WebSocket и ждёт analysis_result.
    Возвращает payload (dict), либо dict с ошибкой.
    """
    req_id = f"reg-{hash(url) & 0xFFFFFFFF:x}"
    payload = {
        "type": "analyze_url",
        "requestId": req_id,
        "payload": {
            "url": url,
            "context": context,
            "use_external_apis": True,
        },
    }
    try:
        async with websockets.connect(ws_url, max_size=2**23) as ws:  # ~8MB
            await ws.send(json.dumps(payload))
            async for msg in ws:
                try:
                    data = json.loads(msg)
                except Exception:
                    continue
                if data.get("type") == "analysis_result" and data.get("requestId") == req_id:
                    return data.get("payload") or {}
                if data.get("type") == "error":
                    # Ошибка по нашему запросу
                    if data.get("requestId") == req_id:
                        return {"safe": None, "threat_type": None, "details": f"WS error: {data.get('detail')}"}
    except Exception as e:
        return {"safe": None, "threat_type": None, "details": f"WS connect/send error: {e}"}
    return {"safe": None, "threat_type": None, "details": "No analysis_result received"}


async def amain() -> None:
    parser = argparse.ArgumentParser(
        description="Регрессионная проверка улучшений AVQON через /check/url"
    )
    parser.add_argument(
        "--api-base",
        default="http://127.0.0.1:8000",
        help="Базовый URL API (используется только для вычисления ws://host:port/ws)",
    )
    parser.add_argument(
        "--urls-file",
        help="Файл со списком URL (по одному на строку). Если не задан, используется встроенный набор.",
    )
    args = parser.parse_args()

    # Строим WS URL из api-base
    parsed = urlparse(args.api_base)
    scheme = "ws" if parsed.scheme in ("http", "") else "wss"
    netloc = parsed.netloc or (parsed.hostname or "127.0.0.1")
    if parsed.port:
        netloc = f"{parsed.hostname}:{parsed.port}"
    ws_url = f"{scheme}://{netloc}/ws"

    if args.urls_file:
        try:
            with open(args.urls_file, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Не удалось прочитать {args.urls_file}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        urls = DEFAULT_TEST_URLS

    hr(f"WS_URL = {ws_url}")
    print("Всего URL для проверки:", len(urls))

    for url in urls:
        hr(f"URL: {url}")
        data = await ws_analyze_url(ws_url, url, context="link_check")

        safe = data.get("safe")
        threat_type = data.get("threat_type")
        source = data.get("source")
        confidence = data.get("confidence")

        print(f"safe={safe}, threat_type={threat_type}, source={source}, confidence={confidence}")

        det = s(data.get("details") or "", 180)
        if det:
            print("details:", det)

        domain_meta = data.get("domain_metadata") or {}
        print("domain_metadata:", describe_domain_meta(domain_meta))

        meta = data.get("meta") or {}
        print("heuristics:", describe_heuristics(meta))
        print("TI:", describe_ti(meta))


if __name__ == "__main__":
    asyncio.run(amain())