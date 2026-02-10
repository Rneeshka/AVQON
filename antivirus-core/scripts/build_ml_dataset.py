#!/usr/bin/env python3
"""
Сбор датасета для обучения URL ML: фишинг из PhishTank + безопасные URL из списка.
Результат: CSV с колонками url, label (0=safe, 1=phishing).

Использование:
  pip install requests
  python scripts/build_ml_dataset.py --output scripts/url_ml_train.csv
  python scripts/build_ml_dataset.py --output train.csv --safe-urls my_safe_list.txt
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from urllib.parse import urlparse

PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"
OPENPHISH_URL = "https://openphish.com/feed.txt"

# Известные безопасные домены и пути (для баланса датасета)
SAFE_URLS = [
    "https://www.google.com/search?q=test",
    "https://github.com/",
    "https://www.youtube.com/",
    "https://docs.python.org/",
    "https://en.wikipedia.org/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.amazon.com/",
    "https://www.reddit.com/",
    "https://twitter.com/",
    "https://linkedin.com/",
    "https://cloudflare.com/",
    "https://www.netflix.com/",
    "https://spotify.com/",
    "https://discord.com/",
    "https://medium.com/",
    "https://www.bbc.com/",
    "https://stackoverflow.com/",
    "https://www.mozilla.org/",
    "https://paypal.com/",
    "https://accounts.google.com/",
    "https://github.com/login",
    "https://login.live.com/",
    "https://www.dropbox.com/",
    "https://www.office.com/",
    "https://www.amazon.com/",
    "https://api.github.com/",
    "https://pypi.org/",
    "https://npmjs.com/",
    "https://developer.mozilla.org/",
    "https://www.w3.org/",
    "https://git-scm.com/",
    "https://code.visualstudio.com/",
    "https://dashboard.heroku.com/",
    "https://www.digitalocean.com/",
    "https://aws.amazon.com/",
    "https://portal.azure.com",
    "https://console.cloud.google.com",
    "https://vercel.com/",
    "https://www.notion.so/",
    "https://trello.com/",
    "https://slack.com/",
    "https://zoom.us/",
    "https://meet.google.com",
    "https://calendar.google.com",
    "https://drive.google.com",
    "https://mail.google.com",
    "https://maps.google.com",
    "https://translate.google.com",
    "https://docs.google.com",
    "https://myaccount.google.com",
    "https://support.google.com",
    "https://www.facebook.com/",
    "https://www.instagram.com/",
    "https://web.telegram.org",
    "https://open.spotify.com/",
    "https://www.twitch.tv/",
    "https://www.ebay.com/",
    "https://www.booking.com/",
    "https://www.airbnb.com/",
    "https://duckduckgo.com/",
    "https://www.bing.com/",
    "https://brave.com/",
    "https://policies.google.com/",
    "https://help.github.com/",
    "https://docs.microsoft.com/",
    "https://support.apple.com/",
    "https://support.microsoft.com/",
]


def fetch_phishtank(max_urls: int = 5000) -> list[str]:
    """Скачать URL фишинга из PhishTank (публичный фид)."""
    try:
        import urllib.request
        req = urllib.request.Request(PHISHTANK_URL, headers={"User-Agent": "AVQON-ML-Dataset/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"Ошибка загрузки PhishTank: {e}", file=sys.stderr)
        return []
    try:
        import json
        js = json.loads(data)
    except Exception as e:
        print(f"Ошибка парсинга JSON: {e}", file=sys.stderr)
        return []
    if not isinstance(js, list):
        print("Неожиданный формат PhishTank", file=sys.stderr)
        return []
    urls = []
    seen = set()
    for i, entry in enumerate(js):
        if i >= max_urls:
            break
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or entry.get("phish_detail_url")
        if not url or not url.startswith(("http://", "https://")):
            continue
        url = url.strip()
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def fetch_openphish(max_urls: int = 5000) -> list[str]:
    """Скачать фишинговые URL из OpenPhish (публичный TXT‑фид)."""
    try:
        import urllib.request

        req = urllib.request.Request(OPENPHISH_URL, headers={"User-Agent": "AVQON-ML-Dataset/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"Ошибка загрузки OpenPhish: {e}", file=sys.stderr)
        return []
    urls = []
    seen = set()
    for line in text.splitlines():
        url = line.strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= max_urls:
            break
    return urls


def load_safe_urls(path: Path | None) -> list[str]:
    """Загрузить безопасные URL из файла (по одному URL на строку) или вернуть встроенный список."""
    if path and path.is_file():
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [line.strip() for line in f if line.strip() and (line.startswith("http://") or line.startswith("https://"))]
    return list(SAFE_URLS)


def main():
    parser = argparse.ArgumentParser(description="Build URL ML dataset from PhishTank + safe URLs")
    parser.add_argument("--output", default="scripts/url_ml_train.csv", help="Output CSV path")
    parser.add_argument("--safe-urls", type=Path, help="File with safe URLs (one per line)")
    parser.add_argument("--max-phish", type=int, default=5000, help="Max phishing URLs from PhishTank")
    parser.add_argument("--max-openphish", type=int, default=2000, help="Max phishing URLs from OpenPhish")
    args = parser.parse_args()

    print("Загрузка фишинговых URL из PhishTank...")
    phish_urls = fetch_phishtank(max_urls=args.max_phish)
    print(f"  Загружено из PhishTank: {len(phish_urls)}")

    print("Загрузка фишинговых URL из OpenPhish...")
    openphish_urls = fetch_openphish(max_urls=args.max_openphish)
    print(f"  Загружено из OpenPhish: {len(openphish_urls)}")

    safe_urls = load_safe_urls(args.safe_urls)
    print(f"Безопасных URL: {len(safe_urls)}")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        for u in safe_urls:
            w.writerow([u, 0])
        for u in phish_urls:
            w.writerow([u, 1])
        for u in openphish_urls:
            w.writerow([u, 1])
    print(
        f"Сохранено: {out_path} ({len(safe_urls)} safe, "
        f"{len(phish_urls)} phishing PhishTank, {len(openphish_urls)} phishing OpenPhish)"
    )


if __name__ == "__main__":
    main()
