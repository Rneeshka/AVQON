#!/usr/bin/env python3
"""
Экспорт датасета для обучения URL ML из текущей БД AVQON.

Формат вывода: CSV с колонками url,label
  - label=1 — вредоносные/подозрительные (malicious_urls + cached_blacklist)
  - label=0 — безопасные (cached_whitelist)

Использование (на том же сервере, где крутится antivirus-core):

  cd antivirus-core
  python3 scripts/export_url_ml_from_db.py --output scripts/url_ml_from_db.csv
  python3 scripts/train_url_ml.py --data scripts/url_ml_from_db.csv --output app/data/url_ml_model.json
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

# Добавляем app/ в sys.path, чтобы импортировать db_manager
ROOT = Path(__file__).resolve().parent.parent
APP_DIR = ROOT / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

def _load_db_manager():
    """
    Импортируем db_manager ПОСЛЕ того, как выставили DATABASE_URL (если задан).
    """
    try:
        from database import db_manager  # type: ignore
        return db_manager
    except Exception as e:  # pragma: no cover - утилитарный скрипт
        print(f"Не удалось импортировать db_manager: {e}", file=sys.stderr)
        sys.exit(1)


def collect_malicious_urls(limit: int | None = None) -> set[str]:
    """
    Собирает URL из malicious_urls и cached_blacklist как позитивный класс (label=1).
    """
    urls: set[str] = set()
    try:
        with db_manager._get_connection() as conn:  # type: ignore[attr-defined, name-defined]
            cur = conn.cursor()
            # 1) malicious_urls (основной источник истины)
            q = "SELECT url FROM malicious_urls"
            if limit:
                q += " LIMIT %s"
                cur.execute(q, (limit,))
            else:
                cur.execute(q)
            for row in cur.fetchall() or []:
                u = (row[0] or "").strip()
                if u:
                    urls.add(u)

            # 2) cached_blacklist (локальный blacklist)
            q = "SELECT url FROM cached_blacklist"
            if limit:
                q += " LIMIT %s"
                cur.execute(q, (limit,))
            else:
                cur.execute(q)
            for row in cur.fetchall() or []:
                u = (row[0] or "").strip()
                if u:
                    urls.add(u)
    except Exception as e:  # pragma: no cover
        print(f"Ошибка при чтении malicious_urls/cached_blacklist: {e}", file=sys.stderr)
    return urls


def collect_safe_urls(limit: int | None = None) -> set[str]:
    """
    Собирает безопасные URL из cached_whitelist (по домену формируем https://domain/).
    """
    urls: set[str] = set()
    try:
        with db_manager._get_connection() as conn:  # type: ignore[attr-defined, name-defined]
            cur = conn.cursor()
            q = "SELECT domain FROM cached_whitelist"
            if limit:
                q += " LIMIT %s"
                cur.execute(q, (limit,))
            else:
                cur.execute(q)
            for row in cur.fetchall() or []:
                d = (row[0] or "").strip().lower()
                if not d:
                    continue
                # Формируем базовый безопасный URL; при необходимости можно расширить путями
                urls.add(f"https://{d}/")
    except Exception as e:  # pragma: no cover
        print(f"Ошибка при чтении cached_whitelist: {e}", file=sys.stderr)
    return urls


def main() -> None:
    parser = argparse.ArgumentParser(description="Экспорт датасета URL из БД AVQON")
    parser.add_argument(
        "--database-url",
        default="",
        help="Явно задать DATABASE_URL (перебивает окружение на время запуска скрипта)",
    )
    parser.add_argument(
        "--output",
        default="scripts/url_ml_from_db.csv",
        help="Путь к выходному CSV (по умолчанию scripts/url_ml_from_db.csv)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5000,
        help="Макс. количество записей из каждой таблицы (malicious/whitelist/blacklist)",
    )
    args = parser.parse_args()

    if args.database_url:
        os.environ["DATABASE_URL"] = args.database_url

    # Глобально, чтобы функции collect_* могли использовать
    global db_manager  # noqa: PLW0603
    db_manager = _load_db_manager()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print("Сбор опасных URL (malicious_urls + cached_blacklist)...")
    mal = collect_malicious_urls(limit=args.limit)
    print(f"  найдено опасных URL: {len(mal)}")

    print("Сбор безопасных URL (cached_whitelist)...")
    safe = collect_safe_urls(limit=args.limit)
    print(f"  найдено безопасных URL: {len(safe)}")

    if not mal and not safe:
        print("В БД нет данных для экспорта (malicious/whitelist/blacklist пусты).", file=sys.stderr)
        sys.exit(1)

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        for u in sorted(safe):
            w.writerow([u, 0])
        for u in sorted(mal):
            w.writerow([u, 1])

    print(f"Датасет сохранён: {out_path} (safe={len(safe)}, phishing={len(mal)})")


if __name__ == "__main__":
    main()

