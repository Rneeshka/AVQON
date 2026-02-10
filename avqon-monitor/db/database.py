# -*- coding: utf-8 -*-
"""
AVQON Monitor — подключение к БД (PostgreSQL).
"""
import sys
from pathlib import Path

# Корень проекта
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
import psycopg2
from psycopg2.extras import RealDictCursor


def get_conn():
    """Подключение к PostgreSQL. Возвращает connection с RealDictCursor по умолчанию для cursor()."""
    return psycopg2.connect(
        config.DATABASE_URL,
        cursor_factory=RealDictCursor,
    )


def get_conn_raw():
    """Подключение без DictCursor (для executemany и т.п.)."""
    return psycopg2.connect(config.DATABASE_URL)


def init_db():
    """Инициализация БД: выполнение schema.sql."""
    schema_path = Path(__file__).parent / "schema.sql"
    sql = schema_path.read_text(encoding="utf-8")
    statements = [s.strip() for s in sql.split(";") if s.strip()]
    conn = psycopg2.connect(config.DATABASE_URL)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            for stmt in statements:
                if stmt:
                    cur.execute(stmt)
    finally:
        conn.close()
