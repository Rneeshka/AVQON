# -*- coding: utf-8 -*-
"""Точка входа: планировщик (fetcher + worker по расписанию)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db.database import init_db
init_db()
from scheduler import main
main()
