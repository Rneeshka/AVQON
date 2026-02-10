# -*- coding: utf-8 -*-
"""Точка входа: один запуск Data Fetcher (сбор постов)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from worker.data_fetcher import main
main()
