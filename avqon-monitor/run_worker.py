# -*- coding: utf-8 -*-
"""Точка входа: один запуск Analysis Worker (анализ и сравнение)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from worker.analysis_worker import main
main()
