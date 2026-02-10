# -*- coding: utf-8 -*-
"""Точка входа: запуск Telegram-бота AVQON Monitor."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db.database import init_db
init_db()
from bot.main import main
main()
