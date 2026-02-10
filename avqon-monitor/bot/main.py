# -*- coding: utf-8 -*-
"""
AVQON Monitor — запуск Telegram-бота.
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from telegram.ext import Application, CommandHandler
import config
from bot.handlers import cmd_start, cmd_connect, cmd_stats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("avqon.bot")


def main():
    if not config.TELEGRAM_BOT_TOKEN:
        logger.error("Set AVQON_TELEGRAM_BOT_TOKEN environment variable")
        sys.exit(1)
    app = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("connect", cmd_connect))
    app.add_handler(CommandHandler("stats", cmd_stats))
    logger.info("AVQON Monitor bot starting...")
    app.run_polling(allowed_updates=["message"])


if __name__ == "__main__":
    main()
