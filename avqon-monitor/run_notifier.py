# -*- coding: utf-8 -*-
"""Отправка накопленных уведомлений о совпадениях (вызов из планировщика или cron)."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
from telegram import Bot
from bot.handlers import send_match_notifications


async def main():
    if not config.TELEGRAM_BOT_TOKEN:
        return
    bot = Bot(token=config.TELEGRAM_BOT_TOKEN)
    await send_match_notifications(bot)


if __name__ == "__main__":
    asyncio.run(main())
