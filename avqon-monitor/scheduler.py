# -*- coding: utf-8 -*-
"""
AVQON Monitor — планировщик: запуск Data Fetcher и Analysis Worker по расписанию.
"""
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from telegram import Bot

import config
from worker.data_fetcher import run_fetcher
from worker.analysis_worker import run_worker_once
from bot.handlers import send_match_notifications

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("avqon.scheduler")


async def job_fetcher():
    await run_fetcher()


async def job_worker():
    await run_worker_once()


async def job_notifier():
    if not config.TELEGRAM_BOT_TOKEN:
        return
    bot = Bot(token=config.TELEGRAM_BOT_TOKEN)
    await send_match_notifications(bot)


async def main_async():
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        job_fetcher,
        IntervalTrigger(minutes=config.FETCH_INTERVAL_MINUTES),
        id="data_fetcher",
    )
    scheduler.add_job(
        job_worker,
        IntervalTrigger(minutes=config.ANALYSIS_INTERVAL_MINUTES),
        id="analysis_worker",
    )
    scheduler.add_job(
        job_notifier,
        IntervalTrigger(minutes=5),
        id="notifier",
    )
    scheduler.start()
    logger.info(
        "Scheduler started: fetcher every %s min, worker every %s min",
        config.FETCH_INTERVAL_MINUTES,
        config.ANALYSIS_INTERVAL_MINUTES,
    )
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        scheduler.shutdown(wait=False)


def main():
    try:
        asyncio.run(main_async())
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
