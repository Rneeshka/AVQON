# -*- coding: utf-8 -*-
"""
AVQON Monitor — модуль сбора данных (Data Fetcher).
Подписка на обновления каналов, парсинг постов, сохранение в raw_posts.
Требуется: Telethon, API ID/Hash (my.telegram.org), сессия (первый запуск — авторизация в консоли).
"""
import asyncio
import logging
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from db.database import init_db
from db import models as db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("avqon.fetcher")

try:
    from telethon import TelegramClient
    from telethon.tl.types import MessageMediaPhoto, MessageMediaDocument
except ImportError:
    TelegramClient = None
    MessageMediaPhoto = MessageMediaDocument = None


def _get_client():
    if not TelegramClient:
        raise RuntimeError("Install telethon: pip install telethon")
    if not config.TELEGRAM_API_ID or not config.TELEGRAM_API_HASH:
        raise RuntimeError("Set AVQON_TELEGRAM_API_ID and AVQON_TELEGRAM_API_HASH (my.telegram.org)")
    session_path = config.DATA_DIR / f"{config.TELEGRAM_SESSION_NAME}.session"
    return TelegramClient(
        str(session_path),
        config.TELEGRAM_API_ID,
        config.TELEGRAM_API_HASH,
        proxy=config.TELEGRAM_PROXY,
    )


async def fetch_channel(client: TelegramClient, channel_id: int, channel_username: str, limit: int = 50):
    """Собрать последние посты канала и сохранить в raw_posts."""
    entity = await client.get_entity(channel_id if channel_id < 0 else f"@{channel_username}")
    added = 0
    async for message in client.iter_messages(entity, limit=limit):
        if not message.date:
            continue
        text = message.text or message.message or ""
        media_urls = []
        media_type = ""
        if message.media:
            if isinstance(message.media, MessageMediaPhoto):
                media_type = "photo"
                # Сохраняем file_reference или id; скачивание — в Analysis Worker
                media_urls.append(f"photo:{message.media.id}")
            elif isinstance(message.media, MessageMediaDocument):
                media_type = "document"
                media_urls.append(f"document:{getattr(message.media.document, 'id', '')}")
        date_str = message.date.strftime("%Y-%m-%d %H:%M:%S")
        try:
            db.insert_raw_post(
                channel_id=channel_id,
                telegram_message_id=message.id,
                text=text,
                media_urls=media_urls,
                media_type=media_type,
                date=date_str,
            )
            added += 1
        except Exception as e:
            logger.debug("Skip duplicate or error post %s: %s", message.id, e)
        await asyncio.sleep(config.TELEGRAM_API_DELAY)
    return added


async def run_fetcher():
    init_db()
    channels = db.get_all_active_channels(protected_only=False)
    if not channels:
        logger.info("No active channels to fetch")
        return
    client = _get_client()
    async with client:
        for ch in channels:
            try:
                n = await fetch_channel(client, ch["channel_id"], ch["channel_username"])
                logger.info("Channel @%s: fetched %s new posts", ch["channel_username"], n)
            except Exception as e:
                logger.exception("Failed to fetch @%s: %s", ch["channel_username"], e)
            await asyncio.sleep(config.TELEGRAM_API_DELAY * 2)


def main():
    asyncio.run(run_fetcher())


if __name__ == "__main__":
    main()
