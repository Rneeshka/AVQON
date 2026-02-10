# -*- coding: utf-8 -*-
"""
AVQON Monitor — модуль анализа и сравнения (Analysis Worker).
pHash для изображений, нормализация и сравнение текста. Запись в content_hashes и matches.
"""
import asyncio
import hashlib
import io
import logging
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from db.database import init_db
from db import models as db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("avqon.worker")

# Опциональные зависимости
try:
    import imagehash
    from PIL import Image
    HAS_IMAGEHASH = True
except ImportError:
    HAS_IMAGEHASH = False

try:
    from difflib import SequenceMatcher
except ImportError:
    SequenceMatcher = None

try:
    from telethon import TelegramClient
    from telethon.tl.types import MessageMediaPhoto
except ImportError:
    TelegramClient = None
    MessageMediaPhoto = None


def normalize_text(text: str) -> str:
    """Приведение к нижнему регистру, удаление лишних пробелов и знаков препинания."""
    if not text or not text.strip():
        return ""
    t = text.lower().strip()
    t = re.sub(r"[^\w\s]", " ", t, flags=re.UNICODE)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def text_hash(normalized: str) -> str:
    """Упрощённый хеш текста для быстрого отсева."""
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def text_similarity(a: str, b: str) -> float:
    """Степень совпадения текста (0.0–1.0), difflib.SequenceMatcher."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio() if SequenceMatcher else (1.0 if a == b else 0.0)


def compute_phash(image_bytes: bytes) -> str:
    """Вычислить perceptual hash изображения."""
    if not HAS_IMAGEHASH:
        return ""
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        h = imagehash.phash(img)
        return str(h)
    except Exception as e:
        logger.debug("phash failed: %s", e)
        return ""


def hamming_distance(h1: str, h2: str) -> int:
    """Расстояние Хэмминга между двумя pHash (строками hex)."""
    if not h1 or not h2 or len(h1) != len(h2):
        return 999
    return sum(c1 != c2 for c1, c2 in zip(h1, h2))


def get_telethon_client():
    if not TelegramClient:
        return None
    if not config.TELEGRAM_API_ID or not config.TELEGRAM_API_HASH:
        return None
    session_path = config.DATA_DIR / f"{config.TELEGRAM_SESSION_NAME}.session"
    return TelegramClient(
        str(session_path),
        config.TELEGRAM_API_ID,
        config.TELEGRAM_API_HASH,
        proxy=config.TELEGRAM_PROXY,
    )


async def download_photo(client: TelegramClient, channel_id: int, channel_username: str, message_id: int) -> bytes:
    """Скачать фото поста через Telethon. Возвращает bytes или пустой bytes."""
    try:
        entity = await client.get_entity(channel_id if channel_id < 0 else f"@{channel_username}")
        message = await client.get_messages(entity, ids=message_id)
        if not message or not message.media:
            return b""
        if not isinstance(message.media, MessageMediaPhoto):
            return b""
        data = await client.download_media(message.media, bytes)
        return data or b""
    except Exception as e:
        logger.debug("Download photo failed for msg %s: %s", message_id, e)
        return b""


def process_post_sync(post: dict, protected_hashes: list) -> list:
    """
    Вычислить хеши поста и найти совпадения с защищёнными постами.
    Возвращает список (original_post_id, copied_post_id, match_type, confidence).
    """
    text_norm = normalize_text(post.get("text") or "")
    text_h = text_hash(text_norm)
    media_hash = ""

    # pHash для первого фото поста — выполняется снаружи при наличии client и скачанных bytes
    # Здесь только сохраняем переданный media_hash если есть
    if post.get("media_hash_computed"):
        media_hash = post["media_hash_computed"]

    db.insert_content_hash(
        post_id=post["post_id"],
        media_hash=media_hash,
        text_hash=text_h,
        text_normalized=text_norm,
    )
    db.mark_post_processed(post["post_id"])

    matches_found = []
    if not post.get("is_protected"):
        for ref in protected_hashes:
            if ref["post_id"] == post["post_id"]:
                continue
            conf = 0.0
            match_type = ""
            if media_hash and ref.get("media_hash"):
                dist = hamming_distance(media_hash, ref["media_hash"])
                if dist <= config.PHASH_HAMMING_THRESHOLD:
                    conf = max(conf, 1.0 - dist / 16.0)
                    match_type = "image"
            if text_norm and ref.get("text_normalized"):
                sim = text_similarity(text_norm, ref["text_normalized"])
                if sim >= config.TEXT_SIMILARITY_THRESHOLD:
                    conf = max(conf, sim)
                    if not match_type:
                        match_type = "text"
                    else:
                        match_type = "text_image"
            if conf >= config.TEXT_SIMILARITY_THRESHOLD or (match_type == "image" and conf > 0):
                matches_found.append((ref["post_id"], post["post_id"], match_type or "text", conf))
                break  # одно совпадение на пост достаточно для уведомления

    return matches_found


async def run_worker_once():
    init_db()
    posts = db.get_unprocessed_posts(limit=50)
    if not posts:
        logger.info("No unprocessed posts")
        return

    protected = db.get_protected_hashes_for_comparison(since_days=config.MATCH_LOOKBACK_DAYS)
    client = get_telethon_client()

    for post in posts:
        try:
            media_hash = ""
            if post.get("media_type") == "photo" and post.get("media_urls") and client:
                # Скачать фото и вычислить pHash
                async with client:
                    raw = await download_photo(
                        client,
                        post["channel_id"],
                        post["channel_username"],
                        post["telegram_message_id"],
                    )
                    if raw:
                        media_hash = compute_phash(raw)
                await asyncio.sleep(config.TELEGRAM_API_DELAY)
            post["media_hash_computed"] = media_hash
            matches = process_post_sync(post, protected)
            for orig_id, copy_id, mtype, conf in matches:
                db.insert_match(orig_id, copy_id, mtype, conf)
                logger.info("Match: original=%s copied=%s type=%s conf=%s", orig_id, copy_id, mtype, conf)
        except Exception as e:
            logger.exception("Failed to process post %s: %s", post.get("post_id"), e)
        await asyncio.sleep(0.2)


def main():
    asyncio.run(run_worker_once())


if __name__ == "__main__":
    main()
