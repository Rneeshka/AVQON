# -*- coding: utf-8 -*-
"""
AVQON Monitor — операции с таблицами (users, channels, raw_posts, content_hashes, matches).
PostgreSQL.
"""
import json
from datetime import datetime, timedelta
from db.database import get_conn


# --- Users ---
def upsert_user(user_id: int, username: str = None, first_name: str = None):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO users (user_id, username, first_name, updated_at)
                   VALUES (%s, %s, %s, NOW())
                   ON CONFLICT (user_id) DO UPDATE SET
                     username = EXCLUDED.username,
                     first_name = EXCLUDED.first_name,
                     updated_at = NOW()""",
                (user_id, username or "", first_name or ""),
            )
        conn.commit()
    finally:
        conn.close()


def get_user(user_id: int):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
            r = cur.fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


# --- Channels ---
def add_channel(channel_id: int, channel_username: str, channel_title: str, user_id: int, is_protected: int = 1):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO channels (channel_id, channel_username, channel_title, user_id, is_protected, is_active, updated_at)
                   VALUES (%s, %s, %s, %s, %s, 1, NOW())
                   ON CONFLICT (channel_id) DO UPDATE SET
                     channel_username = EXCLUDED.channel_username,
                     channel_title = EXCLUDED.channel_title,
                     user_id = EXCLUDED.user_id,
                     is_protected = EXCLUDED.is_protected,
                     is_active = 1,
                     updated_at = NOW()""",
                (channel_id, channel_username or "", channel_title or "", user_id, is_protected),
            )
        conn.commit()
    finally:
        conn.close()


def get_channels_for_user(user_id: int, active_only: bool = True):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if active_only:
                cur.execute(
                    "SELECT channel_id, channel_username, channel_title, is_protected FROM channels WHERE user_id = %s AND is_active = 1",
                    (user_id,),
                )
            else:
                cur.execute(
                    "SELECT channel_id, channel_username, channel_title, is_protected FROM channels WHERE user_id = %s",
                    (user_id,),
                )
            rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_user_id_by_channel_id(channel_id: int):
    """Владелец канала (user_id) по channel_id."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM channels WHERE channel_id = %s", (channel_id,))
            r = cur.fetchone()
        return r["user_id"] if r else None
    finally:
        conn.close()


def get_all_active_channels(protected_only: bool = False):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if protected_only:
                cur.execute(
                    "SELECT channel_id, channel_username, user_id FROM channels WHERE is_active = 1 AND is_protected = 1"
                )
            else:
                cur.execute("SELECT channel_id, channel_username, user_id FROM channels WHERE is_active = 1")
            rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# --- Raw posts ---
def insert_raw_post(channel_id: int, telegram_message_id: int, text: str, media_urls: list, media_type: str, date: str):
    """Вставка поста. При конфликте (channel_id, telegram_message_id) ничего не делает. Возвращает post_id или None."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO raw_posts (channel_id, telegram_message_id, text, media_urls, media_type, date)
                   VALUES (%s, %s, %s, %s::jsonb, %s, %s::timestamptz)
                   ON CONFLICT (channel_id, telegram_message_id) DO NOTHING
                   RETURNING post_id""",
                (channel_id, telegram_message_id, text or "", json.dumps(media_urls or []), media_type or "", date),
            )
            row = cur.fetchone()
        conn.commit()
        return row["post_id"] if row else None
    finally:
        conn.close()


def get_unprocessed_posts(limit: int = 100):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT rp.post_id, rp.channel_id, rp.telegram_message_id, rp.text, rp.media_urls, rp.media_type, rp.date,
                          ch.channel_username, ch.is_protected
                   FROM raw_posts rp
                   JOIN channels ch ON ch.channel_id = rp.channel_id
                   WHERE rp.processed = 0 ORDER BY rp.date LIMIT %s""",
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {**dict(r), "media_urls": r["media_urls"] or []}
            for r in rows
        ]
    finally:
        conn.close()


def mark_post_processed(post_id: int):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE raw_posts SET processed = 1 WHERE post_id = %s", (post_id,))
        conn.commit()
    finally:
        conn.close()


# --- Content hashes ---
def insert_content_hash(post_id: int, media_hash: str = None, text_hash: str = None, text_normalized: str = None):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO content_hashes (post_id, media_hash, text_hash, text_normalized)
                   VALUES (%s, %s, %s, %s)
                   RETURNING hash_id""",
                (post_id, media_hash or "", text_hash or "", text_normalized or ""),
            )
            row = cur.fetchone()
        conn.commit()
        return row["hash_id"] if row else None
    finally:
        conn.close()


def get_author_posts_for_comparison(channel_id: int, since_days: int = 30):
    conn = get_conn()
    try:
        since = (datetime.utcnow() - timedelta(days=since_days)).strftime("%Y-%m-%d %H:%M:%S")
        with conn.cursor() as cur:
            cur.execute(
                """SELECT ch.hash_id, ch.post_id, ch.media_hash, ch.text_hash, ch.text_normalized, rp.date
                   FROM content_hashes ch
                   JOIN raw_posts rp ON rp.post_id = ch.post_id
                   WHERE rp.channel_id = %s AND rp.date >= %s::timestamptz AND (ch.media_hash != '' OR ch.text_hash != '')""",
                (channel_id, since),
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_hashes_by_channel_for_lookup(since_days: int = 30):
    conn = get_conn()
    try:
        since = (datetime.utcnow() - timedelta(days=since_days)).strftime("%Y-%m-%d %H:%M:%S")
        with conn.cursor() as cur:
            cur.execute(
                """SELECT rp.channel_id, ch.post_id, ch.media_hash, ch.text_hash, ch.text_normalized
                   FROM content_hashes ch
                   JOIN raw_posts rp ON rp.post_id = ch.post_id
                   WHERE rp.date >= %s::timestamptz AND (ch.media_hash != '' OR ch.text_hash != '')""",
                (since,),
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_protected_hashes_for_comparison(since_days: int = 30):
    conn = get_conn()
    try:
        since = (datetime.utcnow() - timedelta(days=since_days)).strftime("%Y-%m-%d %H:%M:%S")
        with conn.cursor() as cur:
            cur.execute(
                """SELECT rp.channel_id, ch.post_id, ch.media_hash, ch.text_hash, ch.text_normalized
                   FROM content_hashes ch
                   JOIN raw_posts rp ON rp.post_id = ch.post_id
                   JOIN channels c ON c.channel_id = rp.channel_id
                   WHERE c.is_protected = 1 AND rp.date >= %s::timestamptz AND (ch.media_hash != '' OR ch.text_hash != '')""",
                (since,),
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# --- Matches ---
def insert_match(original_post_id: int, copied_post_id: int, match_type: str, confidence: float):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO matches (original_post_id, copied_post_id, match_type, confidence) VALUES (%s, %s, %s, %s) RETURNING match_id",
                (original_post_id, copied_post_id, match_type, confidence),
            )
            row = cur.fetchone()
        conn.commit()
        return row["match_id"] if row else None
    finally:
        conn.close()


def get_unnotified_matches():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT m.match_id, m.original_post_id, m.copied_post_id, m.match_type, m.confidence,
                          o.channel_id AS original_channel_id, o.telegram_message_id AS original_msg_id,
                          c.channel_id AS copied_channel_id, c.telegram_message_id AS copied_msg_id,
                          ch_orig.channel_username AS original_username, ch_cop.channel_username AS copied_username
                   FROM matches m
                   JOIN raw_posts o ON o.post_id = m.original_post_id
                   JOIN raw_posts c ON c.post_id = m.copied_post_id
                   JOIN channels ch_orig ON ch_orig.channel_id = o.channel_id
                   JOIN channels ch_cop ON ch_cop.channel_id = c.channel_id
                   WHERE m.notified = 0"""
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def mark_match_notified(match_id: int):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE matches SET notified = 1 WHERE match_id = %s", (match_id,))
        conn.commit()
    finally:
        conn.close()


def get_stats_for_user(user_id: int):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS c FROM channels WHERE user_id = %s AND is_active = 1", (user_id,)
            )
            channels = cur.fetchone()["c"]
            cur.execute(
                """SELECT COUNT(*) AS c FROM raw_posts rp
                   JOIN channels ch ON ch.channel_id = rp.channel_id WHERE ch.user_id = %s""",
                (user_id,),
            )
            posts = cur.fetchone()["c"]
            cur.execute(
                """SELECT COUNT(*) AS c FROM matches m
                   JOIN raw_posts o ON o.post_id = m.original_post_id
                   JOIN channels ch ON ch.channel_id = o.channel_id WHERE ch.user_id = %s""",
                (user_id,),
            )
            matches = cur.fetchone()["c"]
        return {"channels": channels, "posts": posts, "matches": matches}
    finally:
        conn.close()
