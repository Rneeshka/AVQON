# -*- coding: utf-8 -*-
"""
AVQON Monitor — обработчики команд бота.
/start, /connect [@channel], /stats, уведомления о совпадениях.
"""
import re
import logging
from telegram import Update, Bot
from telegram.ext import ContextTypes

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from db import models as db

logger = logging.getLogger("avqon.bot")


def extract_channel_username(text: str):
    """Извлечь @username или t.me/username из строки."""
    text = (text or "").strip()
    if not text:
        return None
    m = re.match(r"@(\w+)", text)
    if m:
        return m.group(1)
    m = re.search(r"t\.me/(\w+)", text)
    if m:
        return m.group(1)
    if text.startswith("https://"):
        m = re.search(r"telegram\.(?:me|dog)/(\w+)", text)
        if m:
            return m.group(1)
    return text.lstrip("@") if text else None


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    db.upsert_user(user.id, user.username, user.first_name)
    await update.message.reply_text(
        "Привет! Я **AVQON Monitor** — помогаю отслеживать копирование контента в Telegram.\n\n"
        "Команды:\n"
        "/connect @channel — подключить канал для защиты (нужны права администратора)\n"
        "/stats — статистика по вашим каналам\n\n"
        "После подключения канала мы будем мониторить другие каналы и при обнаружении копии пришлём уведомление.",
        parse_mode="Markdown",
    )


async def cmd_connect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    db.upsert_user(user.id, user.username, user.first_name)

    text = (update.message.text or "").strip()
    channel_username = extract_channel_username(text.replace("/connect", "").strip() if " " in text else "")

    if not channel_username:
        await update.message.reply_text(
            "Укажите канал для подключения:\n`/connect @channel` или `/connect t.me/channel`",
            parse_mode="Markdown",
        )
        return

    bot: Bot = context.bot
    try:
        # Получить чат по username
        chat = await bot.get_chat(f"@{channel_username}")
    except Exception as e:
        logger.warning("get_chat failed for @%s: %s", channel_username, e)
        await update.message.reply_text(
            f"Не удалось найти канал @{channel_username}. Проверьте имя и что бот добавлен в канал (хотя бы как администратор)."
        )
        return

    if chat.type not in ("channel", "supergroup"):
        await update.message.reply_text("Поддерживаются только каналы и супергруппы.")
        return

    try:
        member = await bot.get_chat_member(chat.id, user.id)
    except Exception as e:
        logger.warning("get_chat_member failed: %s", e)
        await update.message.reply_text("Не удалось проверить права. Убедитесь, что бот добавлен в канал как администратор.")
        return

    if member.status not in ("administrator", "creator"):
        await update.message.reply_text(
            "Вы должны быть администратором или создателем канала, чтобы подключить его к AVQON Monitor."
        )
        return

    db.add_channel(
        channel_id=chat.id,
        channel_username=channel_username,
        channel_title=chat.title or "",
        user_id=user.id,
        is_protected=1,
    )
    await update.message.reply_text(
        f"Канал **{chat.title or channel_username}** (@{channel_username}) подключён. "
        "Мы начнём собирать посты и искать копии в других каналах.",
        parse_mode="Markdown",
    )


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    db.upsert_user(user.id, user.username, user.first_name)
    stats = db.get_stats_for_user(user.id)
    channels = db.get_channels_for_user(user.id)
    ch_list = "\n".join([f"• @{c['channel_username']} ({c['channel_title'] or '—'})" for c in channels]) or "—"
    await update.message.reply_text(
        f"**Ваша статистика AVQON Monitor**\n\n"
        f"Подключено каналов: {stats['channels']}\n"
        f"Собрано постов: {stats['posts']}\n"
        f"Найдено совпадений: {stats['matches']}\n\n"
        f"Каналы:\n{ch_list}",
        parse_mode="Markdown",
    )


def build_match_message(match: dict) -> str:
    """Формирование текста уведомления о найденной копии."""
    orig_link = f"https://t.me/{match['original_username']}/{match['original_msg_id']}"
    copy_link = f"https://t.me/{match['copied_username']}/{match['copied_msg_id']}"
    return (
        "⚠️ **Обнаружена возможная копия контента**\n\n"
        f"Тип: {match['match_type']}\n"
        f"Уверенность: {match['confidence']:.0%}\n\n"
        f"Оригинал (ваш пост): {orig_link}\n"
        f"Копия: {copy_link}"
    )


async def send_match_notifications(bot: Bot):
    """Отправить все ненаправленные уведомления о совпадениях."""
    matches = db.get_unnotified_matches()
    for m in matches:
        user_id = db.get_user_id_by_channel_id(m["original_channel_id"])
        if not user_id:
            db.mark_match_notified(m["match_id"])
            continue
        try:
            await bot.send_message(
                chat_id=user_id,
                text=build_match_message(m),
                parse_mode="Markdown",
            )
            db.mark_match_notified(m["match_id"])
        except Exception as e:
            logger.exception("Failed to send match notification to %s: %s", user_id, e)
