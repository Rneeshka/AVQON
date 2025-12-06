"""Покупки через backend AEGIS (новая система)"""

import logging
import aiohttp
from aiogram import Router, F
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton

from config import (
    BACKEND_URL,
    SUPPORT_TECH,
    INSTALLATION_LINK,
)

logger = logging.getLogger(__name__)
router = Router()

# --------------------------
# ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ
# --------------------------

async def backend_create_payment(amount: int, license_type: str, user_id: int, username: str):
    """
    Вызывает наш backend /payments/create
    Возвращает: { payment_id, confirmation_url } или None
    """

    url = f"{BACKEND_URL}/payments/create"
    payload = {
        "amount": amount,
        "license_type": license_type,
        "telegram_id": user_id,
        "username": username
    }

    logger.info(f"Отправляю запрос на backend: {url} | {payload}")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=20) as resp:
                if resp.status != 200:
                    logger.error(f"Backend error: HTTP {resp.status}")
                    return None
                data = await resp.json()
                logger.info(f"Ответ от backend: {data}")
                return data
    except Exception as e:
        logger.error(f"Ошибка запроса на backend: {e}", exc_info=True)
        return None


# --------------------------
# ВЕЧНАЯ ЛИЦЕНЗИЯ
# --------------------------

@router.callback_query(F.data == "buy_forever")
async def buy_forever(callback: CallbackQuery):
    user_id = callback.from_user.id
    username = callback.from_user.username or ""

    logger.info(f"Покупка FOREVER: user_id={user_id}")

    await callback.answer()

    # Здесь просто создаём заказ на backend
    response = await backend_create_payment(
        amount=500,
        license_type="forever",
        user_id=user_id,
        username=username
    )

    if not response:
        await callback.message.edit_text(
            "❌ Платеж временно недоступен.\nОбратитесь в поддержку: " + SUPPORT_TECH
        )
        return

    payment_id = response.get("payment_id")
    confirmation_url = response.get("confirmation_url")

    text = f"""✅ Вы выбрали вечную лицензию AEGIS

Цена: 500₽  
Доступ: бессрочный  

Ссылка для оплаты:
{confirmation_url}

После оплаты нажмите кнопку ниже:
"""

    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔄 Проверить оплату", callback_data=f"check_payment_{payment_id}")],
        [InlineKeyboardButton(text="❌ Отменить", callback_data="cancel_payment")]
    ])

    await callback.message.edit_text(text, reply_markup=keyboard)


# --------------------------
# МЕСЯЧНАЯ ПОДПИСКА
# --------------------------

@router.callback_query(F.data == "buy_monthly")
async def buy_monthly(callback: CallbackQuery):
    user_id = callback.from_user.id
    username = callback.from_user.username or ""

    logger.info(f"Покупка MONTHLY: user_id={user_id}")

    await callback.answer()

    response = await backend_create_payment(
        amount=150,
        license_type="monthly",
        user_id=user_id,
        username=username
    )

    if not response:
        await callback.message.edit_text(
            "❌ Платеж временно недоступен.\nОбратитесь в поддержку: " + SUPPORT_TECH
        )
        return

    payment_id = response.get("payment_id")
    confirmation_url = response.get("confirmation_url")

    text = f"""✅ Вы выбрали AEGIS на 30 дней

Цена: 150₽  
Срок: 30 дней  
Автопродление: ❌  

Ссылка для оплаты:
{confirmation_url}

После оплаты нажмите кнопку ниже:
"""

    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔄 Проверить оплату", callback_data=f"check_payment_{payment_id}")],
        [InlineKeyboardButton(text="❌ Отменить", callback_data="cancel_payment")]
    ])

    await callback.message.edit_text(text, reply_markup=keyboard)


# --------------------------
# ПРОВЕРКА ПЛАТЕЖА (через backend)
# --------------------------

async def backend_check_payment(payment_id: str):
    url = f"{BACKEND_URL}/payments/status/{payment_id}"

    logger.info(f"Запрашиваю статус платежа: {url}")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    logger.error(f"Backend HTTP error: {resp.status}")
                    return None
                return await resp.json()
    except Exception as e:
        logger.error(f"Ошибка запроса статуса: {e}", exc_info=True)
        return None


@router.callback_query(F.data.startswith("check_payment_"))
async def check_payment(callback: CallbackQuery):
    payment_id = callback.data.replace("check_payment_", "")
    user_id = callback.from_user.id

    logger.info(f"Проверка платежа {payment_id} от user={user_id}")

    await callback.answer()

    status_data = await backend_check_payment(payment_id)

    if not status_data:
        await callback.message.edit_text(
            "❌ Ошибка проверки платежа. Попробуйте позже."
        )
        return

    status = status_data.get("status")

    if status == "pending":
        await callback.message.edit_text(
            "⏳ Платеж ещё не подтвержден.\nПопробуйте позже.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔄 Проверить снова", callback_data=f"check_payment_{payment_id}")],
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
        )
        return

    if status == "succeeded":
        await callback.message.edit_text(
            "🎉 Платёж успешно подтвержден!\n"
            "Ваш доступ активирован.\n\n"
            f"📦 Ссылка на установку:\n{INSTALLATION_LINK}",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
        )
        return

    if status == "canceled":
        await callback.message.edit_text(
            "❌ Платёж отменён.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
        )
        return

    await callback.message.edit_text(
        f"❓ Неизвестный статус: {status}"
    )


# --------------------------
# ОТМЕНА ПЛАТЕЖА
# --------------------------

@router.callback_query(F.data == "cancel_payment")
async def cancel_payment(callback: CallbackQuery):
    await callback.answer()
    await callback.message.edit_text(
        "❌ Платеж отменён.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
        ])
    )