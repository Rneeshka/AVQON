"""Покупки через backend AEGIS (новая система)"""

import logging
import aiohttp
from aiogram import Router, F
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton

from config import (
    BACKEND_URL,
    SUPPORT_TECH,
    INSTALLATION_LINK,
    DB_PATH,
)

from database import Database
from api_client import generate_license_for_user

logger = logging.getLogger(__name__)
router = Router()
db = Database(DB_PATH)

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

    if not payment_id or not confirmation_url:
        logger.error(f"Backend не вернул payment_id или confirmation_url: {response}")
        await callback.message.edit_text(
            "❌ Ошибка при создании платежа. Попробуйте позже или обратитесь в поддержку: " + SUPPORT_TECH
        )
        return

    # Сохраняем платеж в БД
    try:
        db.create_yookassa_payment(
            payment_id=payment_id,
            user_id=user_id,
            amount=500 * 100,  # в копейках
            license_type="forever"
        )
        logger.info(f"Платеж {payment_id} сохранен в БД для user={user_id}")
    except Exception as db_error:
        logger.error(f"Ошибка при сохранении платежа в БД: {db_error}", exc_info=True)
        # Продолжаем, даже если не удалось сохранить в БД

    # Проверяем лимит постоянных лицензий
    available = db.get_available_forever_licenses()

    text = f"""✅ Вы выбрали вечную лицензию AEGIS

Цена: 500₽  
Доступ: бессрочный  
Осталось: {available} из 1000

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

    if not payment_id or not confirmation_url:
        logger.error(f"Backend не вернул payment_id или confirmation_url: {response}")
        await callback.message.edit_text(
            "❌ Ошибка при создании платежа. Попробуйте позже или обратитесь в поддержку: " + SUPPORT_TECH
        )
        return

    # Сохраняем платеж в БД
    try:
        db.create_yookassa_payment(
            payment_id=payment_id,
            user_id=user_id,
            amount=150 * 100,  # в копейках
            license_type="monthly"
        )
        logger.info(f"Платеж {payment_id} сохранен в БД для user={user_id}")
    except Exception as db_error:
        logger.error(f"Ошибка при сохранении платежа в БД: {db_error}", exc_info=True)
        # Продолжаем, даже если не удалось сохранить в БД

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
    """Проверка статуса платежа и выдача ключа при успешной оплате"""
    payment_id = callback.data.replace("check_payment_", "")
    user_id = callback.from_user.id
    username = callback.from_user.username or ""

    logger.info(f"Проверка платежа {payment_id} от user={user_id}")

    await callback.answer()

    try:
        # Получаем статус платежа от backend
        status_data = await backend_check_payment(payment_id)

        if not status_data:
            logger.error(f"Не удалось получить статус платежа {payment_id}")
            await callback.message.edit_text(
                "❌ Ошибка проверки платежа. Попробуйте позже или обратитесь в поддержку: " + SUPPORT_TECH
            )
            return

        status = status_data.get("status")
        logger.info(f"Статус платежа {payment_id}: {status}")

        # Получаем информацию о платеже из БД
        payment_db = db.get_yookassa_payment(payment_id)
        if not payment_db:
            logger.warning(f"Платеж {payment_id} не найден в БД")
            # Пытаемся получить license_type из ответа backend
            license_type = status_data.get("license_type", "forever")
        else:
            license_type = payment_db.get("license_type", "forever")
            # Проверяем, что платеж принадлежит этому пользователю
            if payment_db.get("user_id") != user_id:
                await callback.answer("❌ Это не ваш платеж!", show_alert=True)
                return

        # Обновляем статус в БД
        if payment_db:
            db.update_yookassa_payment_status(payment_id, status)

        if status == "pending":
            await callback.message.edit_text(
                "⏳ Платеж ещё не подтвержден.\nПодождите 1-2 минуты и попробуйте снова.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🔄 Проверить снова", callback_data=f"check_payment_{payment_id}")],
                    [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                ])
            )
            return

        if status == "succeeded":
            logger.info(f"Платеж {payment_id} успешен, генерирую ключ для user={user_id}")
            
            # Проверяем, не выдан ли уже ключ
            user = db.get_user(user_id)
            if user and user.get("has_license"):
                # Ключ уже выдан
                license_key = user.get("license_key", "N/A")
                logger.info(f"Ключ уже выдан пользователю {user_id}: {license_key}")
                text = f"""✅ У вас уже есть активная лицензия!

Ваш лицензионный ключ:

`{license_key}`

Ссылка для установки расширения:
{INSTALLATION_LINK}

Инструкция по активации:
1. Установите расширение по ссылке выше
2. Откройте настройки расширения
3. Введите ваш лицензионный ключ
4. Расширение активировано

При возникновении вопросов: {SUPPORT_TECH}"""
            else:
                # Генерируем новый ключ
                is_lifetime = license_type == "forever"
                logger.info(f"Генерация ключа для user={user_id}, is_lifetime={is_lifetime}")
                
                license_key = await generate_license_for_user(user_id, username, is_lifetime=is_lifetime)
                
                if not license_key:
                    logger.error(f"Не удалось сгенерировать ключ для user={user_id}")
                    await callback.message.edit_text(
                        f"❌ Произошла ошибка при генерации ключа. Обратитесь в поддержку: {SUPPORT_TECH}"
                    )
                    return
                
                # Сохраняем ключ в БД
                db.update_user_license(user_id, license_key)
                if payment_db:
                    db.update_yookassa_payment_status(payment_id, "succeeded", license_key)
                
                logger.info(f"Ключ успешно выдан пользователю {user_id}: {license_key}")
                
                # Формируем сообщение в зависимости от типа лицензии
                if license_type == "forever":
                    license_text = "Ваш ключ действует бессрочно"
                else:
                    from datetime import datetime, timedelta
                    expiry_date = datetime.now() + timedelta(days=30)
                    license_text = f"Ваша подписка действует до {expiry_date.strftime('%d.%m.%Y')}. За 3 дня до окончания получите уведомление"
                
                text = f"""✅ Оплата подтверждена!

Ваш лицензионный ключ:

`{license_key}`

{license_text}

Ссылка для установки расширения:
{INSTALLATION_LINK}

Инструкция по активации:
1. Установите расширение по ссылке выше
2. Откройте настройки расширения
3. Введите ваш лицензионный ключ
4. Расширение активировано

Расширение начнет работать сразу после активации. Просто продолжайте пользоваться браузером как обычно.

При возникновении вопросов: {SUPPORT_TECH}"""
            
            keyboard = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="📦 Ссылка на установку", url=INSTALLATION_LINK)],
                [InlineKeyboardButton(text="❓ Помощь по активации", callback_data="help")],
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
            
            await callback.message.edit_text(text, reply_markup=keyboard)
            return

        if status == "canceled":
            await callback.message.edit_text(
                "❌ Платёж отменён.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                ])
            )
            return

        if status == "waiting_for_capture":
            await callback.message.edit_text(
                "⏳ Платеж ожидает подтверждения. Обычно это занимает несколько минут.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🔄 Проверить снова", callback_data=f"check_payment_{payment_id}")],
                    [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                ])
            )
            return

        # Неизвестный статус
        logger.warning(f"Неизвестный статус платежа {payment_id}: {status}")
        await callback.message.edit_text(
            f"❓ Неизвестный статус платежа: {status}\nОбратитесь в поддержку: {SUPPORT_TECH}",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
        )
        
    except Exception as e:
        logger.error(f"Критическая ошибка при проверке платежа {payment_id}: {e}", exc_info=True)
        await callback.message.edit_text(
            f"❌ Произошла ошибка при проверке платежа. Попробуйте позже или обратитесь в поддержку: {SUPPORT_TECH}"
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