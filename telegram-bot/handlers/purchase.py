"""Покупки через backend AEGIS (новая система)"""

import logging
import aiohttp
from typing import Optional, Dict
from aiogram import Router, F
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.exceptions import TelegramBadRequest

from config import (
    BACKEND_URL,
    SUPPORT_TECH,
    INSTALLATION_LINK,
    DB_PATH,
    YOOKASSA_SHOP_ID,
    YOOKASSA_SECRET_KEY,
)

from database import Database
from api_client import generate_license_for_user

logger = logging.getLogger(__name__)
router = Router()
db = Database(DB_PATH)


# --------------------------
# ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ БЕЗОПАСНОГО РЕДАКТИРОВАНИЯ
# --------------------------

async def safe_edit_message(callback: CallbackQuery, text: str, reply_markup=None):
    """
    Безопасно редактирует сообщение, обрабатывая ошибку "message is not modified"
    """
    try:
        await callback.message.edit_text(text, reply_markup=reply_markup)
    except TelegramBadRequest as e:
        if "message is not modified" in str(e).lower():
            # Сообщение не изменилось - это нормально, просто отвечаем на callback
            logger.debug(f"[SAFE_EDIT] Message not modified, answering callback: {callback.data}")
            try:
                await callback.answer()
            except Exception:
                pass
        else:
            # Другая ошибка - пробуем отправить новое сообщение
            logger.warning(f"[SAFE_EDIT] TelegramBadRequest: {e}, trying to send new message")
            try:
                await callback.message.answer(text, reply_markup=reply_markup)
            except Exception as send_err:
                logger.error(f"[SAFE_EDIT] Failed to send new message: {send_err}")
                raise
    except Exception as e:
        # Любая другая ошибка - пробуем отправить новое сообщение
        logger.warning(f"[SAFE_EDIT] Error editing message: {e}, trying to send new message")
        try:
            await callback.message.answer(text, reply_markup=reply_markup)
        except Exception as send_err:
            logger.error(f"[SAFE_EDIT] Failed to send new message: {send_err}")
            raise

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

    logger.info(f"[PAYMENT] Отправляю запрос на backend: {url}")
    logger.info(f"[PAYMENT] BACKEND_URL из config: {BACKEND_URL}")
    logger.info(f"[PAYMENT] Payload: {payload}")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=20) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    logger.error(f"Backend error: HTTP {resp.status}, response: {error_text[:500]}")
                    return None
                try:
                    data = await resp.json()
                    logger.info(f"Ответ от backend: {data}")
                    return data
                except Exception as json_err:
                    error_text = await resp.text()
                    logger.error(f"Ошибка парсинга JSON ответа от backend: {json_err}, response: {error_text[:500]}")
                    return None
    except aiohttp.ClientError as client_err:
        logger.error(f"Сетевая ошибка при запросе к backend: {client_err}", exc_info=True)
        return None
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
        await safe_edit_message(
            callback,
            "❌ Платеж временно недоступен.\nОбратитесь в поддержку: " + SUPPORT_TECH
        )
        return

    payment_id = response.get("payment_id")
    confirmation_url = response.get("confirmation_url")

    if not payment_id or not confirmation_url:
        logger.error(f"Backend не вернул payment_id или confirmation_url: {response}")
        await safe_edit_message(
            callback,
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

После успешной оплаты ключ придет автоматически (вебхук)."""

    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отменить", callback_data="cancel_payment")]
    ])

    await safe_edit_message(callback, text, reply_markup=keyboard)


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
        await safe_edit_message(
            callback,
            "❌ Платеж временно недоступен.\nОбратитесь в поддержку: " + SUPPORT_TECH
        )
        return

    payment_id = response.get("payment_id")
    confirmation_url = response.get("confirmation_url")

    if not payment_id or not confirmation_url:
        logger.error(f"Backend не вернул payment_id или confirmation_url: {response}")
        await safe_edit_message(
            callback,
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

После успешной оплаты ключ придет автоматически (вебхук)."""

    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отменить", callback_data="cancel_payment")]
    ])

    await safe_edit_message(callback, text, reply_markup=keyboard)


# --------------------------
# ПРОВЕРКА ПЛАТЕЖА (напрямую через ЮKassa API)
# --------------------------

async def check_payment_direct_yookassa(payment_id: str) -> Optional[Dict]:
    """
    Проверка статуса платежа напрямую через ЮKassa API.
    Возвращает словарь с полями: status, metadata (user_id, license_type), amount
    """
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error(f"[CHECK_PAYMENT] YooKassa credentials not configured")
        return None
    
    url = f"https://api.yookassa.ru/v3/payments/{payment_id}"
    auth = aiohttp.BasicAuth(login=YOOKASSA_SHOP_ID, password=YOOKASSA_SECRET_KEY)
    
    logger.info(f"[CHECK_PAYMENT] Запрашиваю статус платежа напрямую у ЮKassa: {payment_id}")
    
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, auth=auth) as resp:
                logger.info(f"[CHECK_PAYMENT] ЮKassa ответил со статусом: {resp.status}")
                
                if resp.status == 200:
                    data = await resp.json()
                    yookassa_status = data.get("status", "pending")
                    logger.info(f"[CHECK_PAYMENT] Статус платежа {payment_id} от ЮKassa: {yookassa_status}")
                    
                    # Получаем метаданные
                    metadata = data.get("metadata", {})
                    user_id = metadata.get("telegram_id") or metadata.get("user_id")
                    license_type = metadata.get("license_type", "")
                    
                    # Получаем сумму
                    amount_value = 0.0
                    if "amount" in data:
                        amount_obj = data.get("amount", {})
                        if isinstance(amount_obj, dict) and "value" in amount_obj:
                            try:
                                amount_value = float(amount_obj["value"])
                            except (ValueError, TypeError):
                                pass
                    
                    # Если метаданных нет в ответе ЮKassa, пытаемся получить из БД
                    if not user_id or not license_type:
                        payment_db = db.get_yookassa_payment(payment_id)
                        if payment_db:
                            user_id = user_id or str(payment_db.get("user_id", ""))
                            license_type = license_type or payment_db.get("license_type", "")
                            if not amount_value:
                                amount_value = payment_db.get("amount", 0) / 100
                    
                    result = {
                        "status": yookassa_status,
                        "metadata": {
                            "user_id": str(user_id) if user_id else "",
                            "license_type": license_type or "forever"
                        },
                        "amount": f"{amount_value:.2f}"
                    }
                    
                    logger.info(f"[CHECK_PAYMENT] Результат проверки: status={yookassa_status}, user_id={user_id}, license_type={license_type}")
                    return result
                    
                elif resp.status == 404:
                    logger.warning(f"[CHECK_PAYMENT] Платеж {payment_id} не найден в ЮKassa")
                    return None
                else:
                    error_text = await resp.text()
                    logger.error(f"[CHECK_PAYMENT] ЮKassa вернул ошибку {resp.status}: {error_text[:200]}")
                    return None
                    
    except aiohttp.ClientError as e:
        logger.error(f"[CHECK_PAYMENT] Сетевая ошибка при запросе к ЮKassa: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"[CHECK_PAYMENT] Неожиданная ошибка при проверке платежа: {e}", exc_info=True)
        return None


# Оставляем старую функцию для обратной совместимости, но она теперь вызывает прямую проверку
async def backend_check_payment(payment_id: str):
    """Проверка статуса платежа (теперь напрямую через ЮKassa)"""
    return await check_payment_direct_yookassa(payment_id)


@router.callback_query(F.data.startswith("check_payment_"))
async def check_payment(callback: CallbackQuery):
    """Проверка статуса платежа и выдача ключа при успешной оплате"""
    payment_id = callback.data.replace("check_payment_", "")
    user_id = callback.from_user.id
    username = callback.from_user.username or ""

    logger.info(f"[CHECK_PAYMENT] Начало проверки платежа {payment_id} от user={user_id}")

    try:
        await callback.answer()
    except Exception as answer_err:
        logger.warning(f"[CHECK_PAYMENT] Ошибка при answer callback: {answer_err}")

    try:
        # Получаем статус платежа напрямую от ЮKassa
        logger.info(f"[CHECK_PAYMENT] Запрос статуса платежа {payment_id} напрямую к ЮKassa...")
        status_data = await check_payment_direct_yookassa(payment_id)

        if not status_data:
            logger.error(f"[CHECK_PAYMENT] Не удалось получить данные о платеже {payment_id} от ЮKassa")
            await safe_edit_message(
                callback,
                "❌ Ошибка проверки платежа. Попробуйте позже или обратитесь в поддержку: " + SUPPORT_TECH
            )
            return

        logger.info(f"[CHECK_PAYMENT] Получен ответ от ЮKassa: {status_data}")
        
        status = status_data.get("status")
        if not status:
            logger.error(f"[CHECK_PAYMENT] В ответе ЮKassa отсутствует поле 'status': {status_data}")
            await safe_edit_message(
                callback,
                "❌ Ошибка: неверный формат ответа от сервера. Обратитесь в поддержку: " + SUPPORT_TECH
            )
            return
            
        logger.info(f"[CHECK_PAYMENT] Статус платежа {payment_id}: {status}")
        logger.debug(f"[CHECK_PAYMENT] Полный ответ от ЮKassa: {status_data}")

        # Получаем информацию о платеже из БД
        payment_db = db.get_yookassa_payment(payment_id)
        
        # Извлекаем license_type из ответа ЮKassa (metadata) или из БД
        metadata = status_data.get("metadata", {})
        logger.info(f"[CHECK_PAYMENT] Метаданные из ЮKassa: {metadata}")
        
        # Приоритет: метаданные из backend > БД > значение по умолчанию
        license_type = None
        if metadata and metadata.get("license_type"):
            license_type = metadata.get("license_type")
            logger.info(f"[CHECK_PAYMENT] License type из метаданных backend: {license_type}")
        elif payment_db and payment_db.get("license_type"):
            license_type = payment_db.get("license_type")
            logger.info(f"[CHECK_PAYMENT] License type из БД: {license_type}")
        else:
            license_type = "forever"  # значение по умолчанию
            logger.warning(f"[CHECK_PAYMENT] License type не найден, используем значение по умолчанию: {license_type}")
        
        logger.info(f"[CHECK_PAYMENT] Итоговый license_type: {license_type}")
        
        if not payment_db:
            logger.warning(f"Платеж {payment_id} не найден в БД")
        else:
            # Проверяем, что платеж принадлежит этому пользователю
            db_user_id = payment_db.get("user_id")
            backend_user_id = metadata.get("user_id")
            if db_user_id and str(db_user_id) != str(user_id):
                logger.warning(f"Платеж {payment_id} принадлежит другому пользователю: {db_user_id} != {user_id}")
                await callback.answer("❌ Это не ваш платеж!", show_alert=True)
                return
            if backend_user_id and str(backend_user_id) != str(user_id):
                logger.warning(f"Платеж {payment_id} принадлежит другому пользователю (из backend): {backend_user_id} != {user_id}")
                await callback.answer("❌ Это не ваш платеж!", show_alert=True)
                return

        # Обновляем статус в БД если изменился
        if payment_db:
            db_status = payment_db.get("status", "pending")
            if status != db_status:
                try:
                    db.update_yookassa_payment_status(payment_id, status)
                    logger.info(f"[CHECK_PAYMENT] Статус платежа {payment_id} обновлен в БД: {db_status} -> {status}")
                except Exception as update_err:
                    logger.error(f"[CHECK_PAYMENT] Ошибка при обновлении статуса в БД: {update_err}", exc_info=True)
            else:
                logger.debug(f"[CHECK_PAYMENT] Статус платежа {payment_id} не изменился: {status}")

        if status == "pending":
            await safe_edit_message(
                callback,
                "⏳ Платеж ещё не подтвержден.\nПодождите 1-2 минуты и попробуйте снова.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🔄 Проверить снова", callback_data=f"check_payment_{payment_id}")],
                    [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                ])
            )
            return

        if status == "succeeded":
            logger.info(f"[CHECK_PAYMENT] Платеж {payment_id} успешен, обрабатываю для user={user_id}, license_type={license_type}")

            # Проверяем, является ли это продлением
            is_renewal = payment_db and payment_db.get("is_renewal", False)
            
            user = db.get_user(user_id)
            existing_license_key = user.get("license_key") if user and user.get("has_license") else None
            
            if is_renewal and existing_license_key:
                # ПРОДЛЕНИЕ ПОДПИСКИ
                logger.info(f"[CHECK_PAYMENT] Это продление подписки для user={user_id}, license_key={existing_license_key[:10]}...")
                
                from api_client import renew_license
                from datetime import datetime, timedelta
                
                # Продлеваем лицензию через API
                renewal_success = await renew_license(existing_license_key, extend_days=30)
                
                if not renewal_success:
                    logger.error(f"[CHECK_PAYMENT] Не удалось продлить лицензию для user={user_id}")
                    await safe_edit_message(
                        callback,
                        f"❌ Ошибка при продлении лицензии. Обратитесь в поддержку: {SUPPORT_TECH}"
                    )
                    return
                
                # Обновляем подписку в БД
                subscription = db.get_subscription(user_id)
                if subscription:
                    # Продлеваем срок: если подписка еще активна, добавляем 30 дней к текущему сроку
                    expires_at_str = subscription.get("expires_at")
                    if expires_at_str:
                        if isinstance(expires_at_str, str):
                            current_expires = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                        else:
                            current_expires = expires_at_str
                        
                        # Если подписка уже истекла, начинаем с текущей даты + 30 дней
                        # Если еще активна, добавляем 30 дней к текущему сроку
                        now = datetime.now()
                        if current_expires.tzinfo:
                            now = now.replace(tzinfo=current_expires.tzinfo)
                        
                        if current_expires < now:
                            new_expires_at = now + timedelta(days=30)
                        else:
                            new_expires_at = current_expires + timedelta(days=30)
                        
                        db.update_subscription_expiry(user_id, new_expires_at)
                        logger.info(f"[CHECK_PAYMENT] Подписка продлена до {new_expires_at} для user={user_id}")
                    else:
                        # Если expires_at не указан, создаем новый срок
                        new_expires_at = datetime.now() + timedelta(days=30)
                        db.update_subscription_expiry(user_id, new_expires_at)
                else:
                    # Если подписки нет, создаем новую
                    new_expires_at = datetime.now() + timedelta(days=30)
                    db.create_subscription(user_id, existing_license_key, "monthly", new_expires_at)
                    logger.info(f"[CHECK_PAYMENT] Создана новая подписка для user={user_id}")
                
                # Обновляем статус платежа
                if payment_db:
                    db.update_yookassa_payment_status(payment_id, "succeeded", existing_license_key)
                
                new_expires_date = new_expires_at.strftime("%d.%m.%Y")
                text = f"""✅ Подписка успешно продлена!

Ваш лицензионный ключ:
`{existing_license_key}`

📅 Подписка действует до: {new_expires_date}

Ссылка для установки: {INSTALLATION_LINK}"""
                
                keyboard = InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="📦 Установить расширение", url=INSTALLATION_LINK)],
                    [InlineKeyboardButton(text="📊 Моя подписка", callback_data="my_subscription")],
                    [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                ])
                
                await safe_edit_message(callback, text, reply_markup=keyboard)
                return
            
            # НОВАЯ ПОКУПКА
            if user and user.get("has_license"):
                license_key = user.get("license_key", "N/A")
                logger.info(f"[CHECK_PAYMENT] Ключ уже выдан пользователю {user_id}: {license_key}")

                text = f"""✅ У вас уже есть активная лицензия!

Ваш лицензионный ключ:

`{license_key}`

Ссылка для установки расширения:
{INSTALLATION_LINK}

Если возникнут вопросы — {SUPPORT_TECH}"""

            else:
                # Генерируем новый ключ
                is_lifetime = license_type == "forever"
                logger.info(f"[CHECK_PAYMENT] Генерирую ключ для user={user_id}, is_lifetime={is_lifetime}, license_type={license_type}")
                license_key = await generate_license_for_user(user_id, username, is_lifetime=is_lifetime)

                if not license_key:
                    logger.error(f"[CHECK_PAYMENT] Не удалось сгенерировать ключ для user={user_id}")
                    await safe_edit_message(
                        callback,
                        f"❌ Ошибка при генерации ключа. Обратитесь в поддержку: {SUPPORT_TECH}"
                    )
                    return
                
                logger.info(f"[CHECK_PAYMENT] Ключ успешно сгенерирован для user={user_id}: {license_key[:10]}...")

                # Сохраняем ключ
                db.update_user_license(user_id, license_key)
                if payment_db:
                    db.update_yookassa_payment_status(payment_id, "succeeded", license_key)

                # Создаем подписку для месячных лицензий
                if license_type == "monthly":
                    try:
                        from datetime import datetime, timedelta
                        expires_at = datetime.now() + timedelta(days=30)
                        db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
                        logger.info(f"[CHECK_PAYMENT] Создана подписка для user={user_id}, expires_at={expires_at}")
                    except Exception as e:
                        logger.error(f"[CHECK_PAYMENT] Ошибка создания подписки: {e}", exc_info=True)

                if license_type == "forever":
                    license_text = "Ваш ключ действует бессрочно."
                else:
                    from datetime import datetime, timedelta
                    expiry_date = datetime.now() + timedelta(days=30)
                    license_text = f"Подписка действует до {expiry_date.strftime('%d.%m.%Y')}."

                text = f"""✅ Оплата подтверждена!

Ваш ключ:

`{license_key}`

{license_text}

Ссылка для установки: {INSTALLATION_LINK}
"""

            keyboard = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="📦 Установить расширение", url=INSTALLATION_LINK)],
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])

            await safe_edit_message(callback, text, reply_markup=keyboard)
            return

        if status == "canceled":
            await safe_edit_message(
                callback,
                "❌ Платёж отменён.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                ])
            )
            return

        if status == "waiting_for_capture":
            await safe_edit_message(
                callback,
                "⏳ Платеж ожидает подтверждения. Обычно это занимает несколько минут.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🔄 Проверить снова", callback_data=f"check_payment_{payment_id}")],
                    [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                ])
            )
            return

        # Неизвестный статус
        logger.warning(f"[CHECK_PAYMENT] Неизвестный статус платежа {payment_id}: {status}")
        await safe_edit_message(
            callback,
            f"❓ Неизвестный статус платежа: {status}\nОбратитесь в поддержку: {SUPPORT_TECH}",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
        )
        
    except aiohttp.ClientError as client_err:
        logger.error(f"[CHECK_PAYMENT] Сетевая ошибка при проверке платежа {payment_id}: {client_err}", exc_info=True)
        await safe_edit_message(
            callback,
            f"❌ Ошибка соединения с сервером. Проверьте интернет и попробуйте позже.\nПоддержка: {SUPPORT_TECH}"
        )
    except KeyError as key_err:
        logger.error(f"[CHECK_PAYMENT] Ошибка доступа к полю в ответе backend для платежа {payment_id}: {key_err}", exc_info=True)
        await safe_edit_message(
            callback,
            f"❌ Ошибка обработки ответа сервера. Обратитесь в поддержку: {SUPPORT_TECH}"
        )
    except Exception as e:
        logger.error(f"[CHECK_PAYMENT] Критическая ошибка при проверке платежа {payment_id}: {type(e).__name__}: {e}", exc_info=True)
        error_details = f"{type(e).__name__}: {str(e)}"
        logger.error(f"[CHECK_PAYMENT] Детали ошибки: {error_details}")
        # Убираем детали ошибки из сообщения пользователю для безопасности
        await safe_edit_message(
            callback,
            f"❌ Произошла ошибка при проверке платежа.\n\nОбратитесь в поддержку: {SUPPORT_TECH}"
        )


# --------------------------
# ОТМЕНА ПЛАТЕЖА
# --------------------------

@router.callback_query(F.data == "cancel_payment")
async def cancel_payment(callback: CallbackQuery):
    await callback.answer()
    await safe_edit_message(
        callback,
        "❌ Платеж отменён.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
        ])
    )