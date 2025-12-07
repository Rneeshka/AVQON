"""Обработчики для управления подписками"""
import logging
import aiohttp
from datetime import datetime, timedelta
from typing import Optional
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command

from database import Database
from config import DB_PATH, BACKEND_URL, API_KEY, SUPPORT_TECH, INSTALLATION_LINK, LICENSE_PRICE_MONTHLY
from handlers.purchase import backend_create_payment, safe_edit_message

logger = logging.getLogger(__name__)
router = Router()
db = Database(DB_PATH)


@router.message(Command("my_subscription"))
async def cmd_my_subscription(message: Message):
    """Показать информацию о текущей подписке"""
    try:
        user_id = message.from_user.id
        username = message.from_user.username or ""
        
        logger.info(f"[MY_SUBSCRIPTION] Запрос от user={user_id}")
        
        user = db.get_user(user_id)
        if not user or not user.get("has_license"):
            await message.answer(
                "❌ У вас нет активной подписки.\n\n"
                "Выберите подходящий вариант:",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🔐 Постоянный доступ (500₽)", callback_data="buy_forever")],
                    [InlineKeyboardButton(text="📅 Проверка на месяц (150₽)", callback_data="buy_monthly")]
                ])
            )
            return
        
        license_key = user.get("license_key")
        subscription = db.get_subscription(user_id)
        
        if not subscription:
            # Проверяем по платежам, какой тип лицензии был куплен
            # Если это месячная, но подписки нет - создаем её
            try:
                payment = db.get_yookassa_payment_by_license_key(license_key)
                if payment and payment.get("license_type") == "monthly":
                    # Создаем подписку на основе платежа
                    created_at_str = payment.get("created_at")
                    if created_at_str:
                        if isinstance(created_at_str, str):
                            created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                        else:
                            created_at = created_at_str
                        # Если платеж был недавно (менее 30 дней назад), создаем подписку
                        expires_at = created_at + timedelta(days=30)
                        now = datetime.now()
                        if expires_at.tzinfo:
                            now = now.replace(tzinfo=expires_at.tzinfo)
                        
                        if expires_at > now:
                            # Подписка еще не истекла, создаем запись
                            db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
                            subscription = db.get_subscription(user_id)
                            logger.info(f"Создана подписка для существующего пользователя {user_id} на основе платежа")
                        else:
                            # Подписка уже истекла, но создаем для истории
                            expires_at = now + timedelta(days=30)  # Даем еще 30 дней
                            db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
                            subscription = db.get_subscription(user_id)
                            logger.info(f"Создана подписка для пользователя {user_id} (была истекшей)")
                    else:
                        # Если даты нет, создаем с текущей датой + 30 дней
                        expires_at = datetime.now() + timedelta(days=30)
                        db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
                        subscription = db.get_subscription(user_id)
                        logger.info(f"Создана подписка для пользователя {user_id} (без даты платежа)")
            except Exception as e:
                logger.error(f"Ошибка при проверке платежей для создания подписки: {e}", exc_info=True)
            
            if not subscription:
                # Если не месячная или не удалось создать - это вечная лицензия
                await message.answer(
                    f"✅ У вас активная лицензия:\n\n"
                    f"`{license_key}`\n\n"
                    f"Тип: Постоянная (бессрочная)\n\n"
                    f"Ссылка для установки: {INSTALLATION_LINK}"
                )
                return
        
        expires_at_str = subscription.get("expires_at")
        if expires_at_str:
            if isinstance(expires_at_str, str):
                expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
            else:
                expires_at = expires_at_str
            
            now = datetime.now()
            if expires_at.tzinfo:
                now = now.replace(tzinfo=expires_at.tzinfo)
            
            days_left = (expires_at - now).days
            hours_left = int((expires_at - now).total_seconds() / 3600)
            auto_renew = subscription.get("auto_renew", False)
            renewal_count = subscription.get("renewal_count", 0)
            
            # Форматирование таймера
            if days_left < 0:
                status_text = "❌ Подписка истекла"
                timer_text = f"⏰ Истекла {abs(days_left)} дней назад"
                timer_emoji = "❌"
            elif days_left == 0:
                status_text = "⚠️ Подписка истекает сегодня"
                if hours_left > 0:
                    timer_text = f"⏰ Осталось {hours_left} часов"
                else:
                    timer_text = "⏰ Осталось менее часа"
                timer_emoji = "🔴"
            elif days_left <= 3:
                status_text = "⚠️ Подписка скоро истечет"
                timer_text = f"⏰ Осталось {days_left} дня"
                timer_emoji = "🟠"
            elif days_left <= 7:
                status_text = "✅ Подписка активна"
                timer_text = f"⏰ Осталось {days_left} дней"
                timer_emoji = "🟡"
            else:
                status_text = "✅ Подписка активна"
                timer_text = f"⏰ Осталось {days_left} дней"
                timer_emoji = "🟢"
            
            expires_date = expires_at.strftime("%d.%m.%Y")
            expires_time = expires_at.strftime("%H:%M")
            
            # Текст для кнопки продления
            if days_left > 0:
                new_expires = expires_at + timedelta(days=30)
                renew_button_text = f"🔄 Продлить (+30 дней, будет до {new_expires.strftime('%d.%m.%Y')})"
            else:
                renew_button_text = "🔄 Продлить подписку"
            
            text = f"""{status_text}

{timer_emoji} <b>ТАЙМЕР ДО ОКОНЧАНИЯ:</b>
{timer_text}

📅 Дата окончания: {expires_date} в {expires_time}

🔑 Ваш ключ:
`{license_key}`

🔄 Автопродление: {"✅ Включено" if auto_renew else "❌ Выключено"}
📊 Продлений: {renewal_count}

💡 <i>Вы можете продлить подписку заранее - к текущему сроку добавится еще 30 дней</i>

Ссылка для установки: {INSTALLATION_LINK}"""
            
            keyboard = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text=renew_button_text, callback_data="renew_subscription")],
                [InlineKeyboardButton(
                    text="🔄 " + ("Выключить" if auto_renew else "Включить") + " автопродление",
                    callback_data=f"toggle_auto_renew_{'off' if auto_renew else 'on'}"
                )],
                [InlineKeyboardButton(text="📜 История подписок", callback_data="subscription_history")],
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
            
            await message.answer(text, reply_markup=keyboard)
        else:
            await message.answer(
                f"✅ У вас активная подписка\n\n"
                f"Ключ: `{license_key}`\n\n"
                f"Ссылка для установки: {INSTALLATION_LINK}"
            )
    except Exception as e:
        logger.error(f"[MY_SUBSCRIPTION] Ошибка при обработке команды для user={message.from_user.id}: {e}", exc_info=True)
        try:
            await message.answer(
                f"❌ Произошла ошибка при получении информации о подписке.\n\n"
                f"Обратитесь в поддержку: {SUPPORT_TECH}"
            )
        except:
            pass


@router.callback_query(F.data == "my_subscription")
async def callback_my_subscription(callback: CallbackQuery):
    """Callback для кнопки 'Моя подписка'"""
    user_id = callback.from_user.id
    username = callback.from_user.username or ""
    
    await callback.answer()
    
    user = db.get_user(user_id)
    if not user or not user.get("has_license"):
        await safe_edit_message(
            callback,
            "❌ У вас нет активной подписки.\n\n"
            "Выберите подходящий вариант:",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔐 Постоянный доступ (500₽)", callback_data="buy_forever")],
                [InlineKeyboardButton(text="📅 Проверка на месяц (150₽)", callback_data="buy_monthly")]
            ])
        )
        return
    
    license_key = user.get("license_key")
    subscription = db.get_subscription(user_id)
    
    if not subscription:
        # Проверяем по платежам, какой тип лицензии был куплен
        # Если это месячная, но подписки нет - создаем её
        try:
            payment = db.get_yookassa_payment_by_license_key(license_key)
            if payment and payment.get("license_type") == "monthly":
                # Создаем подписку на основе платежа
                from datetime import datetime, timedelta
                created_at_str = payment.get("created_at")
                if created_at_str:
                    if isinstance(created_at_str, str):
                        created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                    else:
                        created_at = created_at_str
                    expires_at = created_at + timedelta(days=30)
                    now = datetime.now()
                    if expires_at.tzinfo:
                        now = now.replace(tzinfo=expires_at.tzinfo)
                    
                    if expires_at > now:
                        db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
                        subscription = db.get_subscription(user_id)
                        logger.info(f"Создана подписка для существующего пользователя {user_id} (callback)")
                    else:
                        expires_at = now + timedelta(days=30)
                        db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
                        subscription = db.get_subscription(user_id)
                        logger.info(f"Создана подписка для пользователя {user_id} (была истекшей, callback)")
                else:
                    expires_at = datetime.now() + timedelta(days=30)
                    db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
                    subscription = db.get_subscription(user_id)
                    logger.info(f"Создана подписка для пользователя {user_id} (без даты платежа, callback)")
        except Exception as e:
            logger.error(f"Ошибка при проверке платежей: {e}", exc_info=True)
        
        if not subscription:
            # Если не месячная или не удалось создать - это вечная лицензия
            await safe_edit_message(
                callback,
                f"✅ У вас активная лицензия:\n\n"
                f"`{license_key}`\n\n"
                f"Тип: Постоянная (бессрочная)\n\n"
                f"Ссылка для установки: {INSTALLATION_LINK}"
            )
            return
    
    expires_at_str = subscription.get("expires_at")
    if expires_at_str:
        if isinstance(expires_at_str, str):
            expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
        else:
            expires_at = expires_at_str
        
        now = datetime.now()
        if expires_at.tzinfo:
            now = now.replace(tzinfo=expires_at.tzinfo)
        
        days_left = (expires_at - now).days
        hours_left = int((expires_at - now).total_seconds() / 3600)
        auto_renew = subscription.get("auto_renew", False)
        renewal_count = subscription.get("renewal_count", 0)
        
        # Форматирование таймера
        if days_left < 0:
            status_text = "❌ Подписка истекла"
            timer_text = f"⏰ Истекла {abs(days_left)} дней назад"
            timer_emoji = "❌"
        elif days_left == 0:
            status_text = "⚠️ Подписка истекает сегодня"
            if hours_left > 0:
                timer_text = f"⏰ Осталось {hours_left} часов"
            else:
                timer_text = "⏰ Осталось менее часа"
            timer_emoji = "🔴"
        elif days_left <= 3:
            status_text = "⚠️ Подписка скоро истечет"
            timer_text = f"⏰ Осталось {days_left} дня"
            timer_emoji = "🟠"
        elif days_left <= 7:
            status_text = "✅ Подписка активна"
            timer_text = f"⏰ Осталось {days_left} дней"
            timer_emoji = "🟡"
        else:
            status_text = "✅ Подписка активна"
            timer_text = f"⏰ Осталось {days_left} дней"
            timer_emoji = "🟢"
        
        expires_date = expires_at.strftime("%d.%m.%Y")
        expires_time = expires_at.strftime("%H:%M")
        
        # Текст для кнопки продления
        if days_left > 0:
            new_expires = expires_at + timedelta(days=30)
            renew_button_text = f"🔄 Продлить (+30 дней, будет до {new_expires.strftime('%d.%m.%Y')})"
        else:
            renew_button_text = "🔄 Продлить подписку"
        
        text = f"""{status_text}

{timer_emoji} <b>ТАЙМЕР ДО ОКОНЧАНИЯ:</b>
{timer_text}

📅 Дата окончания: {expires_date} в {expires_time}

🔑 Ваш ключ:
`{license_key}`

🔄 Автопродление: {"✅ Включено" if auto_renew else "❌ Выключено"}
📊 Продлений: {renewal_count}

💡 <i>Вы можете продлить подписку заранее - к текущему сроку добавится еще 30 дней</i>

Ссылка для установки: {INSTALLATION_LINK}"""
        
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=renew_button_text, callback_data="renew_subscription")],
            [InlineKeyboardButton(
                text="🔄 " + ("Выключить" if auto_renew else "Включить") + " автопродление",
                callback_data=f"toggle_auto_renew_{'off' if auto_renew else 'on'}"
            )],
            [InlineKeyboardButton(text="📜 История подписок", callback_data="subscription_history")],
            [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
        ])
        
        await safe_edit_message(callback, text, reply_markup=keyboard)
    else:
        await safe_edit_message(
            callback,
            f"✅ У вас активная подписка\n\n"
            f"Ключ: `{license_key}`\n\n"
            f"Ссылка для установки: {INSTALLATION_LINK}"
        )


@router.callback_query(F.data == "renew_subscription")
async def renew_subscription(callback: CallbackQuery):
    """Начать процесс продления подписки"""
    user_id = callback.from_user.id
    username = callback.from_user.username or ""
    
    await callback.answer()
    
    user = db.get_user(user_id)
    if not user or not user.get("has_license"):
        await safe_edit_message(
            callback,
            "❌ У вас нет активной подписки для продления."
        )
        return
    
    subscription = db.get_subscription(user_id)
    if not subscription:
        await safe_edit_message(
            callback,
            "❌ Подписка не найдена. Возможно, у вас постоянная лицензия."
        )
        return
    
    # Показываем информацию о текущей подписке и что будет после продления
    expires_at_str = subscription.get("expires_at")
    if expires_at_str:
        if isinstance(expires_at_str, str):
            current_expires = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
        else:
            current_expires = expires_at_str
        
        now = datetime.now()
        if current_expires.tzinfo:
            now = now.replace(tzinfo=current_expires.tzinfo)
        
        days_left = (current_expires - now).days
        new_expires = current_expires + timedelta(days=30)
        
        if days_left > 0:
            info_text = f"""📊 <b>Текущая подписка:</b>
⏰ Осталось: {days_left} дней
📅 Истекает: {current_expires.strftime('%d.%m.%Y')}

📊 <b>После продления:</b>
📅 Будет действовать до: {new_expires.strftime('%d.%m.%Y')}
⏰ Всего дней: {(new_expires - now).days} дней"""
        else:
            info_text = f"""📊 <b>Текущая подписка:</b>
❌ Подписка истекла

📊 <b>После продления:</b>
📅 Будет действовать до: {new_expires.strftime('%d.%m.%Y')}
⏰ Всего дней: 30 дней"""
    else:
        info_text = "После продления подписка будет продлена на 30 дней"
    
    # Создаем новый платеж для продления
    response = await backend_create_payment(
        amount=LICENSE_PRICE_MONTHLY,
        license_type="monthly",
        user_id=user_id,
        username=username
    )
    
    if not response:
        await safe_edit_message(
            callback,
            f"❌ Платеж временно недоступен.\nОбратитесь в поддержку: {SUPPORT_TECH}"
        )
        return
    
    payment_id = response.get("payment_id")
    confirmation_url = response.get("confirmation_url")
    
    if not payment_id or not confirmation_url:
        logger.error(f"Backend не вернул payment_id или confirmation_url: {response}")
        await safe_edit_message(
            callback,
            f"❌ Ошибка при создании платежа. Попробуйте позже или обратитесь в поддержку: {SUPPORT_TECH}"
        )
        return
    
    # Сохраняем платеж в БД с пометкой is_renewal=True
    try:
        db.create_yookassa_payment(
            payment_id=payment_id,
            user_id=user_id,
            amount=LICENSE_PRICE_MONTHLY * 100,  # в копейках
            license_type="monthly",
            is_renewal=True
        )
        logger.info(f"Платеж на продление {payment_id} сохранен в БД для user={user_id}")
    except Exception as db_error:
        logger.error(f"Ошибка при сохранении платежа в БД: {db_error}", exc_info=True)
    
    text = f"""🔄 <b>Продление подписки</b>

💰 Цена: {LICENSE_PRICE_MONTHLY}₽
📅 Добавится: +30 дней к текущему сроку

{info_text}

💳 <b>Ссылка для оплаты:</b>
{confirmation_url}

✅ После успешной оплаты подписка будет автоматически продлена."""
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Оплатить", url=confirmation_url)],
        [InlineKeyboardButton(text="🔍 Проверить оплату", callback_data=f"check_payment_{payment_id}")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="cancel_payment")]
    ])
    
    await safe_edit_message(callback, text, reply_markup=keyboard)


@router.callback_query(F.data.startswith("toggle_auto_renew_"))
async def toggle_auto_renew(callback: CallbackQuery):
    """Включить/выключить автопродление"""
    user_id = callback.from_user.id
    action = callback.data.replace("toggle_auto_renew_", "")
    
    await callback.answer()
    
    subscription = db.get_subscription(user_id)
    if not subscription:
        await safe_edit_message(
            callback,
            "❌ Подписка не найдена."
        )
        return
    
    auto_renew = action == "on"
    db.set_subscription_auto_renew(user_id, auto_renew)
    
    status = "включено" if auto_renew else "выключено"
    await safe_edit_message(
        callback,
        f"✅ Автопродление {status}.\n\n"
        f"Используйте /my_subscription для просмотра информации о подписке."
    )


@router.callback_query(F.data == "subscription_history")
async def subscription_history(callback: CallbackQuery):
    """Показать историю подписок"""
    user_id = callback.from_user.id
    
    await callback.answer()
    
    history = db.get_subscription_history(user_id)
    
    if not history:
        await safe_edit_message(
            callback,
            "📜 История подписок пуста."
        )
        return
    
    text = "📜 История подписок:\n\n"
    
    for i, sub in enumerate(history[:10], 1):  # Показываем последние 10
        expires_at_str = sub.get("expires_at")
        status = sub.get("status", "unknown")
        renewal_count = sub.get("renewal_count", 0)
        created_at_str = sub.get("created_at")
        
        status_emoji = {
            "active": "✅",
            "expired": "❌",
            "canceled": "🚫"
        }.get(status, "❓")
        
        if expires_at_str:
            if isinstance(expires_at_str, str):
                expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
            else:
                expires_at = expires_at_str
            expires_text = expires_at.strftime("%d.%m.%Y")
        else:
            expires_text = "Не указано"
        
        if created_at_str:
            if isinstance(created_at_str, str):
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
            else:
                created_at = created_at_str
            created_text = created_at.strftime("%d.%m.%Y")
        else:
            created_text = "Не указано"
        
        text += f"{status_emoji} Подписка #{i}\n"
        text += f"Создана: {created_text}\n"
        text += f"Истекает: {expires_text}\n"
        text += f"Продлений: {renewal_count}\n"
        text += f"Статус: {status}\n\n"
    
    if len(history) > 10:
        text += f"... и еще {len(history) - 10} записей"
    
    await safe_edit_message(callback, text)


@router.message(Command("renew"))
async def cmd_renew(message: Message):
    """Команда для продления подписки"""
    user_id = message.from_user.id
    username = message.from_user.username or ""
    
    user = db.get_user(user_id)
    if not user or not user.get("has_license"):
        await message.answer(
            "❌ У вас нет активной подписки для продления.\n\n"
            "Выберите подходящий вариант:",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔐 Постоянный доступ (500₽)", callback_data="buy_forever")],
                [InlineKeyboardButton(text="📅 Проверка на месяц (150₽)", callback_data="buy_monthly")]
            ])
        )
        return
    
    subscription = db.get_subscription(user_id)
    if not subscription:
        await message.answer(
            "❌ Подписка не найдена. Возможно, у вас постоянная лицензия."
        )
        return
    
    # Показываем информацию о текущей подписке и что будет после продления
    expires_at_str = subscription.get("expires_at")
    if expires_at_str:
        if isinstance(expires_at_str, str):
            current_expires = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
        else:
            current_expires = expires_at_str
        
        now = datetime.now()
        if current_expires.tzinfo:
            now = now.replace(tzinfo=current_expires.tzinfo)
        
        days_left = (current_expires - now).days
        new_expires = current_expires + timedelta(days=30)
        
        if days_left > 0:
            info_text = f"""📊 <b>Текущая подписка:</b>
⏰ Осталось: {days_left} дней
📅 Истекает: {current_expires.strftime('%d.%m.%Y')}

📊 <b>После продления:</b>
📅 Будет действовать до: {new_expires.strftime('%d.%m.%Y')}
⏰ Всего дней: {(new_expires - now).days} дней"""
        else:
            info_text = f"""📊 <b>Текущая подписка:</b>
❌ Подписка истекла

📊 <b>После продления:</b>
📅 Будет действовать до: {new_expires.strftime('%d.%m.%Y')}
⏰ Всего дней: 30 дней"""
    else:
        info_text = "После продления подписка будет продлена на 30 дней"
    
    # Создаем новый платеж для продления
    response = await backend_create_payment(
        amount=LICENSE_PRICE_MONTHLY,
        license_type="monthly",
        user_id=user_id,
        username=username
    )
    
    if not response:
        await message.answer(
            f"❌ Платеж временно недоступен.\nОбратитесь в поддержку: {SUPPORT_TECH}"
        )
        return
    
    payment_id = response.get("payment_id")
    confirmation_url = response.get("confirmation_url")
    
    if not payment_id or not confirmation_url:
        logger.error(f"Backend не вернул payment_id или confirmation_url: {response}")
        await message.answer(
            f"❌ Ошибка при создании платежа. Попробуйте позже или обратитесь в поддержку: {SUPPORT_TECH}"
        )
        return
    
    # Сохраняем платеж в БД с пометкой is_renewal=True
    try:
        db.create_yookassa_payment(
            payment_id=payment_id,
            user_id=user_id,
            amount=LICENSE_PRICE_MONTHLY * 100,  # в копейках
            license_type="monthly",
            is_renewal=True
        )
        logger.info(f"Платеж на продление {payment_id} сохранен в БД для user={user_id}")
    except Exception as db_error:
        logger.error(f"Ошибка при сохранении платежа в БД: {db_error}", exc_info=True)
    
    text = f"""🔄 <b>Продление подписки</b>

💰 Цена: {LICENSE_PRICE_MONTHLY}₽
📅 Добавится: +30 дней к текущему сроку

{info_text}

💳 <b>Ссылка для оплаты:</b>
{confirmation_url}

✅ После успешной оплаты подписка будет автоматически продлена."""
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Оплатить", url=confirmation_url)],
        [InlineKeyboardButton(text="🔍 Проверить оплату", callback_data=f"check_payment_{payment_id}")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="cancel_payment")]
    ])
    
    await message.answer(text, reply_markup=keyboard)


@router.message(Command("auto_renew"))
async def cmd_auto_renew(message: Message):
    """Команда для управления автопродлением"""
    user_id = message.from_user.id
    args = message.text.split()[1:] if message.text else []
    
    subscription = db.get_subscription(user_id)
    if not subscription:
        await message.answer(
            "❌ У вас нет активной подписки."
        )
        return
    
    if not args:
        auto_renew = subscription.get("auto_renew", False)
        await message.answer(
            f"🔄 Автопродление: {'✅ Включено' if auto_renew else '❌ Выключено'}\n\n"
            f"Используйте:\n"
            f"/auto_renew on - включить\n"
            f"/auto_renew off - выключить"
        )
        return
    
    action = args[0].lower()
    if action not in ["on", "off"]:
        await message.answer(
            "❌ Неверная команда. Используйте:\n"
            "/auto_renew on - включить\n"
            "/auto_renew off - выключить"
        )
        return
    
    auto_renew = action == "on"
    db.set_subscription_auto_renew(user_id, auto_renew)
    
    status = "включено" if auto_renew else "выключено"
    await message.answer(
        f"✅ Автопродление {status}."
    )


@router.message(Command("subscription_history"))
async def cmd_subscription_history(message: Message):
    """Команда для просмотра истории подписок"""
    user_id = message.from_user.id
    
    history = db.get_subscription_history(user_id)
    
    if not history:
        await message.answer("📜 История подписок пуста.")
        return
    
    text = "📜 История подписок:\n\n"
    
    for i, sub in enumerate(history[:10], 1):
        expires_at_str = sub.get("expires_at")
        status = sub.get("status", "unknown")
        renewal_count = sub.get("renewal_count", 0)
        created_at_str = sub.get("created_at")
        
        status_emoji = {
            "active": "✅",
            "expired": "❌",
            "canceled": "🚫"
        }.get(status, "❓")
        
        if expires_at_str:
            if isinstance(expires_at_str, str):
                expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
            else:
                expires_at = expires_at_str
            expires_text = expires_at.strftime("%d.%m.%Y")
        else:
            expires_text = "Не указано"
        
        if created_at_str:
            if isinstance(created_at_str, str):
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
            else:
                created_at = created_at_str
            created_text = created_at.strftime("%d.%m.%Y")
        else:
            created_text = "Не указано"
        
        text += f"{status_emoji} Подписка #{i}\n"
        text += f"Создана: {created_text}\n"
        text += f"Истекает: {expires_text}\n"
        text += f"Продлений: {renewal_count}\n"
        text += f"Статус: {status}\n\n"
    
    if len(history) > 10:
        text += f"... и еще {len(history) - 10} записей"
    
    await message.answer(text)

