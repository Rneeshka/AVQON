"""Общие обработчики"""
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
from database import Database
from config import (
    DB_PATH, INSTALLATION_LINK, SUPPORT_TECH
)

# Безопасный импорт yookassa
try:
    from yookassa_client import get_payment_status
    from payment_utils import process_successful_payment_internal
    YOOKASSA_AVAILABLE = True
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Модули ЮKassa недоступны: {e}. Платежи через ЮKassa не будут работать.")
    YOOKASSA_AVAILABLE = False
    get_payment_status = None
    process_successful_payment_internal = None

router = Router()
db = Database(DB_PATH)


@router.message(Command("start"))
async def cmd_start(message: Message):
    """Обработчик команды /start"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        user_id = message.from_user.id
        username = message.from_user.username
        
        # Создаем или получаем пользователя
        user = db.get_user(user_id)
        if not user:
            db.create_user(user_id, username)
            user = db.get_user(user_id)
        
        # Проверяем pending платежи и автоматически проверяем статус последнего
        if YOOKASSA_AVAILABLE and get_payment_status and process_successful_payment_internal:
            try:
                pending_payments = db.get_pending_payments_by_user(user_id)
                if pending_payments and not (user and user.get("has_license")):
                    # Проверяем статус последнего pending платежа
                    last_payment = pending_payments[0]
                    payment_id = last_payment["payment_id"]
                    
                    try:
                        payment_status = await get_payment_status(payment_id)
                        if payment_status:
                            status = payment_status["status"]
                            db.update_yookassa_payment_status(payment_id, status)
                            
                            if status == "succeeded":
                                # Платеж успешен - выдаем ключ
                                license_key, text = await process_successful_payment_internal(
                                    db, last_payment, user_id, username or ""
                                )
                                
                                if license_key:
                                    keyboard = InlineKeyboardMarkup(inline_keyboard=[
                                        [InlineKeyboardButton(text="📦 Ссылка на установку", url=INSTALLATION_LINK)],
                                        [InlineKeyboardButton(text="❓ Помощь по активации", callback_data="help")],
                                        [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                                    ])
                                    await message.answer(text, reply_markup=keyboard)
                                    return
                    except Exception as payment_check_error:
                        logger.warning(f"Не удалось проверить статус платежа {payment_id}: {payment_check_error}")
                        # Продолжаем выполнение, не блокируем /start
            except Exception as e:
                logger.error(f"Ошибка при проверке pending платежей: {e}", exc_info=True)
                # Продолжаем выполнение, не блокируем /start
        
        # Если у пользователя уже есть лицензия
        if user and user.get("has_license"):
            license_key = user.get("license_key", "N/A")
            text = f"""С возвращением.

Ваш лицензионный ключ:

`{license_key}`

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
                [InlineKeyboardButton(text="🔑 Посмотреть мой ключ", callback_data="show_key")],
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
            
            await message.answer(text, reply_markup=keyboard)
            return
        
        # Первое приветствие для новых пользователей
        stats = db.get_stats()
        remaining = stats["remaining_forever_licenses"]
        
        text = f"""Добро пожаловать.

AEGIS — это расширение для браузера, которое проверяет безопасность ссылок в реальном времени.

Как это работает:
1. Вы ищете что-то в интернете
2. Наводите курсор на любую ссылку
3. Расширение мгновенно анализирует её
4. Вы видите цветной индикатор:
   • Зеленый — безопасно
   • Желтый — подозрительно
   • Красный — опасность

Ничего нажимать не нужно. Анализ происходит автоматически при наведении курсора.

Доступные варианты:

• **Постоянный доступ** — 500₽
  — Работает навсегда
  — Осталось: {remaining} из 1000

• **Проверка на месяц** — 150₽
  — Доступ на 30 дней

Что вас интересует?"""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔐 Постоянный доступ (500₽)", callback_data="buy_forever")],
            [InlineKeyboardButton(text="📅 Проверка на месяц (150₽)", callback_data="buy_monthly")],
            [InlineKeyboardButton(text="❓ Подробнее о работе", callback_data="how_it_works")],
            [InlineKeyboardButton(text="💬 Поддержка", callback_data="support")]
        ])
        
        await message.answer(text, reply_markup=keyboard)
    except Exception as e:
        logger.error(f"Критическая ошибка в /start: {e}", exc_info=True)
        try:
            await message.answer(
                f"❌ Произошла ошибка. Попробуйте позже или обратитесь в поддержку: {SUPPORT_TECH}"
            )
        except:
            pass  # Если даже отправка сообщения не работает, просто логируем


@router.callback_query(F.data == "main_menu")
async def main_menu(callback: CallbackQuery):
    """Вернуться в главное меню"""
    await callback.answer()
    user_id = callback.from_user.id
    user = db.get_user(user_id)
    
    if user and user.get("has_license"):
        # Показываем меню для пользователя с лицензией
        license_key = user.get("license_key", "N/A")
        text = f"""С возвращением.

Ваш лицензионный ключ:

`{license_key}`

Ссылка для установки расширения:
{INSTALLATION_LINK}

Инструкция по активации:
1. Установите расширение по ссылке выше
2. Откройте настройки расширения
3. Введите ваш лицензионный ключ
4. Расширение активировано

Расширение начнет работать сразу после активации. Просто продолжайте пользоваться браузером как обычно.

При возникновении вопросов: {SUPPORT_TECH}"""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📦 Ссылка на установку", url=INSTALLATION_LINK)],
            [InlineKeyboardButton(text="❓ Помощь по активации", callback_data="help")],
            [InlineKeyboardButton(text="🔑 Посмотреть мой ключ", callback_data="show_key")]
        ])
    else:
        # Главное меню для новых пользователей
        stats = db.get_stats()
        remaining = stats["remaining_forever_licenses"]
        
        text = f"""Добро пожаловать.

AEGIS — это расширение для браузера, которое проверяет безопасность ссылок в реальном времени.

Как это работает:
1. Вы ищете что-то в интернете
2. Наводите курсор на любую ссылку
3. Расширение мгновенно анализирует её
4. Вы видите цветной индикатор:
   • Зеленый — безопасно
   • Желтый — подозрительно
   • Красный — опасность

Ничего нажимать не нужно. Анализ происходит автоматически при наведении курсора.

Доступные варианты:

• **Постоянный доступ** — 500₽
  — Работает навсегда
  — Осталось: {remaining} из 1000

• **Проверка на месяц** — 150₽
  — Доступ на 30 дней

Что вас интересует?"""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔐 Постоянный доступ (500₽)", callback_data="buy_forever")],
            [InlineKeyboardButton(text="📅 Проверка на месяц (150₽)", callback_data="buy_monthly")],
            [InlineKeyboardButton(text="❓ Подробнее о работе", callback_data="how_it_works")],
            [InlineKeyboardButton(text="💬 Поддержка", callback_data="support")]
        ])
    
    await callback.message.edit_text(text, reply_markup=keyboard)


@router.callback_query(F.data == "show_key")
async def show_key(callback: CallbackQuery):
    """Показать ключ пользователя"""
    await callback.answer()
    user_id = callback.from_user.id
    user = db.get_user(user_id)
    
    if user and user.get("has_license"):
        license_key = user.get("license_key", "N/A")
        text = f"""🔑 Ваш лицензионный ключ:

`{license_key}`

Ссылка для установки расширения:
{INSTALLATION_LINK}

Инструкция по активации:
1. Установите расширение по ссылке выше
2. Откройте настройки расширения
3. Введите ваш лицензионный ключ
4. Расширение активировано

Расширение начнет работать сразу после активации. Просто продолжайте пользоваться браузером как обычно.

При возникновении вопросов: {SUPPORT_TECH}"""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📦 Ссылка на установку", url=INSTALLATION_LINK)],
            [InlineKeyboardButton(text="❓ Помощь по активации", callback_data="help")],
            [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
        ])
        
        await callback.message.edit_text(text, reply_markup=keyboard)
    else:
        await callback.answer("У вас пока нет лицензии", show_alert=True)

