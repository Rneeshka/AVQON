"""Обработчики покупки"""
import uuid
import logging
from aiogram import Router, F
from aiogram.types import CallbackQuery, Message, InlineKeyboardMarkup, InlineKeyboardButton
from database import Database
from config import (
    DB_PATH, LICENSE_PRICE_LIFETIME, LICENSE_PRICE_MONTHLY,
    INSTALLATION_LINK, SUPPORT_TECH
)

logger = logging.getLogger(__name__)

# Безопасный импорт yookassa
try:
    from yookassa_client import create_payment, get_payment_status
    from payment_utils import process_successful_payment_internal
    YOOKASSA_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Модули ЮKassa недоступны: {e}. Платежи через ЮKassa не будут работать.")
    YOOKASSA_AVAILABLE = False
    create_payment = None
    get_payment_status = None
    process_successful_payment_internal = None

router = Router()
db = Database(DB_PATH)




@router.callback_query(F.data == "buy_forever")
async def buy_forever(callback: CallbackQuery):
    """Обработчик выбора постоянного доступа"""
    await callback.answer()
    
    user_id = callback.from_user.id
    user = db.get_user(user_id)
    
    # Проверяем, не купил ли уже
    if user and user.get("has_license"):
        await callback.message.edit_text(
            "У вас уже есть лицензия. Используйте команду /start чтобы увидеть свой ключ."
        )
        return
    
    # Проверяем лимит постоянных лицензий
    available = db.get_available_forever_licenses()
    if available <= 0:
        text = """Постоянный доступ временно недоступен.

Лимит в 1000 лицензий исчерпан. Мы выпускаем доступ ограниченными партиями для обеспечения стабильной работы системы.

В данный момент доступна:
• Проверка на месяц — 150₽

Вы можете оставить контакт для уведомления о поступлении новых постоянных лицензий."""
        
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📅 Взять проверку на месяц", callback_data="buy_monthly")],
            [InlineKeyboardButton(text="← Назад", callback_data="main_menu")]
        ])
        
        await callback.message.edit_text(text, reply_markup=keyboard)
        return
    
    # Создаем платеж в ЮKassa
    if not YOOKASSA_AVAILABLE or not create_payment:
        await callback.message.edit_text(
            "❌ Платежная система временно недоступна. Обратитесь в поддержку: " + SUPPORT_TECH
        )
        return
    
    description = f"Постоянный доступ к AEGIS - вечная лицензия"
    logger.info(f"Попытка создать платеж для пользователя {user_id}, сумма {LICENSE_PRICE_LIFETIME}₽")
    payment_result = await create_payment(LICENSE_PRICE_LIFETIME, description)
    
    if not payment_result:
        logger.error(f"Не удалось создать платеж для пользователя {user_id}")
        await callback.message.edit_text(
            "❌ Ошибка при создании платежа. Попробуйте позже или обратитесь в поддержку: " + SUPPORT_TECH
        )
        return
    
    payment_id = payment_result["payment_id"]
    confirmation_url = payment_result["confirmation_url"]
    
    # Сохраняем платеж в БД
    db.create_yookassa_payment(
        payment_id=payment_id,
        user_id=user_id,
        amount=LICENSE_PRICE_LIFETIME * 100,  # в копейках
        license_type="forever"
    )
    
    text = f"""✅ Вы выбрали вечную лицензию AEGIS

Цена: 500₽
Доступ: бессрочный
Осталось: {available} из 1000

Ссылка для оплаты:
{confirmation_url}

После оплаты нажмите кнопку ниже:"""
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Проверить оплату", callback_data=f"check_payment_{payment_id}")],
        [InlineKeyboardButton(text="❌ Отменить", callback_data="cancel_payment")]
    ])
    
    await callback.message.edit_text(text, reply_markup=keyboard)


@router.callback_query(F.data == "buy_monthly")
async def buy_monthly(callback: CallbackQuery):
    """Обработчик выбора проверки на месяц"""
    await callback.answer()
    
    user_id = callback.from_user.id
    user = db.get_user(user_id)
    
    # Проверяем, не купил ли уже
    if user and user.get("has_license"):
        await callback.message.edit_text(
            "У вас уже есть лицензия. Используйте команду /start чтобы увидеть свой ключ."
        )
        return
    
    # Создаем платеж в ЮKassa
    if not YOOKASSA_AVAILABLE or not create_payment:
        await callback.message.edit_text(
            "❌ Платежная система временно недоступна. Обратитесь в поддержку: " + SUPPORT_TECH
        )
        return
    
    description = f"Проверка AEGIS на 30 дней - месячная подписка"
    logger.info(f"Попытка создать платеж для пользователя {user_id}, сумма {LICENSE_PRICE_MONTHLY}₽")
    payment_result = await create_payment(LICENSE_PRICE_MONTHLY, description)
    
    if not payment_result:
        logger.error(f"Не удалось создать платеж для пользователя {user_id}")
        await callback.message.edit_text(
            "❌ Ошибка при создании платежа. Попробуйте позже или обратитесь в поддержку: " + SUPPORT_TECH
        )
        return
    
    payment_id = payment_result["payment_id"]
    confirmation_url = payment_result["confirmation_url"]
    
    # Сохраняем платеж в БД
    db.create_yookassa_payment(
        payment_id=payment_id,
        user_id=user_id,
        amount=LICENSE_PRICE_MONTHLY * 100,  # в копейках
        license_type="monthly"
    )
    
    text = f"""✅ Вы выбрали проверку AEGIS на 30 дней

Цена: 150₽
Срок действия: 30 дней с момента активации
Автопродление: нет

Что включено:
• Все функции анализа ссылок
• Обновления базы угроз
• Поддержка

Ссылка для оплаты:
{confirmation_url}

После оплаты нажмите кнопку ниже:"""
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Проверить оплату", callback_data=f"check_payment_{payment_id}")],
        [InlineKeyboardButton(text="❌ Отменить", callback_data="cancel_payment")]
    ])
    
    await callback.message.edit_text(text, reply_markup=keyboard)


@router.callback_query(F.data.startswith("check_payment_"))
async def check_payment(callback: CallbackQuery):
    """Проверка статуса платежа"""
    await callback.answer()
    
    payment_id = callback.data.replace("check_payment_", "")
    user_id = callback.from_user.id
    
    # Получаем платеж из БД
    payment_db = db.get_yookassa_payment(payment_id)
    if not payment_db:
        await callback.message.edit_text("❌ Платеж не найден в базе данных.")
        return
    
    # Проверяем, что платеж принадлежит этому пользователю
    if payment_db["user_id"] != user_id:
        await callback.answer("❌ Это не ваш платеж!", show_alert=True)
        return
    
    # Запрашиваем статус у ЮKassa
    if not YOOKASSA_AVAILABLE or not get_payment_status:
        await callback.message.edit_text(
            "❌ Платежная система временно недоступна. Обратитесь в поддержку: " + SUPPORT_TECH
        )
        return
    
    payment_status = await get_payment_status(payment_id)
    
    if not payment_status:
        await callback.message.edit_text(
            "❌ Ошибка при проверке статуса платежа. Попробуйте позже или обратитесь в поддержку: " + SUPPORT_TECH
        )
        return
    
    status = payment_status["status"]
    username = callback.from_user.username or ""
    
    # Обновляем статус в БД
    db.update_yookassa_payment_status(payment_id, status)
    
    if status == "succeeded":
        # Платеж успешен - выдаем ключ
        if not YOOKASSA_AVAILABLE or not process_successful_payment_internal:
            await callback.message.edit_text(
                "❌ Ошибка обработки платежа. Обратитесь в поддержку: " + SUPPORT_TECH
            )
            return
        
        license_key, text = await process_successful_payment_internal(
            db, payment_db, user_id, username
        )
        
        if license_key:
            keyboard = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="📦 Ссылка на установку", url=INSTALLATION_LINK)],
                [InlineKeyboardButton(text="❓ Помощь по активации", callback_data="help")],
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
            await callback.message.edit_text(text, reply_markup=keyboard)
        else:
            await callback.message.edit_text(text)
    
    elif status == "pending":
        await callback.message.edit_text(
            "⏳ Платеж еще обрабатывается. Подождите 1-2 минуты и нажмите кнопку проверки снова.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔄 Проверить снова", callback_data=f"check_payment_{payment_id}")],
                [InlineKeyboardButton(text="← Назад", callback_data="main_menu")]
            ])
        )
    
    elif status == "canceled":
        await callback.message.edit_text(
            "❌ Платеж отменен.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
            ])
        )
    
    elif status == "waiting_for_capture":
        await callback.message.edit_text(
            "⏳ Платеж ожидает подтверждения. Обычно это занимает несколько минут.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔄 Проверить снова", callback_data=f"check_payment_{payment_id}")],
                [InlineKeyboardButton(text="← Назад", callback_data="main_menu")]
            ])
        )
    
    else:
        await callback.message.edit_text(
            f"❓ Неизвестный статус платежа: {status}. Обратитесь в поддержку: {SUPPORT_TECH}"
        )


@router.callback_query(F.data == "cancel_payment")
async def cancel_payment(callback: CallbackQuery):
    """Отмена платежа"""
    await callback.answer("Платеж отменен")
    await callback.message.edit_text(
        "❌ Платеж отменен.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
        ])
    )
