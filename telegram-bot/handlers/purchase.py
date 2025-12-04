"""Обработчики покупки"""
import uuid
from aiogram import Router, F
from aiogram.types import CallbackQuery, Message, PreCheckoutQuery, LabeledPrice, InlineKeyboardMarkup, InlineKeyboardButton
from database import Database
from api_client import generate_license_for_user
from config import (
    DB_PATH, LICENSE_PRICE_LIFETIME, LICENSE_PRICE_MONTHLY,
    INSTALLATION_LINK, SUPPORT_TECH, YOOKASSA_PROVIDER_TOKEN
)

router = Router()
db = Database(DB_PATH)


async def create_invoice(amount: int, description: str, license_type: str):
    """
    Создает счет для оплаты через ЮKassa
    В реальном режиме нужно будет заменить на вызов API ЮKassa
    """
    
    # Параметры для платежа
    prices = [LabeledPrice(label="AEGIS License", amount=amount * 100)]  # в копейках
    
    # В реальной версии здесь будет:
    # 1. Создание платежа в ЮKassa через API
    # 2. Получение confirmation_url
    # 3. Возврат ссылки для оплаты
    
    # Заглушка для разработки (заменить на реальный provider_token)
    return {
        "title": "Оплата AEGIS",
        "description": description,
        "payload": f"payment_{license_type}_{uuid.uuid4().hex[:8]}",
        "provider_token": YOOKASSA_PROVIDER_TOKEN or "TEST_PROVIDER_TOKEN",  # Заменить на реальный
        "currency": "RUB",
        "prices": prices,
        "start_parameter": "aegis_payment",
        "need_email": False,
        "need_phone_number": False,
    }


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
    
    text = f"""Вы выбрали постоянный доступ к AEGIS.

Стоимость: 500₽
Доступ: не ограничен по времени
Действует: на всех ваших устройствах с этим браузером

После оплаты вы получите:
• Лицензионный ключ
• Инструкцию по установке и активации
• Доступ к обновлениям

Осталось доступных лицензий: {available} из 1000

Перейти к оплате?"""
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Перейти к оплате (500₽)", callback_data="proceed_payment_forever")],
        [InlineKeyboardButton(text="← Назад к выбору", callback_data="main_menu")]
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
    
    text = """Вы выбрали проверку AEGIS на 30 дней.

Стоимость: 150₽
Срок действия: 30 дней с момента активации
Автопродление: нет

Что включено:
• Все функции анализа ссылок
• Обновления базы угроз
• Поддержка

Этот вариант подходит, если хотите оценить работу расширения перед покупкой постоянного доступа.

Перейти к оплате?"""
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Перейти к оплате (150₽)", callback_data="proceed_payment_monthly")],
        [InlineKeyboardButton(text="← Назад к выбору", callback_data="main_menu")]
    ])
    
    await callback.message.edit_text(text, reply_markup=keyboard)


@router.callback_query(F.data.startswith("proceed_payment_"))
async def proceed_payment(callback: CallbackQuery):
    """Обработчик перехода к оплате"""
    await callback.answer()
    
    license_type = "forever" if callback.data == "proceed_payment_forever" else "monthly"
    amount = LICENSE_PRICE_LIFETIME if license_type == "forever" else LICENSE_PRICE_MONTHLY
    
    user_id = callback.from_user.id
    
    # Проверяем лимит для постоянных лицензий
    if license_type == "forever":
        available = db.get_available_forever_licenses()
        if available <= 0:
            await callback.message.edit_text(
                "Постоянный доступ временно недоступен. Лимит исчерпан."
            )
            return
    
    description = f"Постоянный доступ к AEGIS" if license_type == "forever" else f"Проверка AEGIS на 30 дней"
    
    invoice_data = await create_invoice(amount, description, license_type)
    
    # Отправляем инвойс
    bot = callback.bot
    
    try:
        await bot.send_invoice(
            chat_id=callback.message.chat.id,
            title=invoice_data["title"],
            description=invoice_data["description"],
            payload=invoice_data["payload"],
            provider_token=invoice_data["provider_token"],
            currency=invoice_data["currency"],
            prices=invoice_data["prices"],
            start_parameter=invoice_data["start_parameter"],
            need_email=invoice_data["need_email"],
            need_phone_number=invoice_data["need_phone_number"]
        )
    except Exception as e:
        # Если не поддерживается платеж через Telegram, используем альтернативный метод
        # В реальной версии здесь будет ссылка на форму оплаты ЮKassa
        text = f"""Оплата через ЮKassa.

Сумма к оплате: {amount}₽

Для оплаты перейдите по ссылке:
[Ссылка на форму оплаты ЮKassa будет здесь]

После успешной оплаты:
1. Вы автоматически получите лицензионный ключ
2. Ссылку на установку расширения
3. Инструкцию по активации

Оплата защищена ЮKassa."""
        
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="← Назад", callback_data=f"buy_{license_type}")]
        ])
        
        await callback.message.edit_text(text, reply_markup=keyboard)


@router.pre_checkout_query()
async def process_pre_checkout_query(pre_checkout_query: PreCheckoutQuery):
    """Обработка предварительного запроса оплаты"""
    # В реальной версии здесь будет проверка платежа в ЮKassa
    await pre_checkout_query.bot.answer_pre_checkout_query(
        pre_checkout_query.id,
        ok=True
    )


@router.message(F.successful_payment)
async def process_successful_payment(message: Message):
    """Обработка успешной оплаты"""
    
    payment_info = message.successful_payment
    amount = payment_info.total_amount // 100  # из копеек в рубли
    
    # Определяем тип лицензии по сумме
    license_type = "forever" if amount == LICENSE_PRICE_LIFETIME else "monthly"
    
    user_id = message.from_user.id
    username = message.from_user.username
    
    # Проверяем, не купил ли уже
    user = db.get_user(user_id)
    if user and user.get("has_license"):
        await message.answer(
            "У вас уже есть активная лицензия. Используйте команду /start чтобы увидеть свой ключ."
        )
        return
    
    # Создаем запись о платеже
    payment_id = payment_info.telegram_payment_charge_id or f"tg_{uuid.uuid4().hex[:8]}"
    db.create_payment(payment_id, user_id, amount, license_type, "pending")
    
    # Генерируем ключ
    is_lifetime = license_type == "forever"
    license_key = await generate_license_for_user(user_id, username, is_lifetime=is_lifetime)
    
    if not license_key:
        await message.answer(
            "Произошла ошибка при генерации ключа. Обратитесь в поддержку: " + SUPPORT_TECH
        )
        return
    
    # Сохраняем лицензию в БД
    db.update_user_license(user_id, license_key)
    db.update_payment_status(payment_id, "completed")
    db.update_payment_license_key(payment_id, license_key)
    
    # Отправляем ключ пользователю
    text = f"""Оплата подтверждена.

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
        [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
    ])
    
    await message.answer(text, reply_markup=keyboard)
