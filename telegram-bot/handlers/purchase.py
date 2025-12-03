"""Обработчики покупки"""
import asyncio
from aiogram import Router, F
from aiogram.types import CallbackQuery
from database import Database
from api_client import generate_license_for_user
from config import DB_PATH, TOTAL_LICENSES, LICENSE_PRICE_LIFETIME, LICENSE_PRICE_MONTHLY, OWNERS_CHAT_LINK, INSTALLATION_LINK, TEST_MODE

router = Router()
db = Database(DB_PATH)


@router.callback_query(F.data == "buy_license")
async def buy_license(callback: CallbackQuery):
    """Обработчик кнопки покупки лицензии"""
    await callback.answer()
    
    user_id = callback.from_user.id
    user = db.get_user(user_id)
    
    # Проверяем, не купил ли уже
    if user and user.get("has_license"):
        await callback.message.edit_text(
            "У тебя уже есть лицензия! Используй команду /start чтобы увидеть свой ключ."
        )
        return
    
    stats = db.get_stats()
    remaining = stats["remaining_licenses"]
    
    if remaining <= 0:
        text = "😔 К сожалению, все 1000 лицензий уже разобраны! Следи за новостями — скоро будет подписка за 150₽/месяц."
        await callback.message.edit_text(text)
        return
    
    text = f"""Отлично, хороший выбор! 🙌

Что ты получаешь за 500₽:
🔹 Вечный доступ к AEGIS Premium (не подписка, а навсегда)
🔹 Проверка ссылок по наведению курсора (главная фича!)
🔹 Доступ к общей базе угроз (она пополняется каждым пользователем)
🔹 Будущие обновления безопасности
🔹 Доступ в закрытый чат владельцев (там делимся новыми угрозами)

Вот как будет выглядеть покупка:
1. Ты жмешь «Оплатить» → переходишь в безопасную платежную систему
2. Оплачиваешь 500₽ картой или криптой
3. Через 10 секунд бот присылает тебе уникальный ключ
4. Устанавливаешь расширение из Chrome Store, вводишь ключ
5. Все, ты защищен!

⚠️ Важно: это предложение ТОЛЬКО для первых 1000 человек.
Сейчас осталось: {remaining} мест

Готов забирать свою лицензию?"""
    
    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Оплатить 500₽ (перейти к оплате)", callback_data="proceed_payment")],
        [InlineKeyboardButton(text="🤔 Есть вопросы", callback_data="faq")],
        [InlineKeyboardButton(text="← Вернуться назад", callback_data="main_menu")]
    ])
    
    await callback.message.edit_text(text, reply_markup=keyboard)


@router.callback_query(F.data == "proceed_payment")
async def proceed_payment(callback: CallbackQuery):
    """Обработчик перехода к оплате"""
    await callback.answer()
    
    if TEST_MODE:
        text = """👌 Супер! Сейчас перенаправлю тебя в платежную систему...

[Пауза 1 секунда]

Ах да, я же забыл сказать! Сейчас мы в режиме бета-теста, поэтому платежи идут в тестовом режиме.

Что это значит:
• Ты можешь протестировать ВСЮ цепочку: оплату → получение ключа → активацию
• Деньги НЕ списываются (это тестовый платеж)
• Ключ ты получаешь НАСТОЯЩИЙ, рабочий
• Потом, когда включим реальные платежи, первые тестеры получат скидку

Хочешь протестировать и получить рабочий ключ прямо сейчас?"""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Да, протестировать! (получить тестовый ключ)", callback_data="test_payment")],
            [InlineKeyboardButton(text="❌ Не сейчас, вернусь позже", callback_data="main_menu")]
        ])
        
        await callback.message.edit_text(text, reply_markup=keyboard)
    else:
        # Здесь будет реальная интеграция с платежной системой
        await callback.message.edit_text(
            "Реальная оплата будет доступна после завершения бета-теста."
        )


@router.callback_query(F.data == "test_payment")
async def test_payment(callback: CallbackQuery):
    """Обработчик тестовой оплаты"""
    await callback.answer()
    
    user_id = callback.from_user.id
    username = callback.from_user.username
    
    # Проверяем, не купил ли уже
    user = db.get_user(user_id)
    if user and user.get("has_license"):
        await callback.message.edit_text(
            "У тебя уже есть лицензия! Используй команду /start чтобы увидеть свой ключ."
        )
        return
    
    # Имитация процесса оплаты
    await callback.message.edit_text("Имитирую процесс оплаты... 💸\n\n[Тип-топ, тип-топ... 3 секунды]")
    await asyncio.sleep(3)
    
    await callback.message.edit_text("✅ Отлично! «Оплата» прошла успешно!\n\nСейчас запрашиваю для тебя лицензионный ключ на нашем сервере...\n\n[Еще 2 секунды]")
    await asyncio.sleep(2)
    
    # Запрашиваем ключ у API (вечная лицензия за 500₽)
    license_key = await generate_license_for_user(user_id, username, is_lifetime=True)
    
    if not license_key:
        text = """Что-то пошло не так. Наши техники уже в курсе. Попробуй через 5 минут или напиши в поддержку."""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="👨💻 Написать в поддержку", callback_data="support")],
            [InlineKeyboardButton(text="🔄 Попробовать снова", callback_data="test_payment")],
            [InlineKeyboardButton(text="🏠 В главное меню", callback_data="main_menu")]
        ])
        
        await callback.message.edit_text(text, reply_markup=keyboard)
        return
    
    # Сохраняем лицензию в БД
    db.update_user_license(user_id, license_key)
    
    # Создаем запись о платеже (тестовом)
    import uuid
    payment_id = f"test_{uuid.uuid4().hex[:8]}"
    db.create_payment(payment_id, user_id, LICENSE_PRICE_LIFETIME, "completed")
    
    text = f"""🎉 ВОТ ТВОЙ КЛЮЧ:

`{license_key}`

(сохрани его в надежном месте!)

---

📋 **Как активировать:**

1. Установи расширение AEGIS из Chrome Web Store (бесплатно)
2. Открой расширение (кликни на иконке в браузере)
3. Найди поле «Активировать Premium версию»
4. Введи ключ выше
5. Готово! Теперь при наведении на ссылки будет появляться проверка

---

🔒 **Важный момент:**
Твой ключ привязан к твоему Telegram-аккаунту. Если что-то случится с расширением или браузером — просто напиши в поддержку, мы вышлем ключ повторно.

Хочешь зайти в чат других владельцев AEGIS? Там мы обсуждаем новые угрозы и фишки."""
    
    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💬 Войти в чат владельцев", url=OWNERS_CHAT_LINK)],
        [InlineKeyboardButton(text="❓ Помощь с установкой", callback_data="help")],
        [InlineKeyboardButton(text="🏠 В главное меню", callback_data="main_menu")]
    ])
    
    await callback.message.edit_text(text, reply_markup=keyboard)

