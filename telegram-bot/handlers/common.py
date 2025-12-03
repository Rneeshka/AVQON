"""Общие обработчики"""
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.filters import Command
from database import Database
from config import DB_PATH, TOTAL_LICENSES, LICENSE_PRICE, OWNERS_CHAT_LINK, INSTALLATION_LINK

router = Router()
db = Database(DB_PATH)


@router.message(Command("start"))
async def cmd_start(message: Message):
    """Обработчик команды /start"""
    user_id = message.from_user.id
    username = message.from_user.username
    
    # Создаем или получаем пользователя
    user = db.get_user(user_id)
    if not user:
        db.create_user(user_id, username)
        user = db.get_user(user_id)
    
    # Если у пользователя уже есть лицензия
    if user and user.get("has_license"):
        license_key = user.get("license_key", "N/A")
        text = f"""С возвращением! 👋

Вижу, у тебя уже есть лицензия AEGIS Premium. Супер!

Нужна помощь с:
• Ключ: `{license_key}`
• Ссылка на чат владельцев: {OWNERS_CHAT_LINK}
• Инструкция по установке: {INSTALLATION_LINK}

Что-то не работает или есть вопросы?"""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="💬 Перейти в чат", url=OWNERS_CHAT_LINK)],
            [InlineKeyboardButton(text="❓ Нужна помощь", callback_data="help")],
            [InlineKeyboardButton(text="🔑 Посмотреть мой ключ", callback_data="show_key")],
            [InlineKeyboardButton(text="🏠 Главное меню", callback_data="main_menu")]
        ])
        
        await message.answer(text, reply_markup=keyboard)
        return
    
    # Первое приветствие для новых пользователей
    stats = db.get_stats()
    licenses_count = stats["licenses_count"]
    remaining = stats["remaining_licenses"]
    
    text = f"""Привет! 👋

У меня плохие новости: каждый день крипто-инвесторы теряют деньги из-за фишинга. Хорошие новости: теперь есть защита.

AEGIS — это броня для твоего браузера. Установи расширение один раз, и оно будет проверять ВСЕ ссылки, на которые ты наводишь курсор. Подозрительная? Сразу увидишь красное предупреждение.

🔥 ГОРЯЧЕЕ ПРЕДЛОЖЕНИЕ (только сейчас!):
Первым 1000 человек — вечная лицензия за 500₽. Это разово и навсегда. Потом будет только подписка за 150₽ в месяц.

Уже забрали: {licenses_count} из {TOTAL_LICENSES}
(да, счетчик реальный и обновляется)

Что хочешь сделать?"""
    
    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🛒 Забрать вечную лицензию за 500₽", callback_data="buy_license")],
        [InlineKeyboardButton(text="🤔 Как это работает? Покажи!", callback_data="how_it_works")],
        [InlineKeyboardButton(text="❓ Частые вопросы", callback_data="faq")],
        [InlineKeyboardButton(text="👨💻 Поддержка", callback_data="support")]
    ])
    
    await message.answer(text, reply_markup=keyboard)


@router.callback_query(F.data == "main_menu")
async def main_menu(callback: CallbackQuery):
    """Вернуться в главное меню"""
    await callback.answer()
    user_id = callback.from_user.id
    user = db.get_user(user_id)
    
    if user and user.get("has_license"):
        # Показываем меню для пользователя с лицензией
        license_key = user.get("license_key", "N/A")
        text = f"""С возвращением! 👋

Вижу, у тебя уже есть лицензия AEGIS Premium. Супер!

Нужна помощь с:
• Ключ: `{license_key}`
• Ссылка на чат владельцев: {OWNERS_CHAT_LINK}
• Инструкция по установке: {INSTALLATION_LINK}

Что-то не работает или есть вопросы?"""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="💬 Перейти в чат", url=OWNERS_CHAT_LINK)],
            [InlineKeyboardButton(text="❓ Нужна помощь", callback_data="help")],
            [InlineKeyboardButton(text="🔑 Посмотреть мой ключ", callback_data="show_key")]
        ])
    else:
        # Главное меню для новых пользователей
        stats = db.get_stats()
        licenses_count = stats["licenses_count"]
        
        text = f"""Привет! 👋

У меня плохие новости: каждый день крипто-инвесторы теряют деньги из-за фишинга. Хорошие новости: теперь есть защита.

AEGIS — это броня для твоего браузера. Установи расширение один раз, и оно будет проверять ВСЕ ссылки, на которые ты наводишь курсор. Подозрительная? Сразу увидишь красное предупреждение.

🔥 ГОРЯЧЕЕ ПРЕДЛОЖЕНИЕ (только сейчас!):
Первым 1000 человек — вечная лицензия за 500₽. Это разово и навсегда. Потом будет только подписка за 150₽ в месяц.

Уже забрали: {licenses_count} из {TOTAL_LICENSES}
(да, счетчик реальный и обновляется)

Что хочешь сделать?"""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🛒 Забрать вечную лицензию за 500₽", callback_data="buy_license")],
            [InlineKeyboardButton(text="🤔 Как это работает? Покажи!", callback_data="how_it_works")],
            [InlineKeyboardButton(text="❓ Частые вопросы", callback_data="faq")],
            [InlineKeyboardButton(text="👨💻 Поддержка", callback_data="support")]
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
        text = f"""🔑 **Твой лицензионный ключ:**

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
Твой ключ привязан к твоему Telegram-аккаунту. Если что-то случится с расширением или браузером — просто напиши в поддержку, мы вышлем ключ повторно."""
        
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="💬 Войти в чат владельцев", url=OWNERS_CHAT_LINK)],
            [InlineKeyboardButton(text="❓ Помощь с установкой", callback_data="help")],
            [InlineKeyboardButton(text="🏠 В главное меню", callback_data="main_menu")]
        ])
        
        await callback.message.edit_text(text, reply_markup=keyboard)
    else:
        await callback.answer("У тебя пока нет лицензии", show_alert=True)

