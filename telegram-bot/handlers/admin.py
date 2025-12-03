"""Админ-команды"""
from aiogram import Router, F
from aiogram.types import Message
from aiogram.filters import Command
from database import Database
from api_client import generate_license_for_user
from config import ADMIN_ID, DB_PATH

router = Router()
db = Database(DB_PATH)


def is_admin(user_id: int) -> bool:
    """Проверка, является ли пользователь админом"""
    return user_id == ADMIN_ID


@router.message(Command("stats"))
async def cmd_stats(message: Message):
    """Статистика для админа"""
    if not is_admin(message.from_user.id):
        await message.answer("Эта команда доступна только администратору.")
        return
    
    stats = db.get_stats()
    text = f"""📊 **Статистика бота:**

👥 Всего пользователей: {stats['total_users']}
🔑 Выдано лицензий: {stats['licenses_count']}
🎫 Осталось лицензий: {stats['remaining_licenses']}"""
    
    await message.answer(text, parse_mode="Markdown")


@router.message(Command("user"))
async def cmd_user(message: Message):
    """Информация о пользователе"""
    if not is_admin(message.from_user.id):
        await message.answer("Эта команда доступна только администратору.")
        return
    
    # Парсим команду: /user 123456789
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("Использование: /user <user_id>")
        return
    
    try:
        user_id = int(parts[1])
    except ValueError:
        await message.answer("Неверный формат user_id. Используй число.")
        return
    
    user = db.get_user(user_id)
    if not user:
        await message.answer(f"Пользователь {user_id} не найден в базе.")
        return
    
    has_license = "✅ Да" if user.get("has_license") else "❌ Нет"
    license_key = user.get("license_key", "N/A")
    username = user.get("username", "N/A")
    created_at = user.get("created_at", "N/A")
    
    text = f"""👤 **Информация о пользователе:**

ID: `{user_id}`
Username: @{username}
Лицензия: {has_license}
Ключ: `{license_key}`
Зарегистрирован: {created_at}"""
    
    await message.answer(text, parse_mode="Markdown")


@router.message(Command("give_key"))
async def cmd_give_key(message: Message):
    """Выдать ключ вручную"""
    if not is_admin(message.from_user.id):
        await message.answer("Эта команда доступна только администратору.")
        return
    
    # Парсим команду: /give_key 123456789
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("Использование: /give_key <user_id>")
        return
    
    try:
        user_id = int(parts[1])
    except ValueError:
        await message.answer("Неверный формат user_id. Используй число.")
        return
    
    user = db.get_user(user_id)
    if not user:
        await message.answer(f"Пользователь {user_id} не найден в базе. Создаю...")
        db.create_user(user_id)
        user = db.get_user(user_id)
    
    if user and user.get("has_license"):
        await message.answer(f"У пользователя {user_id} уже есть лицензия: `{user.get('license_key')}`", parse_mode="Markdown")
        return
    
    # Запрашиваем ключ у API
    username = user.get("username") if user else None
    await message.answer(f"Запрашиваю ключ для пользователя {user_id}...")
    
    license_key = await generate_license_for_user(user_id, username or "")
    
    if not license_key:
        await message.answer(f"❌ Ошибка при получении ключа от API для пользователя {user_id}.")
        return
    
    # Сохраняем в БД
    db.update_user_license(user_id, license_key)
    
    await message.answer(f"✅ Ключ успешно выдан пользователю {user_id}:\n`{license_key}`", parse_mode="Markdown")
    
    # Отправляем ключ пользователю
    try:
        await message.bot.send_message(
            user_id,
            f"🎉 Тебе выдан лицензионный ключ AEGIS Premium!\n\n`{license_key}`\n\nИспользуй команду /start для инструкций по активации.",
            parse_mode="Markdown"
        )
    except Exception as e:
        await message.answer(f"⚠️ Ключ сохранен в БД, но не удалось отправить пользователю: {e}")

