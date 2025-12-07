"""Админ-команды"""
import logging
import uuid
import traceback
import asyncio
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
from database import Database
from api_client import generate_license_for_user
from config import ADMIN_ID, DB_PATH, YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY, BACKEND_URL, INSTALLATION_LINK, SUPPORT_TECH
import aiohttp
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)
router = Router()
db = Database(DB_PATH)

# ID главного администратора (для критических команд)
MAIN_ADMIN_ID = 696019842


def is_admin(user_id: int) -> bool:
    """Проверка, является ли пользователь админом"""
    return user_id == ADMIN_ID


def is_main_admin(user_id: int) -> bool:
    """Проверка, является ли пользователь главным админом"""
    return user_id == MAIN_ADMIN_ID


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


@router.message(Command("admin_stats"))
async def cmd_admin_stats(message: Message):
    """Детальная статистика по БД"""
    if not is_admin(message.from_user.id):
        await message.answer("Эта команда доступна только администратору.")
        return
    
    stats = db.get_detailed_stats()
    
    # Получаем статистику по платежам ЮKassa
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM yookassa_payments")
    yookassa_total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM yookassa_payments WHERE status = 'succeeded'")
    yookassa_succeeded = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM yookassa_payments WHERE status = 'pending'")
    yookassa_pending = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM yookassa_payments WHERE status = 'canceled'")
    yookassa_canceled = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM yookassa_payments WHERE license_type = 'forever' AND status = 'succeeded'")
    forever_sold = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM yookassa_payments WHERE license_type = 'monthly' AND status = 'succeeded'")
    monthly_sold = cursor.fetchone()[0]
    conn.close()
    
    text = f"""📊 **Детальная статистика БД:**

👥 Пользователей: {stats['users']}
🔑 Лицензий выдано: {stats['licenses']}

💳 **Платежи ЮKassa:**
  Всего: {yookassa_total}
  ✅ Успешно: {yookassa_succeeded}
    • Вечных: {forever_sold}
    • Месячных: {monthly_sold}
  ⏳ В ожидании: {yookassa_pending}
  ❌ Отменено: {yookassa_canceled}

💳 **Старые платежи:**
  Всего: {stats['payments']}
  ✅ Завершено: {stats['completed_payments']}
  ⏳ В ожидании: {stats['pending_payments']}
  ❌ Ошибок: {stats['failed_payments']}"""
    
    await message.answer(text)


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


@router.message(Command("admin_reset_all"))
async def cmd_admin_reset_all(message: Message):
    """Очистка всех данных из БД (только для главного админа)"""
    if not is_main_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только главному администратору.")
        return
    
    # Показываем статистику перед очисткой
    stats = db.get_detailed_stats()
    text = f"""⚠️ **ВНИМАНИЕ! ОПАСНАЯ ОПЕРАЦИЯ!**

Вы собираетесь удалить ВСЕ данные из базы данных:

👥 Пользователей: {stats['users']}
💳 Платежей: {stats['payments']}
🔑 Лицензий: {stats['licenses']}

Эта операция НЕОБРАТИМА!

Вы уверены?"""
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Да, удалить всё", callback_data="confirm_reset_all")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="cancel_reset_all")]
    ])
    
    await message.answer(text, reply_markup=keyboard)


@router.callback_query(F.data == "confirm_reset_all")
async def confirm_reset_all(callback: CallbackQuery):
    """Подтверждение очистки БД"""
    if not is_main_admin(callback.from_user.id):
        await callback.answer("❌ У вас нет прав для выполнения этой операции.", show_alert=True)
        return
    
    await callback.answer()
    
    try:
        # Очищаем БД
        db.reset_all_data()
        
        logger.warning(f"База данных очищена администратором {callback.from_user.id}")
        
        await callback.message.edit_text("✅ База полностью очищена")
    except Exception as e:
        logger.error(f"Ошибка при очистке БД: {e}", exc_info=True)
        await callback.message.edit_text(f"❌ Ошибка при очистке БД: {e}")


@router.callback_query(F.data == "cancel_reset_all")
async def cancel_reset_all(callback: CallbackQuery):
    """Отмена очистки БД"""
    await callback.answer("Операция отменена")
    await callback.message.edit_text("❌ Очистка базы данных отменена")


@router.message(Command("debug_payment"))
async def cmd_debug_payment(message: Message):
    """Проверка связи с backend платежей (Aegis Payments)"""
    user_id = message.from_user.id
    logger.info(f"/debug_payment вызван пользователем {user_id}")

    await message.answer("🔧 Тестирую подключение к платежному серверу...")

    url = "https://api.aegis.builders/payments/debug"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    await message.answer(f"❌ Ошибка: сервер вернул статус {resp.status}")
                    return
                
                data = await resp.json()
                await message.answer(f"✅ Платежный сервер отвечает:\n\n{data}")
                return

    except asyncio.TimeoutError:
        await message.answer("❌ Таймаут: сервер не ответил за 10 секунд")
    except Exception as e:
        logger.error(f"Ошибка debug_payment: {e}", exc_info=True)
        await message.answer(f"❌ Ошибка при подключении к платежному серверу:\n{e}")


# ==================== ОТЛАДКА ПЛАТЕЖЕЙ ====================

async def backend_check_payment(payment_id: str) -> Optional[Dict]:
    """Проверка статуса платежа напрямую через ЮKassa API (для обратной совместимости)"""
    # Используем функцию из purchase.py, которая теперь проверяет напрямую через ЮKassa
    from handlers.purchase import check_payment_direct_yookassa
    return await check_payment_direct_yookassa(payment_id)


async def debug_payment_full_internal(payment_id: str) -> str:
    """Внутренняя функция для полной отладки платежа"""
    result = []
    result.append(f"🔍 ПОЛНАЯ ОТЛАДКА ПЛАТЕЖА: `{payment_id}`\n")
    
    # 1. ИНФОРМАЦИЯ ИЗ БАЗЫ ДАННЫХ
    result.append("📊 ИЗ БАЗЫ ДАННЫХ:")
    payment_db = db.get_yookassa_payment(payment_id)
    
    if not payment_db:
        result.append("❌ Нет записи в БД")
        result.append("\n🎯 ВЫВОД:")
        result.append("❌ ПРОБЛЕМА: Платеж не найден в базе данных бота")
        result.append("💡 РЕШЕНИЕ: Проверьте правильность payment_id или создайте платеж заново")
        return "\n".join(result)
    
    result.append(f"• ID: `{payment_db.get('payment_id', 'N/A')}`")
    result.append(f"• Сумма: {payment_db.get('amount', 0) / 100}₽")
    result.append(f"• Тип: {payment_db.get('license_type', 'N/A')}")
    result.append(f"• Статус в БД: {payment_db.get('status', 'N/A')}")
    result.append(f"• Ключ в БД: {payment_db.get('license_key', 'НЕТ')}")
    result.append(f"• User ID (из БД): {payment_db.get('user_id', 'N/A')}")
    result.append(f"• Создан: {payment_db.get('created_at', 'N/A')}")
    result.append(f"• Обновлен: {payment_db.get('updated_at', 'N/A')}")
    
    user_id = payment_db.get('user_id')
    license_type = payment_db.get('license_type', 'forever')
    status_db = payment_db.get('status', 'pending')
    
    # 2. ИНФОРМАЦИЯ ИЗ BACKEND
    result.append("\n🔄 ЗАПРОС К BACKEND:")
    status_data = await backend_check_payment(payment_id)
    
    if not status_data:
        result.append("❌ Backend не вернул данные или ошибка запроса")
        result.append("\n🎯 ВЫВОД:")
        result.append("❌ ПРОБЛЕМА: Backend не отвечает или возвращает ошибку")
        result.append("💡 РЕШЕНИЕ: Проверьте доступность backend API и логи сервера")
        return "\n".join(result)
    
    backend_status = status_data.get("status", "unknown")
    result.append(f"• Статус от ЮKassa: {backend_status}")
    
    # Метаданные из backend (если есть)
    metadata = status_data.get("metadata", {})
    user_id_from_metadata = metadata.get("user_id") or metadata.get("telegram_id")
    license_type_from_metadata = metadata.get("license_type")
    
    if user_id_from_metadata:
        result.append(f"• User ID из метаданных: {user_id_from_metadata}")
    else:
        result.append("• User ID из метаданных: ❌ НЕТ")
    
    if license_type_from_metadata:
        result.append(f"• License type из метаданных: {license_type_from_metadata}")
    else:
        result.append("• License type из метаданных: ❌ НЕТ")
    
    # Проверяем соответствие
    if user_id_from_metadata and str(user_id_from_metadata) != str(user_id):
        result.append(f"⚠️ ВНИМАНИЕ: User ID в БД ({user_id}) не совпадает с метаданными ({user_id_from_metadata})")
    
    if license_type_from_metadata and license_type_from_metadata != license_type:
        result.append(f"⚠️ ВНИМАНИЕ: License type в БД ({license_type}) не совпадает с метаданными ({license_type_from_metadata})")
    
    # 3. ПРОВЕРКА ГЕНЕРАЦИИ КЛЮЧА
    result.append("\n🔑 ГЕНЕРАЦИЯ КЛЮЧА:")
    
    if backend_status == "succeeded":
        # Проверяем, есть ли уже ключ
        existing_key = payment_db.get('license_key')
        user = db.get_user(user_id) if user_id else None
        
        if existing_key or (user and user.get('has_license')):
            key_to_show = existing_key or user.get('license_key', 'N/A')
            result.append(f"✅ Ключ уже существует: `{key_to_show}`")
        else:
            # Пробуем сгенерировать ключ
            result.append("Пробую сгенерировать ключ...")
            try:
                is_lifetime = license_type == "forever"
                username = user.get('username', '') if user else ''
                license_key = await generate_license_for_user(user_id, username, is_lifetime=is_lifetime)
                
                if license_key:
                    result.append(f"✅ Ключ сгенерирован: `{license_key}`")
                else:
                    result.append("❌ Ошибка: Не удалось сгенерировать ключ через API")
            except Exception as e:
                result.append(f"❌ Ошибка генерации ключа: {str(e)}")
                logger.error(f"Ошибка генерации ключа для payment {payment_id}: {e}", exc_info=True)
    elif backend_status == "pending":
        result.append("⏳ Статус pending - генерация ключа не требуется")
    elif backend_status == "canceled":
        result.append("❌ Платеж отменен - генерация ключа не требуется")
    else:
        result.append(f"❓ Неизвестный статус {backend_status} - генерация ключа не требуется")
    
    # 4. СТАТУС ОТПРАВКИ
    result.append("\n📤 ОТПРАВКА ПОЛЬЗОВАТЕЛЮ:")
    result.append(f"• User ID для отправки: {user_id}")
    
    if user_id:
        user = db.get_user(user_id)
        if user and user.get('has_license'):
            result.append("✅ Пользователь имеет лицензию в БД")
            result.append(f"• Ключ пользователя: `{user.get('license_key', 'N/A')}`")
        else:
            result.append("❌ Пользователь не имеет лицензии в БД")
    else:
        result.append("❌ User ID не найден")
    
    # 5. ВЫЯВЛЕНИЕ ПРОБЛЕМЫ
    result.append("\n🎯 ВЫВОД:")
    
    problems = []
    solutions = []
    
    if not payment_db:
        problems.append("Нет записи в БД")
        solutions.append("Создать платеж заново")
    
    if not status_data:
        problems.append("Backend не отвечает")
        solutions.append("Проверить доступность backend API")
    
    if backend_status == "pending" and status_db == "succeeded":
        problems.append("Backend возвращает pending, хотя в БД succeeded")
        solutions.append("Проверить синхронизацию статусов между backend и ЮKassa")
    
    if backend_status == "succeeded" and not user_id_from_metadata:
        problems.append("Нет user_id в метаданных платежа")
        solutions.append("Проверить создание платежа - метаданные должны содержать user_id")
    
    if backend_status == "succeeded":
        existing_key = payment_db.get('license_key')
        user = db.get_user(user_id) if user_id else None
        has_key = existing_key or (user and user.get('has_license'))
        
        if not has_key:
            problems.append("Платеж succeeded, но ключ не выдан")
            solutions.append("Использовать команду /force_check для принудительной выдачи ключа")
    
    if not problems:
        result.append("✅ Все этапы пройдены успешно!")
        result.append("• Платеж найден в БД")
        result.append("• Backend отвечает корректно")
        if backend_status == "succeeded":
            result.append("• Ключ выдан пользователю")
    else:
        result.append("❌ ОБНАРУЖЕНЫ ПРОБЛЕМЫ:")
        for i, problem in enumerate(problems, 1):
            result.append(f"{i}. {problem}")
        result.append("\n💡 РЕШЕНИЯ:")
        for i, solution in enumerate(solutions, 1):
            result.append(f"{i}. {solution}")
    
    return "\n".join(result)


@router.message(Command("debug_payment_full"))
async def cmd_debug_payment_full(message: Message):
    """Полная отладка платежа"""
    if not is_main_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только главному администратору.")
        return
    
    parts = message.text.split()
    if len(parts) > 1:
        payment_id = parts[1]
        logger.info(f"Отладка платежа {payment_id} запрошена админом {message.from_user.id}")
        result = await debug_payment_full_internal(payment_id)
    else:
        # Показываем последние 3 платежа
        logger.info(f"Отладка последних платежей запрошена админом {message.from_user.id}")
        
        # Получаем последние платежи из БД
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payment_id FROM yookassa_payments ORDER BY created_at DESC LIMIT 3"
        )
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            await message.answer("❌ В базе данных нет платежей")
            return
        
        result = "🔍 ПОСЛЕДНИЕ 3 ПЛАТЕЖА:\n\n"
        for i, row in enumerate(rows, 1):
            payment_id = row[0]
            result += f"--- ПЛАТЕЖ {i}: {payment_id} ---\n"
            result += await debug_payment_full_internal(payment_id)
            result += "\n\n"
    
    # Разбиваем на части если сообщение слишком длинное
    max_length = 4000
    if len(result) > max_length:
        parts = [result[i:i+max_length] for i in range(0, len(result), max_length)]
        for part in parts:
            await message.answer(part, parse_mode="Markdown")
    else:
        await message.answer(result, parse_mode="Markdown")


@router.message(Command("debug_last_payments"))
async def cmd_debug_last_payments(message: Message):
    """Отладка последних 5 платежей"""
    if not is_main_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только главному администратору.")
        return
    
    logger.info(f"Отладка последних платежей запрошена админом {message.from_user.id}")
    
    # Получаем последние 5 платежей из БД
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT payment_id FROM yookassa_payments ORDER BY created_at DESC LIMIT 5"
    )
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        await message.answer("❌ В базе данных нет платежей")
        return
    
    result = "🔍 ПОСЛЕДНИЕ 5 ПЛАТЕЖЕЙ:\n\n"
    for i, row in enumerate(rows, 1):
        payment_id = row[0]
        result += f"═══════════════════════════════════\n"
        result += f"ПЛАТЕЖ {i}: {payment_id}\n"
        result += f"═══════════════════════════════════\n"
        result += await debug_payment_full_internal(payment_id)
        result += "\n\n"
    
    # Разбиваем на части
    max_length = 4000
    if len(result) > max_length:
        parts = [result[i:i+max_length] for i in range(0, len(result), max_length)]
        for part in parts:
            await message.answer(part, parse_mode="Markdown")
    else:
        await message.answer(result, parse_mode="Markdown")


@router.message(Command("debug_user_payments"))
async def cmd_debug_user_payments(message: Message):
    """Отладка всех платежей пользователя"""
    if not is_main_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только главному администратору.")
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("Использование: /debug_user_payments @username или /debug_user_payments <user_id>")
        return
    
    identifier = parts[1].strip('@')
    
    # Пытаемся найти user_id
    try:
        user_id = int(identifier)
    except ValueError:
        # Ищем по username
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (identifier,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            await message.answer(f"❌ Пользователь @{identifier} не найден в базе данных")
            return
        user_id = row[0]
    
    logger.info(f"Отладка платежей пользователя {user_id} запрошена админом {message.from_user.id}")
    
    # Получаем все платежи пользователя
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT payment_id FROM yookassa_payments WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        await message.answer(f"❌ У пользователя {user_id} нет платежей в базе данных")
        return
    
    result = f"🔍 ПЛАТЕЖИ ПОЛЬЗОВАТЕЛЯ {user_id}:\n\n"
    for i, row in enumerate(rows, 1):
        payment_id = row[0]
        result += f"═══════════════════════════════════\n"
        result += f"ПЛАТЕЖ {i}: {payment_id}\n"
        result += f"═══════════════════════════════════\n"
        result += await debug_payment_full_internal(payment_id)
        result += "\n\n"
    
    # Разбиваем на части
    max_length = 4000
    if len(result) > max_length:
        parts = [result[i:i+max_length] for i in range(0, len(result), max_length)]
        for part in parts:
            await message.answer(part, parse_mode="Markdown")
    else:
        await message.answer(result, parse_mode="Markdown")


@router.message(Command("force_check"))
async def cmd_force_check(message: Message):
    """Принудительная проверка и выдача ключа"""
    if not is_main_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только главному администратору.")
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("Использование: /force_check <payment_id>")
        return
    
    payment_id = parts[1]
    logger.info(f"Принудительная проверка платежа {payment_id} запрошена админом {message.from_user.id}")
    
    await message.answer(f"🔧 Принудительная проверка платежа {payment_id}...")
    
    # Получаем платеж из БД
    payment_db = db.get_yookassa_payment(payment_id)
    if not payment_db:
        await message.answer(f"❌ Платеж {payment_id} не найден в базе данных")
        return
    
    user_id = payment_db.get('user_id')
    license_type = payment_db.get('license_type', 'forever')
    
    # Проверяем статус напрямую через ЮKassa API
    from config import YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY
    import aiohttp
    from aiohttp import BasicAuth
    
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        await message.answer("❌ Ключи ЮKassa не настроены в конфиге бота")
        return
    
    url = f"https://api.yookassa.ru/v3/payments/{payment_id}"
    auth = BasicAuth(login=YOOKASSA_SHOP_ID, password=YOOKASSA_SECRET_KEY)
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, auth=auth, timeout=15) as resp:
                if resp.status != 200:
                    await message.answer(f"❌ Не удалось получить статус платежа от ЮKassa (HTTP {resp.status})")
                    return
                
                data = await resp.json()
                status_data = {
                    "status": data.get("status", "pending"),
                    "metadata": {
                        "user_id": str(data.get("metadata", {}).get("telegram_id") or user_id or ""),
                        "license_type": data.get("metadata", {}).get("license_type") or license_type
                    },
                    "amount": f"{float(data.get('amount', {}).get('value', 0)):.2f}"
                }
    except Exception as e:
        logger.error(f"Ошибка при проверке платежа через ЮKassa: {e}", exc_info=True)
        await message.answer(f"❌ Ошибка при проверке платежа: {str(e)}")
        return
    
    backend_status = status_data.get("status")
    
    if backend_status != "succeeded":
        await message.answer(
            f"❌ Платеж имеет статус {backend_status}, а не succeeded.\n"
            f"Выдача ключа возможна только для succeeded платежей."
        )
        return
    
    # Проверяем, не выдан ли уже ключ
    user = db.get_user(user_id) if user_id else None
    if user and user.get('has_license'):
        existing_key = user.get('license_key', 'N/A')
        await message.answer(
            f"✅ Пользователь уже имеет лицензию:\n`{existing_key}`\n\n"
            f"Статус платежа обновлен на succeeded."
        )
        db.update_yookassa_payment_status(payment_id, "succeeded", existing_key)
        return
    
    # Генерируем ключ
    await message.answer("🔑 Генерирую ключ...")
    try:
        is_lifetime = license_type == "forever"
        username = user.get('username', '') if user else ''
        license_key = await generate_license_for_user(user_id, username, is_lifetime=is_lifetime)
        
        if not license_key:
            await message.answer("❌ Не удалось сгенерировать ключ через API")
            return
        
        # Сохраняем ключ в БД
        db.update_user_license(user_id, license_key)
        db.update_yookassa_payment_status(payment_id, "succeeded", license_key)
        
        # Формируем сообщение
        if license_type == "forever":
            license_text = "Ваш ключ действует бессрочно"
        else:
            from datetime import datetime, timedelta
            expiry_date = datetime.now() + timedelta(days=30)
            license_text = f"Ваша подписка действует до {expiry_date.strftime('%d.%m.%Y')}"
        
        result = f"""✅ Ключ успешно выдан!

Платеж: `{payment_id}`
Пользователь: {user_id}
Тип лицензии: {license_type}

Ключ: `{license_key}`

{license_text}

Ссылка для установки:
{INSTALLATION_LINK}"""
        
        await message.answer(result, parse_mode="Markdown")
        
        # Отправляем ключ пользователю
        try:
            await message.bot.send_message(
                user_id,
                f"""✅ Ваш лицензионный ключ:

`{license_key}`

{license_text}

Ссылка для установки расширения:
{INSTALLATION_LINK}

Инструкция по активации:
1. Установите расширение по ссылке выше
2. Откройте настройки расширения
3. Введите ваш лицензионный ключ
4. Расширение активировано

При возникновении вопросов: {SUPPORT_TECH}""",
                parse_mode="Markdown"
            )
            await message.answer(f"✅ Ключ отправлен пользователю {user_id}")
        except Exception as send_error:
            logger.error(f"Ошибка отправки ключа пользователю {user_id}: {send_error}", exc_info=True)
            await message.answer(f"⚠️ Ключ сохранен в БД, но не удалось отправить пользователю: {send_error}")
        
    except Exception as e:
        logger.error(f"Ошибка при принудительной выдаче ключа: {e}", exc_info=True)
        await message.answer(f"❌ Ошибка: {str(e)}")


@router.message(Command("check_yookassa_direct"))
async def cmd_check_yookassa_direct(message: Message):
    """Прямая проверка платежа через ЮKassa API (для отладки)"""
    if not is_main_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только главному администратору.")
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("Использование: /check_yookassa_direct <payment_id>")
        return
    
    payment_id = parts[1]
    logger.info(f"Прямая проверка платежа {payment_id} через ЮKassa API запрошена админом {message.from_user.id}")
    
    await message.answer(f"🔍 Проверяю платеж {payment_id} напрямую через ЮKassa API...")
    
    # Импортируем конфиг
    from config import YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY
    
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        await message.answer("❌ Ключи ЮKassa не настроены в конфиге бота")
        return
    
    import aiohttp
    from aiohttp import BasicAuth
    
    url = f"https://api.yookassa.ru/v3/payments/{payment_id}"
    auth = BasicAuth(login=YOOKASSA_SHOP_ID, password=YOOKASSA_SECRET_KEY)
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, auth=auth, timeout=15) as resp:
                status_code = resp.status
                response_text = await resp.text()
                
                # Формируем результат без Markdown для избежания ошибок парсинга
                result = f"""🔍 Прямой запрос к ЮKassa API:

URL: {url}
HTTP Status: {status_code}

Ответ (первые 1500 символов):
{response_text[:1500]}"""
                
                if status_code == 200:
                    try:
                        import json
                        data = json.loads(response_text)
                        yookassa_status = data.get("status", "unknown")
                        paid = data.get("paid", False)
                        captured_at = data.get("captured_at")
                        created_at = data.get("created_at")
                        metadata = data.get("metadata", {})
                        
                        result += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Статус: {yookassa_status}
Оплачен (paid): {paid}
Создан: {created_at}
Захвачен (captured_at): {captured_at or "N/A"}

Метаданные:
"""
                        # Безопасно форматируем метаданные
                        try:
                            metadata_str = json.dumps(metadata, indent=2, ensure_ascii=False)
                            result += metadata_str[:500]  # Ограничиваем длину
                            if len(metadata_str) > 500:
                                result += "\n... (обрезано)"
                        except Exception:
                            result += str(metadata)[:500]
                    except Exception as parse_err:
                        result += f"\n\n⚠️ Не удалось распарсить JSON: {parse_err}"
                
                # Отправляем без parse_mode, чтобы избежать ошибок парсинга
                await message.answer(result)
                
    except aiohttp.ClientError as e:
        await message.answer(f"❌ Ошибка сети при запросе к ЮKassa: {e}")
    except Exception as e:
        logger.error(f"Ошибка при прямой проверке платежа: {e}", exc_info=True)
        await message.answer(f"❌ Ошибка: {str(e)}")

