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
from config import ADMIN_ID, DB_PATH, YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY

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
    """Тест подключения к ЮKassa"""
    user_id = message.from_user.id
    logger.info(f"Команда /debug_payment вызвана пользователем {user_id}")
    
    try:
        # Сразу отвечаем, чтобы пользователь знал, что команда работает
        await message.answer("🔧 Тестирую подключение к ЮKassa...")
        logger.info(f"Отправлено начальное сообщение пользователю {user_id}")
        
        from yookassa import Configuration, Payment
        from yookassa.domain.exceptions import ApiError
        
        logger.info(f"Импорт yookassa успешен. Настраиваю конфигурацию...")
        
        # 1. Конфигурация (ОБЯЗАТЕЛЬНО ПЕРВЫМ!)
        Configuration.account_id = YOOKASSA_SHOP_ID
        Configuration.secret_key = YOOKASSA_SECRET_KEY
        
        logger.info(f"Конфигурация установлена: account_id={YOOKASSA_SHOP_ID}, secret_key={'установлен' if YOOKASSA_SECRET_KEY else 'не установлен'}")
        
        # 2. Простейший платеж
        idempotence_key = str(uuid.uuid4())
        
        payment_data = {
            "amount": {
                "value": "1.00",  # СТРОКА "1.00" а не число 1
                "currency": "RUB"
            },
            "confirmation": {
                "type": "redirect",
                "return_url": "https://t.me"  # заменить на реальный username если нужно
            },
            "capture": True,
            "description": "Тест подключения к ЮKassa"
        }
        
        logger.info(f"Создание тестового платежа с idempotence_key: {idempotence_key}")
        logger.info(f"Payment data: {payment_data}")
        
        # Payment.create() - синхронный метод, выполняем в отдельном потоке
        def _create_payment_sync():
            try:
                logger.info("Вызываю Payment.create в синхронном потоке...")
                result = Payment.create(payment_data, idempotence_key)
                logger.info(f"Payment.create успешно выполнен. Payment ID: {result.id}")
                return result
            except Exception as sync_error:
                logger.error(f"Ошибка в синхронном вызове Payment.create: {sync_error}", exc_info=True)
                raise
        
        logger.info("Запускаю Payment.create в отдельном потоке...")
        loop = asyncio.get_event_loop()
        payment = await loop.run_in_executor(None, _create_payment_sync)
        logger.info(f"Payment.create успешно выполнен. Payment ID: {payment.id}")
        
        response_text = (
            f"✅ Успешное подключение!\n\n"
            f"Payment ID: `{payment.id}`\n"
            f"Статус: {payment.status}\n"
            f"URL для оплаты: {payment.confirmation.confirmation_url}\n\n"
            f"Idempotence key: `{idempotence_key}`"
        )
        
        logger.info("Отправляю ответ пользователю...")
        await message.answer(response_text)
        logger.info("Ответ отправлен успешно")
        
    except ApiError as e:
        # Полный traceback
        error_trace = traceback.format_exc()
        
        logger.error(f"Ошибка API ЮKassa при debug_payment: {e}", exc_info=True)
        
        error_details = f"❌ Ошибка API ЮKassa:\n\n"
        error_details += f"Тип ошибки: {type(e).__name__}\n"
        error_details += f"Код ошибки: {getattr(e, 'code', 'N/A')}\n"
        error_details += f"Описание: {getattr(e, 'description', str(e))}\n"
        error_details += f"Параметр: {getattr(e, 'parameter', 'N/A')}\n\n"
        error_details += f"Полный traceback:\n```\n{error_trace[:1500]}\n```"
        
        try:
            await message.answer(error_details)
        except Exception as send_error:
            logger.error(f"Не удалось отправить сообщение об ошибке: {send_error}")
        
    except Exception as e:
        # Полный traceback
        error_trace = traceback.format_exc()
        
        logger.error(f"Ошибка при debug_payment: {e}", exc_info=True)
        
        error_details = f"❌ Ошибка подключения к ЮKassa:\n\n"
        error_details += f"Тип ошибки: {type(e).__name__}\n"
        error_details += f"Сообщение: {str(e)}\n\n"
        error_details += f"Полный traceback:\n```\n{error_trace[:1500]}\n```"
        
        try:
            await message.answer(error_details)
        except Exception as send_error:
            logger.error(f"Не удалось отправить сообщение об ошибке: {send_error}")

