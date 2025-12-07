"""Утилиты для обработки платежей"""
import logging
from typing import Tuple, Optional
from database import Database
from api_client import generate_license_for_user
from config import INSTALLATION_LINK, SUPPORT_TECH

logger = logging.getLogger(__name__)


async def process_successful_payment_internal(
    db: Database,
    payment_data: dict,
    user_id: int,
    username: str
) -> Tuple[Optional[str], str]:
    """
    Внутренняя функция для обработки успешного платежа
    
    Returns:
        Tuple[license_key, message_text]
    """
    payment_id = payment_data["payment_id"]
    license_type = payment_data["license_type"]
    
    # Проверяем, не купил ли уже
    user = db.get_user(user_id)
    if user and user.get("has_license"):
        logger.warning(f"Пользователь {user_id} уже имеет лицензию, но пытается получить еще одну")
        return None, "У вас уже есть активная лицензия. Используйте команду /start чтобы увидеть свой ключ."
    
    # Генерируем ключ
    is_lifetime = license_type == "forever"
    license_key = await generate_license_for_user(user_id, username, is_lifetime=is_lifetime)
    
    if not license_key:
        db.update_yookassa_payment_status(payment_id, "failed")
        return None, f"Произошла ошибка при генерации ключа. Обратитесь в поддержку: {SUPPORT_TECH}"
    
    # Сохраняем лицензию в БД
    db.update_user_license(user_id, license_key)
    db.update_yookassa_payment_status(payment_id, "succeeded", license_key)
    
    # Формируем сообщение в зависимости от типа лицензии
    if license_type == "forever":
        license_text = "Ваш ключ действует бессрочно"
    else:
        from datetime import datetime, timedelta
        expiry_date = datetime.now() + timedelta(days=30)
        license_text = f"Ваша подписка действует до {expiry_date.strftime('%d.%m.%Y')}. За 3 дня до окончания получите уведомление"
    
    text = f"""✅ Оплата подтверждена!

Ваш лицензионный ключ:

`{license_key}`

{license_text}

Ссылка для установки расширения:
{INSTALLATION_LINK}

Инструкция по активации:
1. Установите расширение по ссылке выше
2. Откройте настройки расширения
3. Введите ваш лицензионный ключ
4. Расширение активировано

Расширение начнет работать сразу после активации. Просто продолжайте пользоваться браузером как обычно.

При возникновении вопросов: {SUPPORT_TECH}"""
    
    return license_key, text

