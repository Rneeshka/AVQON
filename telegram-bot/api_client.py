"""Клиент для работы с API генерации ключей"""
import aiohttp
import logging
from typing import Optional
from config import API_KEY, API_URL

logger = logging.getLogger(__name__)


async def generate_license_for_user(user_id: int, username: str, is_lifetime: bool = True) -> Optional[str]:
    """
    Запрашивает ключ у нашего сервера через существующий endpoint /admin/api-keys/create
    Возвращает ключ или None в случае ошибки
    
    Args:
        user_id: ID пользователя Telegram
        username: Username пользователя Telegram
        is_lifetime: True для вечной лицензии (500₽), False для месячной (150₽)
    """
    headers = {"Authorization": f"Bearer {API_KEY}"}
    # Используем существующий endpoint для создания ключей
    expires_days = 36500 if is_lifetime else 30  # Вечная (100 лет) или месячная (30 дней)
    license_type = "Lifetime" if is_lifetime else "Monthly"
    
    data = {
        "user_id": str(user_id),
        "username": username or "",
        "name": f"Telegram User {user_id}",
        "description": f"{license_type} license for Telegram user {user_id}" + (f" (@{username})" if username else ""),
        "access_level": "premium",
        "daily_limit": 1000,
        "hourly_limit": 100,
        "expires_days": expires_days
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(API_URL, json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    result = await response.json()
                    # Проверяем оба варианта ответа (license_key для бота, api_key для обычного использования)
                    license_key = result.get("license_key") or result.get("api_key")
                    if license_key:
                        logger.info(f"Получен ключ для пользователя {user_id}: {license_key}")
                        return license_key
                    else:
                        logger.error(f"API вернул успех, но без ключа: {result}")
                        return None
                else:
                    error_text = await response.text()
                    logger.error(f"Ошибка API: {response.status} - {error_text}")
                    return None
    except aiohttp.ClientError as e:
        logger.error(f"Ошибка соединения с API: {e}")
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при запросе ключа: {e}", exc_info=True)
        return None

