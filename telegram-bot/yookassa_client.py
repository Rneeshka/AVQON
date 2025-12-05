"""Клиент для работы с API ЮKassa"""
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

# Безопасный импорт yookassa
try:
    from yookassa import Configuration, Payment
    from yookassa.domain.exceptions import ApiError
    from config import YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY, YOOKASSA_TEST_MODE
    
    # Проверяем наличие ключей
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.warning("Ключи ЮKassa не настроены. Платежи через ЮKassa не будут работать.")
        YOOKASSA_AVAILABLE = False
        Payment = None
        ApiError = Exception
    else:
        # Настройка ЮKassa
        Configuration.account_id = YOOKASSA_SHOP_ID
        Configuration.secret_key = YOOKASSA_SECRET_KEY
        YOOKASSA_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Библиотека yookassa не установлена: {e}. Установите: pip install yookassa")
    YOOKASSA_AVAILABLE = False
    Payment = None
    ApiError = Exception
except Exception as e:
    logger.error(f"Ошибка при инициализации ЮKassa: {e}", exc_info=True)
    YOOKASSA_AVAILABLE = False
    Payment = None
    ApiError = Exception


async def create_payment(amount: int, description: str, return_url: str = None) -> Optional[Dict]:
    """
    Создать платеж в ЮKassa
    
    Args:
        amount: Сумма в рублях (будет конвертирована в копейки)
        description: Описание платежа
        return_url: URL для возврата после оплаты (опционально)
    
    Returns:
        Dict с payment_id и confirmation_url или None при ошибке
    """
    if not YOOKASSA_AVAILABLE:
        logger.warning("ЮKassa недоступна: библиотека не установлена или не настроена")
        return None
    
    if Payment is None:
        logger.warning("Payment класс недоступен")
        return None
    
    try:
        logger.info(f"Создание платежа: сумма {amount}₽, описание: {description}")
        
        # Проверяем, что Configuration настроена правильно
        if not Configuration.account_id or not Configuration.secret_key:
            logger.error("Configuration ЮKassa не настроена: отсутствуют account_id или secret_key")
            return None
        
        payment = Payment.create({
            "amount": {
                "value": f"{amount:.2f}",
                "currency": "RUB"
            },
            "confirmation": {
                "type": "redirect",
                "return_url": return_url or "https://t.me"
            },
            "capture": True,
            "description": description
        })
        
        payment_id = payment.id
        confirmation_url = payment.confirmation.confirmation_url
        
        logger.info(f"Создан платеж ЮKassa: {payment_id}, сумма: {amount}₽")
        
        return {
            "payment_id": payment_id,
            "confirmation_url": confirmation_url,
            "status": payment.status
        }
    except ApiError as e:
        logger.error(f"Ошибка API ЮKassa при создании платежа: {e}")
        logger.error(f"Детали ошибки: {e.__dict__ if hasattr(e, '__dict__') else str(e)}")
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при создании платежа: {e}", exc_info=True)
        return None


async def get_payment_status(payment_id: str) -> Optional[Dict]:
    """
    Получить статус платежа из ЮKassa
    
    Args:
        payment_id: ID платежа от ЮKassa
    
    Returns:
        Dict с данными платежа или None при ошибке
    """
    if not YOOKASSA_AVAILABLE:
        logger.error("ЮKassa недоступна: библиотека не установлена или не настроена")
        return None
    
    try:
        payment = Payment.find_one(payment_id)
        
        return {
            "payment_id": payment.id,
            "status": payment.status,
            "amount": float(payment.amount.value),
            "paid": payment.paid,
            "cancelled": payment.cancelled
        }
    except ApiError as e:
        logger.error(f"Ошибка API ЮKassa при получении статуса платежа {payment_id}: {e}")
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при получении статуса платежа: {e}", exc_info=True)
        return None

