"""
Веб-сервер для приёма webhook'ов от ЮKassa
Интегрируется с существующим ботом для автоматической выдачи ключей
"""
import sys
import os
import logging
import ipaddress
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime, timedelta

# Добавляем путь к модулям бота
BOT_DIR = Path(__file__).parent
sys.path.insert(0, str(BOT_DIR))

# Импортируем функции из бота
from database import Database
from api_client import generate_license_for_user, renew_license
from config import (
    DB_PATH,
    API_KEY,
    API_URL,
    YOOKASSA_SHOP_ID,
    YOOKASSA_SECRET_KEY,
    ADMIN_ID,
    INSTALLATION_LINK,
    SUPPORT_TECH
)

# Настройка логирования
LOG_DIR = BOT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "webhook.log"
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Инициализация БД
db = Database(DB_PATH)

# IP-адреса ЮKassa (для проверки безопасности)
YOOKASSA_IP_RANGES = [
    ipaddress.ip_network('185.71.76.0/27'),
    ipaddress.ip_network('185.71.77.0/27'),
    ipaddress.ip_network('77.75.153.0/25'),
    ipaddress.ip_network('77.75.154.128/25'),
    ipaddress.ip_network('2a02:5180::/32'),
]
YOOKASSA_IPS = [
    ipaddress.ip_address('77.75.156.11'),
    ipaddress.ip_address('77.75.156.35'),
]


def is_yookassa_ip(ip_str: str) -> bool:
    """Проверка, что IP адрес принадлежит ЮKassa"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Проверяем диапазоны
        for network in YOOKASSA_IP_RANGES:
            if ip in network:
                return True
        # Проверяем отдельные IP
        if ip in YOOKASSA_IPS:
            return True
        return False
    except ValueError:
        logger.warning(f"Неверный IP адрес: {ip_str}")
        return False


async def process_payment_succeeded(payment_data: Dict) -> bool:
    """
    Обработка успешного платежа:
    1. Извлекает user_id из metadata
    2. Проверяет тип лицензии
    3. Выдаёт ключ или продлевает существующий
    4. Обновляет статус в БД
    
    Returns:
        True если обработка успешна, False при ошибке
    """
    try:
        payment_id = payment_data.get("id")
        if not payment_id:
            logger.error("В webhook отсутствует payment_id")
            return False
        
        logger.info(f"[WEBHOOK] Обработка платежа {payment_id}")
        
        # Извлекаем метаданные
        metadata = payment_data.get("metadata", {})
        user_id_str = metadata.get("telegram_id") or metadata.get("user_id")
        
        if not user_id_str:
            logger.error(f"[WEBHOOK] В метаданных платежа {payment_id} отсутствует user_id")
            return False
        
        try:
            user_id = int(user_id_str)
        except (ValueError, TypeError):
            logger.error(f"[WEBHOOK] Неверный user_id в метаданных: {user_id_str}")
            return False
        
        # Получаем тип лицензии
        license_type = metadata.get("license_type", "forever")
        is_lifetime = license_type == "forever"
        
        logger.info(f"[WEBHOOK] Платеж {payment_id}: user_id={user_id}, license_type={license_type}")
        
        # Получаем информацию о платеже из БД
        payment_db = db.get_yookassa_payment(payment_id)
        
        if not payment_db:
            logger.warning(f"[WEBHOOK] Платеж {payment_id} не найден в БД, создаю запись")
            # Создаём запись о платеже
            amount_obj = payment_data.get("amount", {})
            amount_value = 0
            if isinstance(amount_obj, dict) and "value" in amount_obj:
                try:
                    amount_value = int(float(amount_obj["value"]) * 100)  # в копейках
                except (ValueError, TypeError):
                    pass
            
            is_renewal = metadata.get("is_renewal", False)
            try:
                db.create_yookassa_payment(
                    payment_id=payment_id,
                    user_id=user_id,
                    amount=amount_value,
                    license_type=license_type,
                    is_renewal=is_renewal
                )
                payment_db = db.get_yookassa_payment(payment_id)
            except Exception as e:
                logger.error(f"[WEBHOOK] Ошибка при создании записи о платеже: {e}", exc_info=True)
                # Продолжаем обработку, даже если не удалось создать запись
        
        # Проверяем, не обработан ли уже этот платеж
        if payment_db and payment_db.get("status") == "succeeded" and payment_db.get("license_key"):
            logger.info(f"[WEBHOOK] Платеж {payment_id} уже обработан, ключ уже выдан")
            return True
        
        # Проверяем, является ли это продлением
        is_renewal = payment_db and payment_db.get("is_renewal", False)
        
        if is_renewal:
            # ПРОДЛЕНИЕ ПОДПИСКИ
            logger.info(f"[WEBHOOK] Это продление подписки для user={user_id}")
            
            user = db.get_user(user_id)
            if not user or not user.get("has_license"):
                logger.error(f"[WEBHOOK] У пользователя {user_id} нет активной лицензии для продления")
                return False
            
            existing_license_key = user.get("license_key")
            if not existing_license_key:
                logger.error(f"[WEBHOOK] У пользователя {user_id} нет license_key")
                return False
            
            # Продлеваем лицензию через API
            renewal_success = await renew_license(existing_license_key, extend_days=30)
            
            if not renewal_success:
                logger.error(f"[WEBHOOK] Не удалось продлить лицензию для user={user_id}")
                return False
            
            # Обновляем подписку в БД
            subscription = db.get_subscription(user_id)
            if subscription:
                expires_at_str = subscription.get("expires_at")
                if expires_at_str:
                    if isinstance(expires_at_str, str):
                        current_expires = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                    else:
                        current_expires = expires_at_str
                    
                    now = datetime.now()
                    if current_expires.tzinfo:
                        now = now.replace(tzinfo=current_expires.tzinfo)
                    
                    if current_expires < now:
                        new_expires_at = now + timedelta(days=30)
                    else:
                        new_expires_at = current_expires + timedelta(days=30)
                    
                    db.update_subscription_expiry(user_id, new_expires_at)
                    logger.info(f"[WEBHOOK] Подписка продлена до {new_expires_at} для user={user_id}")
            else:
                # Если подписки нет, создаем новую
                new_expires_at = datetime.now() + timedelta(days=30)
                db.create_subscription(user_id, existing_license_key, "monthly", new_expires_at)
                logger.info(f"[WEBHOOK] Создана новая подписка для user={user_id}")
            
            # Обновляем статус платежа
            db.update_yookassa_payment_status(payment_id, "succeeded", existing_license_key)
            
            logger.info(f"[WEBHOOK] ✅ Подписка успешно продлена для user={user_id}, payment={payment_id}")
            return True
        
        # НОВАЯ ПОКУПКА
        user = db.get_user(user_id)
        username = user.get("username", "") if user else ""
        
        # Проверяем, есть ли уже ключ у пользователя
        if user and user.get("has_license"):
            existing_key = user.get("license_key")
            logger.info(f"[WEBHOOK] У пользователя {user_id} уже есть ключ: {existing_key[:10]}...")
            
            # Обновляем статус платежа
            db.update_yookassa_payment_status(payment_id, "succeeded", existing_key)
            
            # Создаем подписку для месячных лицензий, если её нет
            if license_type == "monthly":
                subscription = db.get_subscription(user_id)
                if not subscription:
                    expires_at = datetime.now() + timedelta(days=30)
                    db.create_subscription(user_id, existing_key, "monthly", expires_at, auto_renew=False)
                    logger.info(f"[WEBHOOK] Создана подписка для user={user_id}")
            
            logger.info(f"[WEBHOOK] ✅ Платеж {payment_id} обработан (ключ уже был выдан)")
            return True
        
        # Генерируем новый ключ
        logger.info(f"[WEBHOOK] Генерирую новый ключ для user={user_id}, is_lifetime={is_lifetime}")
        license_key = await generate_license_for_user(user_id, username, is_lifetime=is_lifetime)
        
        if not license_key:
            logger.error(f"[WEBHOOK] Не удалось сгенерировать ключ для user={user_id}")
            return False
        
        logger.info(f"[WEBHOOK] Ключ успешно сгенерирован для user={user_id}: {license_key[:10]}...")
        
        # Сохраняем ключ в БД
        db.update_user_license(user_id, license_key)
        
        # Обновляем статус платежа
        db.update_yookassa_payment_status(payment_id, "succeeded", license_key)
        
        # Создаем подписку для месячных лицензий
        if license_type == "monthly":
            expires_at = datetime.now() + timedelta(days=30)
            db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
            logger.info(f"[WEBHOOK] Создана подписка для user={user_id}, expires_at={expires_at}")
        
        logger.info(f"[WEBHOOK] ✅ Ключ успешно выдан для user={user_id}, payment={payment_id}")
        return True
        
    except Exception as e:
        logger.error(f"[WEBHOOK] Критическая ошибка при обработке платежа: {e}", exc_info=True)
        return False


# FastAPI приложение
try:
    from fastapi import FastAPI, Request, HTTPException, status
    from fastapi.responses import JSONResponse
    import uvicorn
    
    app = FastAPI(title="AEGIS Webhook Server", version="1.0.0")
    
    @app.get("/")
    async def root():
        """Проверка работоспособности сервера"""
        return {"status": "ok", "service": "AEGIS Webhook Server"}
    
    @app.get("/health")
    async def health():
        """Health check endpoint"""
        return {"status": "healthy", "timestamp": datetime.now().isoformat()}
    
    @app.post("/webhook/yookassa")
    async def yookassa_webhook(request: Request):
        """
        Обработка webhook'ов от ЮKassa
        
        Принимает уведомления о платежах и автоматически выдаёт ключи
        """
        client_ip = request.client.host if request.client else "unknown"
        logger.info(f"[WEBHOOK] Получен запрос от IP: {client_ip}")
        
        # Проверка IP (опционально, можно отключить для тестирования)
        # if not is_yookassa_ip(client_ip):
        #     logger.warning(f"[WEBHOOK] Запрос от неавторизованного IP: {client_ip}")
        #     # Не блокируем, но логируем (для тестирования можно отключить)
        
        try:
            # Получаем JSON данные
            data = await request.json()
            logger.info(f"[WEBHOOK] Получены данные: {data}")
            
            # Проверяем тип события
            event_type = data.get("type")
            event = data.get("event")
            
            if event_type != "notification":
                logger.warning(f"[WEBHOOK] Неизвестный тип уведомления: {event_type}")
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"status": "ignored", "reason": "unknown_type"}
                )
            
            if event != "payment.succeeded":
                logger.info(f"[WEBHOOK] Игнорируем событие: {event}")
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"status": "ignored", "reason": f"event_{event}"}
                )
            
            # Извлекаем данные платежа
            payment_object = data.get("object")
            if not payment_object:
                logger.error("[WEBHOOK] В уведомлении отсутствует объект платежа")
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"status": "error", "reason": "no_payment_object"}
                )
            
            # Проверяем статус и paid
            payment_status = payment_object.get("status")
            paid = payment_object.get("paid", False)
            
            if payment_status != "succeeded" or not paid:
                logger.info(f"[WEBHOOK] Платеж не оплачен: status={payment_status}, paid={paid}")
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"status": "ignored", "reason": "not_paid"}
                )
            
            # Обрабатываем платеж
            success = await process_payment_succeeded(payment_object)
            
            if success:
                logger.info(f"[WEBHOOK] ✅ Платеж успешно обработан")
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"status": "success", "message": "Payment processed"}
                )
            else:
                logger.error(f"[WEBHOOK] ❌ Ошибка при обработке платежа")
                # Всегда возвращаем 200, чтобы ЮKassa не повторял запрос
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"status": "error", "message": "Processing failed"}
                )
        
        except Exception as e:
            logger.error(f"[WEBHOOK] Критическая ошибка при обработке webhook: {e}", exc_info=True)
            # Всегда возвращаем 200 OK, чтобы ЮKassa не повторял запрос
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"status": "error", "message": "Internal server error"}
            )
    
    def run_server(host: str = "0.0.0.0", port: int = 8000):
        """Запуск веб-сервера"""
        logger.info(f"[WEBHOOK] Запуск веб-сервера на {host}:{port}")
        logger.info(f"[WEBHOOK] Webhook endpoint: http://{host}:{port}/webhook/yookassa")
        uvicorn.run(app, host=host, port=port, log_level="info")
    
    if __name__ == "__main__":
        import argparse
        parser = argparse.ArgumentParser(description="AEGIS Webhook Server")
        parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
        parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
        args = parser.parse_args()
        
        run_server(host=args.host, port=args.port)

except ImportError:
    logger.error("FastAPI не установлен. Установите: pip install fastapi uvicorn")
    logger.info("Используйте: pip install -r requirements.txt")
    sys.exit(1)

