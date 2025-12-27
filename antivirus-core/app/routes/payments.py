# /app/routes/payments.py
import os
import uuid
import hashlib
import aiohttp
from datetime import datetime, timedelta
from typing import Optional, Dict
import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr

from app.logger import logger
from app.database import DatabaseManager

router = APIRouter()

# ==== YooKassa config ====
YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID")
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY")

YOOKASSA_API_URL = "https://api.yookassa.ru/v3/payments"


# ==== MODELS ====
class WebPaymentRequest(BaseModel):
    amount: int                # 150 / 500
    license_type: str          # "monthly" / "forever"
    email: EmailStr            # Email пользователя
    username: str              # Имя пользователя (из email)


class WebPaymentResponse(BaseModel):
    payment_id: str
    confirmation_url: str


def email_to_user_id(email: str) -> int:
    """Преобразует email в числовой user_id для совместимости с БД"""
    # Используем хэш email и берем первые 15 цифр для BIGINT
    hash_obj = hashlib.md5(email.encode())
    hash_hex = hash_obj.hexdigest()
    # Преобразуем в число (первые 15 символов)
    user_id = int(hash_hex[:15], 16) % (10**15)
    return user_id


# ==== DEBUG ENDPOINT ====
@router.get("/debug")
async def debug_payment():
    return {"status": "ok", "message": "Web payment module active"}


# ==== CREATE PAYMENT ====
@router.post("/create", response_model=WebPaymentResponse)
async def create_payment(request_data: WebPaymentRequest):
    """
    Создание платежа для веб-сайта через ЮКассу.
    """
    # === Проверка конфигурации ЮКассы ===
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error(f"[PAYMENTS] YooKassa credentials not configured. SHOP_ID={bool(YOOKASSA_SHOP_ID)}, SECRET_KEY={bool(YOOKASSA_SECRET_KEY)}")
        raise HTTPException(
            status_code=500,
            detail="Payment system configuration error: YooKassa credentials not set"
        )
    
    amount = request_data.amount
    license_type = request_data.license_type
    email = request_data.email
    username = request_data.username

    logger.info(f"[PAYMENTS] Creating payment: email={email}, type={license_type}, amount={amount}")

    # === Validate request ===
    if amount not in (150, 500):
        logger.error(f"[PAYMENTS] Invalid amount: {amount} (expected 150 or 500)")
        raise HTTPException(status_code=400, detail=f"Invalid amount: {amount}. Expected 150 or 500")

    if license_type not in ("monthly", "forever"):
        logger.error(f"[PAYMENTS] Invalid license_type: {license_type} (expected 'monthly' or 'forever')")
        raise HTTPException(status_code=400, detail=f"Invalid license type: {license_type}")
    
    # Проверяем соответствие суммы и типа лицензии
    expected_amount = 150 if license_type == "monthly" else 500
    if amount != expected_amount:
        logger.error(f"[PAYMENTS] Amount mismatch: amount={amount}, license_type={license_type}, expected={expected_amount}")
        raise HTTPException(
            status_code=400, 
            detail=f"Amount {amount} does not match license type {license_type} (expected {expected_amount})"
        )

    # === YooKassa request ===
    payment_idempotence_key = str(uuid.uuid4())
    
    website_url = os.getenv("WEBSITE_URL", "http://localhost:8080")

    headers = {
        "Idempotence-Key": payment_idempotence_key
    }

    auth = aiohttp.BasicAuth(
        login=YOOKASSA_SHOP_ID,
        password=YOOKASSA_SECRET_KEY
    )

    payload = {
        "amount": {
            "value": f"{amount}.00",
            "currency": "RUB"
        },
        "confirmation": {
            "type": "redirect",
            "return_url": f"{website_url}/payment-success.html"
        },
        "capture": True,
        "description": f"AEGIS {license_type.upper()} payment",

        # ===== ОБЯЗАТЕЛЬНЫЙ ЧЕК (receipt) =====
        "receipt": {
            "customer": {
                "full_name": username if username else email.split('@')[0],
                "email": email
            },
            "items": [
                {
                    "description": f"AEGIS {license_type.upper()} license",
                    "quantity": "1.00",
                    "amount": {
                        "value": f"{amount}.00",
                        "currency": "RUB"
                    },
                    "vat_code": 1   # 1 = без НДС
                }
            ]
        },

        "metadata": {
            "email": email,
            "username": username,
            "license_type": license_type
        }
    }

    timeout = aiohttp.ClientTimeout(total=30)

    try:
        async with aiohttp.ClientSession(
            timeout=timeout,
            auth=auth
        ) as session:

            logger.info(f"[PAYMENTS] Sending POST request to YooKassa API: {YOOKASSA_API_URL}")
            logger.debug(
                f"[PAYMENTS] Request payload: amount={amount}, "
                f"license_type={license_type}, email={email}"
            )

            async with session.post(
                YOOKASSA_API_URL,
                json=payload,
                headers=headers
            ) as response:

                logger.info(f"[PAYMENTS] YooKassa responded with status: {response.status}")

                try:
                    data = await response.json()
                    logger.info("[PAYMENTS] YooKassa response received")
                except Exception as json_error:
                    response_text = await response.text()
                    logger.error(f"[PAYMENTS] Failed to parse YooKassa response as JSON: {json_error}")
                    logger.error(f"[PAYMENTS] Response text (first 500 chars): {response_text[:500]}")
                    raise HTTPException(
                        status_code=500,
                        detail="Invalid response from payment system"
                    )
                # Ошибки ЮKassa
                if response.status >= 300:
                    error_description = data.get('description', 'Unknown error')
                    error_code = data.get('code', 'N/A')
                    error_type = data.get('type', 'N/A')
                    logger.error(f"[PAYMENTS] YooKassa error {response.status} (code: {error_code}, type: {error_type}): {error_description}")
                    logger.error(f"[PAYMENTS] Full error response: {data}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"Payment system error: {error_description}"
                    )

                payment_id = data.get("id")
                confirmation = data.get("confirmation", {})
                confirmation_url = confirmation.get("confirmation_url")

                if not payment_id:
                    logger.error(f"[PAYMENTS] YooKassa response missing payment_id. Response: {data}")
                    raise HTTPException(
                        status_code=500,
                        detail="Invalid response from payment system: missing payment_id"
                    )

                if not confirmation_url:
                    logger.error(f"[PAYMENTS] YooKassa response missing confirmation_url. Response: {data}")
                    raise HTTPException(
                        status_code=500,
                        detail="Invalid response from payment system: missing confirmation_url"
                    )

                logger.info(f"[PAYMENTS] Payment created successfully: {payment_id}")
                logger.info(f"[PAYMENTS] Confirmation URL: {confirmation_url}")

                # === Save to DB ===
                try:
                    db = DatabaseManager()
                    # Преобразуем email в user_id для совместимости с БД
                    user_id = email_to_user_id(email)
                    await db.create_yookassa_payment(
                        payment_id=payment_id,
                        user_id=user_id,
                        amount=amount * 100,   # копейки
                        license_type=license_type
                    )
                    logger.info(f"[PAYMENTS] Payment saved to database: {payment_id}")
                except Exception as db_err:
                    logger.error(f"[PAYMENTS] DB save error: {db_err}", exc_info=True)
                    # Не прерываем выполнение, платеж уже создан в ЮKassa

                return WebPaymentResponse(
                    payment_id=payment_id,
                    confirmation_url=confirmation_url
                )

    except aiohttp.ClientError as client_error:
        error_msg = str(client_error)
        logger.error(f"[PAYMENTS] Network error when calling YooKassa API: {error_msg}", exc_info=True)
        
        # Детальная диагностика
        if "Connection refused" in error_msg or "Cannot connect" in error_msg:
            detail_msg = "Не удалось подключиться к платежной системе. Проверьте интернет-соединение."
        elif "Name resolution failed" in error_msg or "DNS" in error_msg:
            detail_msg = "Ошибка DNS. Сервер платежной системы недоступен."
        else:
            detail_msg = f"Сетевая ошибка: {error_msg}"
        
        raise HTTPException(
            status_code=500,
            detail=detail_msg
        )
    except aiohttp.ServerTimeoutError:
        logger.error(f"[PAYMENTS] Timeout when calling YooKassa API (30 seconds)")
        raise HTTPException(
            status_code=500,
            detail="Превышено время ожидания ответа от платежной системы. Попробуйте позже."
        )
    except HTTPException:
        # Перевыбрасываем HTTPException как есть
        raise
    except json.JSONDecodeError as json_error:
        logger.error(f"[PAYMENTS] JSON decode error: {json_error}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Ошибка обработки ответа от платежной системы"
        )
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        logger.error(f"[PAYMENTS] Unexpected error ({error_type}) when creating payment: {error_msg}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Неожиданная ошибка при создании платежа: {error_msg}"
        )


# ==== HELPER FUNCTIONS ====
async def generate_license_key_internal(email: str, username: str, is_lifetime: bool = True) -> Optional[str]:
    """Генерирует ключ через внутренний API"""
    try:
        admin_token = os.getenv("ADMIN_API_TOKEN", "")
        if not admin_token:
            logger.error("[PAYMENTS] ADMIN_API_TOKEN not configured")
            return None
        
        expires_days = 36500 if is_lifetime else 30
        license_type = "Lifetime" if is_lifetime else "Monthly"
        
        # Преобразуем email в user_id для совместимости
        user_id = email_to_user_id(email)
        
        data = {
            "user_id": str(user_id),
            "username": username or email.split('@')[0],
            "name": f"Web User {email.split('@')[0]}",
            "description": f"{license_type} license for {email}",
            "access_level": "premium",
            "daily_limit": None,
            "hourly_limit": None,
            "expires_days": expires_days
        }
        
        # Используем внутренний URL (localhost)
        base_url = os.getenv("BACKEND_URL", "http://localhost:8000")
        api_url = f"{base_url}/admin/api-keys/create"
        
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(api_url, json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    result = await response.json()
                    license_key = result.get("license_key") or result.get("api_key")
                    if license_key:
                        logger.info(f"[PAYMENTS] Generated license key for {email}: {license_key[:10]}...")
                        return license_key
                    else:
                        logger.error(f"[PAYMENTS] API returned success but no key: {result}")
                        return None
                else:
                    error_text = await response.text()
                    logger.error(f"[PAYMENTS] API error: {response.status} - {error_text}")
                    return None
    except Exception as e:
        logger.error(f"[PAYMENTS] Error generating license key: {e}", exc_info=True)
        return None


async def renew_license_internal(license_key: str, extend_days: int = 30) -> bool:
    """Продлевает лицензию через внутренний API"""
    try:
        admin_token = os.getenv("ADMIN_API_TOKEN", "")
        if not admin_token:
            logger.error("[PAYMENTS] ADMIN_API_TOKEN not configured")
            return False
        
        base_url = os.getenv("BACKEND_URL", "http://localhost:8000")
        extend_url = f"{base_url}/admin/api-keys/extend"
        
        data = {
            "api_key": license_key,
            "extend_days": extend_days
        }
        
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(extend_url, json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    logger.info(f"[PAYMENTS] License {license_key[:10]}... extended by {extend_days} days")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"[PAYMENTS] Extend error: {response.status} - {error_text}")
                    return False
    except Exception as e:
        logger.error(f"[PAYMENTS] Error renewing license: {e}", exc_info=True)
        return False


async def send_license_key_email(email: str, license_key: str, license_type: str) -> bool:
    """
    Отправляет email пользователю с лицензионным ключом и поздравлениями.
    """
    try:
        from app.auth import AuthManager
        
        smtp_user = os.getenv("SMTP_USER", "")
        if not smtp_user:
            logger.warning("[PAYMENTS] SMTP_USER not configured; cannot send email")
            return False
        
        install_link = os.getenv(
            "INSTALLATION_LINK",
            "https://chromewebstore.google.com/detail/bedaaeaeddnodmmkfmfealepbbbdoegl"
        )
        
        if license_type == "forever":
            license_text = "Ваш ключ действует бессрочно."
            license_period = "бессрочную лицензию"
        else:
            license_text = "Ваша подписка активирована на 30 дней."
            license_period = "месячную подписку"
        
        subject = "🎉 Оплата успешно получена! Ваш лицензионный ключ AEGIS"
        
        body = f"""Здравствуйте!

Благодарим вас за покупку {license_period} AEGIS!

🎉 Оплата успешно получена!

Ваш лицензионный ключ:
{license_key}

{license_text}

📦 Ссылка для установки расширения:
{install_link}

Как использовать ключ:
1. Установите расширение AEGIS по ссылке выше
2. Откройте настройки расширения
3. Введите ваш лицензионный ключ для активации

Если у вас возникли вопросы, обращайтесь в поддержку:
aegisshieldos@gmail.com

С уважением,
Команда AEGIS
"""
        
        success = AuthManager._send_email(
            to_email=email,
            subject=subject,
            body=body
        )
        
        if success:
            logger.info(f"[PAYMENTS] License key email sent to {email}")
        else:
            logger.error(f"[PAYMENTS] Failed to send license key email to {email}")
        
        return success
        
    except Exception as e:
        logger.error(f"[PAYMENTS] Error sending license key email: {e}", exc_info=True)
        return False


async def process_payment_succeeded(payment_data: Dict) -> bool:
    """
    Обработка успешного платежа:
    1. Извлекает email из metadata
    2. Проверяет тип лицензии
    3. Выдаёт ключ или продлевает существующий
    4. Обновляет статус в БД
    """
    try:
        payment_id = payment_data.get("id")
        if not payment_id:
            logger.error("[PAYMENTS] Payment ID missing in webhook")
            return False
        
        logger.info(f"[PAYMENTS] Processing payment {payment_id}")
        
        # Извлекаем метаданные
        metadata = payment_data.get("metadata", {})
        email = metadata.get("email")
        
        if not email:
            logger.error(f"[PAYMENTS] Email missing in metadata for payment {payment_id}")
            return False
        
        # Получаем тип лицензии
        license_type = metadata.get("license_type", "forever")
        is_lifetime = license_type == "forever"
        
        # Преобразуем email в user_id для совместимости с БД
        user_id = email_to_user_id(email)
        username = metadata.get("username", email.split('@')[0])
        
        logger.info(f"[PAYMENTS] Payment {payment_id}: email={email}, user_id={user_id}, license_type={license_type}")

        db = DatabaseManager()

        # Получаем информацию о платеже из БД
        payment_db = await db.get_yookassa_payment(payment_id)
        
        if not payment_db:
            logger.warning(f"[PAYMENTS] Payment {payment_id} not found in DB, creating record")
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
                await db.create_yookassa_payment(
                    payment_id=payment_id,
                    user_id=user_id,
                    amount=amount_value,
                    license_type=license_type,
                    is_renewal=is_renewal
                )
                payment_db = await db.get_yookassa_payment(payment_id)
            except Exception as e:
                logger.error(f"[PAYMENTS] Error creating payment record: {e}", exc_info=True)
        
        # Проверяем, не обработан ли уже этот платеж
        if payment_db and payment_db.get("status") == "succeeded" and payment_db.get("license_key"):
            logger.info(f"[PAYMENTS] Payment {payment_id} already processed")
            return True
        
        # Проверяем, является ли это продлением (из БД или метаданных)
        is_renewal = False
        if payment_db:
            is_renewal = payment_db.get("is_renewal", False)
        if not is_renewal:
            is_renewal = metadata.get("is_renewal", False)
        
        if is_renewal:
            # ПРОДЛЕНИЕ ПОДПИСКИ
            logger.info(f"[PAYMENTS] Renewal for email={email}")
            
            user = db.get_user(user_id)
            if not user or not user.get("has_license"):
                logger.error(f"[PAYMENTS] User {email} has no active license for renewal")
                return False
            
            existing_license_key = user.get("license_key")
            if not existing_license_key:
                logger.error(f"[PAYMENTS] User {email} has no license_key")
                return False
            
            # Продлеваем лицензию через API
            renewal_success = await renew_license_internal(existing_license_key, extend_days=30)
            
            if not renewal_success:
                logger.error(f"[PAYMENTS] Failed to renew license for email={email}")
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
                    logger.info(f"[PAYMENTS] Subscription extended to {new_expires_at} for email={email}")
            else:
                # Если подписки нет, создаем новую
                new_expires_at = datetime.now() + timedelta(days=30)
                db.create_subscription(user_id, existing_license_key, "monthly", new_expires_at)
                logger.info(f"[PAYMENTS] Created new subscription for email={email}")
            
            # Обновляем статус платежа
            await db.update_yookassa_payment_status(payment_id, "succeeded", existing_license_key)
            
            logger.info(f"[PAYMENTS] ✅ Subscription renewed for email={email}, payment={payment_id}")
            
            # Отправляем уведомление о продлении на email
            await send_license_key_email(email, existing_license_key, "monthly")
            
            return True
        
        # НОВАЯ ПОКУПКА
        user = db.get_user(user_id)
        
        # Создаем пользователя если его нет
        if not user:
            db.create_user(user_id, username)
            user = db.get_user(user_id)
        
        # Проверяем, есть ли уже ключ у пользователя
        if user and user.get("has_license"):
            existing_key = user.get("license_key")
            logger.info(f"[PAYMENTS] User {email} already has key: {existing_key[:10]}...")
            
            # Обновляем статус платежа
            await db.update_yookassa_payment_status(payment_id, "succeeded", existing_key)
            
            # Создаем подписку для месячных лицензий, если её нет
            if license_type == "monthly":
                subscription = db.get_subscription(user_id)
                if not subscription:
                    expires_at = datetime.now() + timedelta(days=30)
                    db.create_subscription(user_id, existing_key, "monthly", expires_at, auto_renew=False)
                    logger.info(f"[PAYMENTS] Created subscription for email={email}")
            
            logger.info(f"[PAYMENTS] ✅ Payment {payment_id} processed (key already issued)")
            
            # Отправляем ключ на email (если пользователь уже имел ключ, отправляем его снова)
            await send_license_key_email(email, existing_key, license_type)
            
            return True
        
        # Генерируем новый ключ
        logger.info(f"[PAYMENTS] Generating new key for email={email}, is_lifetime={is_lifetime}")
        license_key = await generate_license_key_internal(email, username, is_lifetime=is_lifetime)
        
        if not license_key:
            logger.error(f"[PAYMENTS] Failed to generate key for email={email}")
            return False
        
        logger.info(f"[PAYMENTS] Key generated for email={email}: {license_key[:10]}...")
        
        # Сохраняем ключ в БД
        db.update_user_license(user_id, license_key)
        
        # Обновляем статус платежа
        await db.update_yookassa_payment_status(payment_id, "succeeded", license_key)
        
        # Создаем подписку для месячных лицензий
        if license_type == "monthly":
            expires_at = datetime.now() + timedelta(days=30)
            db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
            logger.info(f"[PAYMENTS] Created subscription for email={email}, expires_at={expires_at}")
        
        logger.info(f"[PAYMENTS] ✅ Key issued for email={email}, payment={payment_id}")
        
        # Отправляем ключ на email с поздравлениями
        await send_license_key_email(email, license_key, license_type)
        
        return True
        
    except Exception as e:
        logger.error(f"[PAYMENTS] Critical error processing payment: {e}", exc_info=True)
        return False


# ==== WEBHOOK VALIDATION ====
def validate_yookassa_ip(client_ip: str) -> bool:
    """
    Проверяет, что запрос пришел с IP адресов ЮKassa.
    Официальные IP диапазоны ЮKassa:
    - 185.71.76.0/27
    - 185.71.77.0/27
    - 77.75.153.0/25
    - 77.75.156.11
    - 77.75.156.35
    - 77.75.154.128/25
    """
    import ipaddress
    
    # В режиме разработки разрешаем localhost
    if client_ip in ("127.0.0.1", "localhost", "::1", "unknown"):
        logger.warning(f"[PAYMENTS] Webhook from localhost/IP: {client_ip} (allowed in dev mode)")
        return True
    
    try:
        ip = ipaddress.ip_address(client_ip)
        
        # Проверяем диапазоны ЮKassa
        allowed_ranges = [
            ipaddress.ip_network("185.71.76.0/27"),
            ipaddress.ip_network("185.71.77.0/27"),
            ipaddress.ip_network("77.75.153.0/25"),
            ipaddress.ip_network("77.75.154.128/25"),
        ]
        
        allowed_ips = [
            ipaddress.ip_address("77.75.156.11"),
            ipaddress.ip_address("77.75.156.35"),
        ]
        
        # Проверяем диапазоны
        for network in allowed_ranges:
            if ip in network:
                return True
        
        # Проверяем отдельные IP
        for allowed_ip in allowed_ips:
            if ip == allowed_ip:
                return True
        
        return False
    except ValueError:
        logger.error(f"[PAYMENTS] Invalid IP address format: {client_ip}")
        return False


# ==== WEBHOOK ====
@router.post("/webhook/yookassa")
async def yookassa_webhook(request: Request):
    """
    Обработка webhook'ов от ЮKassa
    Принимает уведомления о платежах и автоматически выдаёт ключи
    """
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"[PAYMENTS] Webhook request from IP: {client_ip}")
    
    # ВАЛИДАЦИЯ IP (опционально, можно отключить для разработки)
    validate_ip = os.getenv("YOOKASSA_VALIDATE_IP", "true").lower() == "true"
    if validate_ip and not validate_yookassa_ip(client_ip):
        logger.error(f"[PAYMENTS] ❌ Webhook rejected: IP {client_ip} not in YooKassa range")
        return JSONResponse(
            status_code=403,
            content={"status": "forbidden", "reason": "invalid_ip"}
        )
    
    try:
        # Получаем JSON данные
        body_bytes = await request.body()
        try:
            data = json.loads(body_bytes.decode('utf-8'))
        except json.JSONDecodeError as json_err:
            logger.error(f"[PAYMENTS] Invalid JSON in webhook: {json_err}")
            return JSONResponse(
                status_code=400,
                content={"status": "error", "reason": "invalid_json"}
            )
        logger.info(f"[PAYMENTS] Webhook data received: {json.dumps(data, ensure_ascii=False)[:500]}")
        
        # Проверяем тип события
        event_type = data.get("type")
        event = data.get("event")
        
        if event_type != "notification":
            logger.warning(f"[PAYMENTS] Unknown notification type: {event_type}")
            return JSONResponse(
                status_code=200,
                content={"status": "ignored", "reason": "unknown_type"}
            )

        if event != "payment.succeeded":
            logger.info(f"[PAYMENTS] Ignoring event: {event}")
            return JSONResponse(
                status_code=200,
                content={"status": "ignored", "reason": f"event_{event}"}
            )
        
        # Извлекаем данные платежа
        payment_object = data.get("object")
        if not payment_object:
            logger.error("[PAYMENTS] Payment object missing in webhook")
            return JSONResponse(
                status_code=200,
                content={"status": "error", "reason": "no_payment_object"}
            )
        
        # Проверяем статус и paid
        payment_status = payment_object.get("status")
        paid = payment_object.get("paid", False)

        if payment_status != "succeeded" or not paid:
            logger.info(f"[PAYMENTS] Payment not paid: status={payment_status}, paid={paid}")
            return JSONResponse(
                status_code=200,
                content={"status": "ignored", "reason": "not_paid"}
            )
        
        # ВАЛИДАЦИЯ: Проверяем сумму платежа
        payment_amount_obj = payment_object.get("amount", {})
        payment_amount = 0
        if isinstance(payment_amount_obj, dict) and "value" in payment_amount_obj:
            try:
                payment_amount = float(payment_amount_obj["value"])
            except (ValueError, TypeError):
                logger.warning(f"[PAYMENTS] Could not parse payment amount: {payment_amount_obj}")
        
        # Получаем ожидаемую сумму из метаданных или БД
        metadata = payment_object.get("metadata", {})
        license_type = metadata.get("license_type", "forever")
        expected_amount = 150.0 if license_type == "monthly" else 500.0
        
        # Допускаем небольшую погрешность (0.01 рубля)
        if payment_amount > 0 and abs(payment_amount - expected_amount) > 0.01:
            logger.warning(
                f"[PAYMENTS] Amount mismatch: received={payment_amount}, expected={expected_amount}, "
                f"license_type={license_type}"
            )
            # Не блокируем, но логируем
        
        # Обрабатываем платеж
        success = await process_payment_succeeded(payment_object)
        
        if success:
            logger.info(f"[PAYMENTS] ✅ Payment successfully processed")
            return JSONResponse(
                status_code=200,
                content={"status": "success", "message": "Payment processed"}
            )
        else:
            logger.error(f"[PAYMENTS] ❌ Payment processing failed")
            # Всегда возвращаем 200, чтобы ЮKassa не повторял запрос
            return JSONResponse(
                status_code=200,
                content={"status": "error", "message": "Processing failed"}
            )
    
    except Exception as e:
        logger.error(f"[PAYMENTS] Critical error in webhook: {e}", exc_info=True)
        # Всегда возвращаем 200 OK, чтобы ЮKassa не повторял запрос
        return JSONResponse(
            status_code=200,
            content={"status": "error", "message": "Internal server error"}
        )

# ==== GET LICENSE KEY BY PAYMENT ID ====
@router.get("/license/{payment_id}")
async def get_license_by_payment(payment_id: str):
    """
    Получение лицензионного ключа по ID платежа.
    Используется для отображения ключа на сайте после успешной оплаты.
    """
    logger.info(f"[PAYMENTS] Getting license for payment: {payment_id}")
    
    db = DatabaseManager()
    payment_db = await db.get_yookassa_payment(payment_id)
    
    if not payment_db:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    if payment_db.get("status") != "succeeded":
        raise HTTPException(status_code=400, detail=f"Payment not completed. Status: {payment_db.get('status')}")
    
    license_key = payment_db.get("license_key")
    if not license_key:
        raise HTTPException(status_code=404, detail="License key not issued yet")
    
    return {
        "payment_id": payment_id,
        "license_key": license_key,
        "license_type": payment_db.get("license_type", "forever"),
        "status": "succeeded"
    }


# ==== CHECK PAYMENT STATUS ====
@router.get("/status/{payment_id}")
async def check_payment_status(payment_id: str):
    """
    Проверка статуса платежа.
    Опрашивает ЮKassa API для получения актуального статуса.
    """
    logger.info(f"[PAYMENTS] ===== Checking payment status: {payment_id} =====")
    
    # Сначала проверяем БД
    db = DatabaseManager()
    payment_db = await db.get_yookassa_payment(payment_id)

    if not payment_db:
        logger.warning(f"[PAYMENTS] Payment {payment_id} not found in database")
        raise HTTPException(status_code=404, detail="Payment not found")

    # Проверяем наличие ключей ЮKassa
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error(f"[PAYMENTS] YooKassa credentials not configured for status check. SHOP_ID={bool(YOOKASSA_SHOP_ID)}, SECRET_KEY={bool(YOOKASSA_SECRET_KEY)}")
        # Возвращаем статус из БД если нет ключей
        return {
            "status": payment_db.get("status", "pending"),
            "metadata": {
                "license_type": payment_db.get("license_type", "")
            },
            "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
        }

    # Опрашиваем ЮKassa API для получения актуального статуса
    yookassa_status_url = f"{YOOKASSA_API_URL}/{payment_id}"
    logger.info(f"[PAYMENTS] YooKassa API URL: {yookassa_status_url}")
    logger.info(f"[PAYMENTS] YooKassa SHOP_ID: {YOOKASSA_SHOP_ID[:5]}... (first 5 chars)")
    
    auth = aiohttp.BasicAuth(
        login=YOOKASSA_SHOP_ID,
        password=YOOKASSA_SECRET_KEY
    )

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            logger.info(f"[PAYMENTS] Requesting payment status from YooKassa: {yookassa_status_url}")
            
            async with session.get(yookassa_status_url, auth=auth) as response:
                logger.info(f"[PAYMENTS] YooKassa HTTP response status: {response.status}")
                
                # Логируем заголовки ответа для отладки
                logger.debug(f"[PAYMENTS] Response headers: {dict(response.headers)}")
                
                if response.status == 200:
                    data = await response.json()
                    yookassa_status = data.get("status", "pending")
                    
                    # КРИТИЧНО: Логируем полный ответ от ЮKassa для отладки
                    logger.info(f"[PAYMENTS] Payment {payment_id} status from YooKassa: {yookassa_status}")
                    logger.info(f"[PAYMENTS] Full YooKassa response for {payment_id}: {data}")
                    
                    # Проверяем все возможные статусы
                    valid_statuses = ["pending", "waiting_for_capture", "succeeded", "canceled"]
                    if yookassa_status not in valid_statuses:
                        logger.warning(f"[PAYMENTS] Unexpected status from YooKassa: {yookassa_status}, valid: {valid_statuses}")
                    
                    # Дополнительная информация о платеже
                    if "paid" in data:
                        logger.info(f"[PAYMENTS] Payment {payment_id} paid flag: {data.get('paid')}")
                    if "captured_at" in data:
                        logger.info(f"[PAYMENTS] Payment {payment_id} captured_at: {data.get('captured_at')}")
                    if "created_at" in data:
                        logger.info(f"[PAYMENTS] Payment {payment_id} created_at: {data.get('created_at')}")
                    
                    # Обновляем статус в БД если изменился
                    db_status = payment_db.get("status", "pending")
                    if yookassa_status != db_status:
                        logger.info(f"[PAYMENTS] Updating payment status in DB: {db_status} -> {yookassa_status}")
                        try:
                            await db.update_yookassa_payment_status(payment_id, yookassa_status)
                            payment_db["status"] = yookassa_status
                        except Exception as update_err:
                            logger.error(f"[PAYMENTS] Failed to update status in DB: {update_err}")
                    
                    # Получаем метаданные из ответа ЮKassa (если есть)
                    yookassa_metadata = data.get("metadata", {})
                    
                    # ВСЕГДА используем данные из БД как основной источник
                    license_type_from_db = payment_db.get("license_type", "")
                    
                    # Пытаемся получить из метаданных ЮKassa, но приоритет у БД
                    license_type_final = yookassa_metadata.get("license_type") or license_type_from_db or ""
                    
                    logger.info(f"[PAYMENTS] Metadata: DB(type={license_type_from_db}), "
                              f"YooKassa(type={yookassa_metadata.get('license_type')}), "
                              f"Final(type={license_type_final})")
                    
                    # Получаем сумму из ответа ЮKassa
                    amount_value = payment_db.get("amount", 0) / 100  # из БД в рублях
                    if "amount" in data:
                        amount_obj = data.get("amount", {})
                        if isinstance(amount_obj, dict) and "value" in amount_obj:
                            try:
                                amount_value = float(amount_obj["value"])
                            except (ValueError, TypeError):
                                pass
                    
                    # КРИТИЧНО: Если платеж успешен и еще не обработан - обрабатываем автоматически
                    if yookassa_status == "succeeded" and payment_db.get("status") != "succeeded":
                        logger.info(f"[PAYMENTS] Payment {payment_id} succeeded, processing automatically...")
                        try:
                            # Получаем полные данные платежа от ЮКасса для обработки
                            payment_object = {
                                "id": payment_id,
                                "status": "succeeded",
                                "paid": True,
                                "metadata": yookassa_metadata or {},
                                "amount": data.get("amount", {})
                            }
                            # Обрабатываем платеж (выдача ключа и т.д.)
                            success = await process_payment_succeeded(payment_object)
                            if success:
                                logger.info(f"[PAYMENTS] ✅ Payment {payment_id} processed successfully via status check")
                            else:
                                logger.error(f"[PAYMENTS] ❌ Failed to process payment {payment_id}")
                        except Exception as process_error:
                            logger.error(f"[PAYMENTS] Error processing payment {payment_id}: {process_error}", exc_info=True)
                    
                    return {
                        "status": yookassa_status,
                        "metadata": {
                            "license_type": license_type_final
                        },
                        "amount": f"{amount_value:.2f}"
                    }
                elif response.status == 404:
                    logger.warning(f"[PAYMENTS] Payment {payment_id} not found in YooKassa")
                    # Возвращаем статус из БД
                    return {
                        "status": payment_db.get("status", "pending"),
                        "metadata": {
                            "license_type": payment_db.get("license_type", "")
                        },
                        "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
                    }
                else:
                    error_text = await response.text()
                    logger.error(f"[PAYMENTS] YooKassa status check error {response.status}")
                    logger.error(f"[PAYMENTS] Error response body: {error_text}")
                    logger.error(f"[PAYMENTS] Error response headers: {dict(response.headers)}")
                    # Возвращаем статус из БД при ошибке
                    return {
                        "status": payment_db.get("status", "pending"),
                        "metadata": {
                            "license_type": payment_db.get("license_type", "")
                        },
                        "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
                    }
                    
    except aiohttp.ClientError as client_error:
        logger.error(f"[PAYMENTS] Network error when checking payment status from YooKassa: {client_error}", exc_info=True)
        # Возвращаем статус из БД при сетевой ошибке
        return {
            "status": payment_db.get("status", "pending"),
            "metadata": {
                "license_type": payment_db.get("license_type", "")
            },
            "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
        }
    except Exception as e:
        logger.error(f"[PAYMENTS] Unexpected error when checking payment status from YooKassa: {e}", exc_info=True)
        # Возвращаем статус из БД при ошибке
        return {
            "status": payment_db.get("status", "pending"),
            "metadata": {
                "license_type": payment_db.get("license_type", "")
            },
            "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
        }
