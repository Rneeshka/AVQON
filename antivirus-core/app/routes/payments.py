# /app/routes/payments.py
import os
import uuid
import aiohttp
from datetime import datetime, timedelta
from typing import Optional, Dict

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.logger import logger
from app.database import DatabaseManager

router = APIRouter()

# ==== YooKassa config ====
YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID")
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY")

YOOKASSA_API_URL = "https://api.yookassa.ru/v3/payments"


# ==== MODELS ====
class BotPaymentRequest(BaseModel):
    amount: int                # 150 / 500
    license_type: str          # "monthly" / "forever"
    telegram_id: int
    username: str


class BotPaymentResponse(BaseModel):
    payment_id: str
    confirmation_url: str


# ==== DEBUG ENDPOINT ====
@router.get("/debug")
async def debug_payment():
    return {"status": "ok", "message": "Telegram payment module active"}


# ==== CREATE PAYMENT ====
@router.post("/create", response_model=BotPaymentResponse)
async def create_payment(request_data: BotPaymentRequest):
    """
    Создание платежа для Telegram-бота.
    Это ТО, ЧТО ОЖИДАЕТ ТВОЙ БОТ.
    """
    amount = request_data.amount
    license_type = request_data.license_type
    telegram_id = request_data.telegram_id
    username = request_data.username

    logger.info(f"[PAYMENTS] Creating payment: user={telegram_id}, type={license_type}, amount={amount}")

    # === Validate request ===
    if amount not in (150, 500):
        raise HTTPException(status_code=400, detail="Invalid amount")

    if license_type not in ("monthly", "forever"):
        raise HTTPException(status_code=400, detail="Invalid license type")

    # === YooKassa request ===
    payment_idempotence_key = str(uuid.uuid4())

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
            "return_url": "https://t.me/AegisShieldWeb_bot"
        },
        "capture": True,
        "description": f"AEGIS {license_type.upper()} payment",

        # ===== ОБЯЗАТЕЛЬНЫЙ ЧЕК (receipt) =====
        "receipt": {
            "customer": {
                "full_name": username if username else "AEGIS Telegram User",
                "email": f"{telegram_id}@aegis.bot"
            },
            "items": [
                {
                    "description": f"AEGIS {license_type.upper()} license",
                    "quantity": "1.00",
                    "amount": {
                        "value": f"{amount}.00",
                        "currency": "RUB"
                    },
                    "vat_code": 1   # 1 = без НДС — подходит
                }
            ]
        },

        "metadata": {
            "telegram_id": str(telegram_id),
            "username": username,
            "license_type": license_type
        }
    }

    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            logger.info(f"[PAYMENTS] Sending POST request to YooKassa API: {YOOKASSA_API_URL}")
            logger.debug(f"[PAYMENTS] Request payload: amount={amount}, license_type={license_type}, user={telegram_id}")
            
            async with session.post(
                YOOKASSA_API_URL,
                json=payload,
                auth=auth,
                headers=headers
            ) as response:
                logger.info(f"[PAYMENTS] YooKassa responded with status: {response.status}")

                try:
                    data = await response.json()
                    logger.info(f"[PAYMENTS] YooKassa response received")
                except Exception as json_error:
                    response_text = await response.text()
                    logger.error(f"[PAYMENTS] Failed to parse YooKassa response as JSON: {json_error}")
                    logger.error(f"[PAYMENTS] Response text (first 500 chars): {response_text[:500]}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"Invalid response from payment system"
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
                    await db.create_yookassa_payment(
                        payment_id=payment_id,
                        user_id=telegram_id,
                        amount=amount * 100,   # копейки
                        license_type=license_type
                    )
                    logger.info(f"[PAYMENTS] Payment saved to database: {payment_id}")
                except Exception as db_err:
                    logger.error(f"[PAYMENTS] DB save error: {db_err}", exc_info=True)
                    # Не прерываем выполнение, платеж уже создан в ЮKassa

                return BotPaymentResponse(
                    payment_id=payment_id,
                    confirmation_url=confirmation_url
                )

    except aiohttp.ClientError as client_error:
        logger.error(f"[PAYMENTS] Network error when calling YooKassa API: {client_error}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Network error: {str(client_error)}"
        )
    except aiohttp.ServerTimeoutError:
        logger.error(f"[PAYMENTS] Timeout when calling YooKassa API (30 seconds)")
        raise HTTPException(
            status_code=500,
            detail="Payment system timeout"
        )
    except HTTPException:
        # Перевыбрасываем HTTPException как есть
        raise
    except Exception as e:
        logger.error(f"[PAYMENTS] Unexpected error when creating payment: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error: {str(e)}"
        )


# ==== HELPER FUNCTIONS ====
async def generate_license_key_internal(user_id: int, username: str, is_lifetime: bool = True) -> Optional[str]:
    """Генерирует ключ через внутренний API"""
    try:
        admin_token = os.getenv("ADMIN_API_TOKEN", "")
        if not admin_token:
            logger.error("[PAYMENTS] ADMIN_API_TOKEN not configured")
            return None
        
        expires_days = 36500 if is_lifetime else 30
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
                        logger.info(f"[PAYMENTS] Generated license key for user {user_id}: {license_key[:10]}...")
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


async def process_payment_succeeded(payment_data: Dict) -> bool:
    """
    Обработка успешного платежа:
    1. Извлекает user_id из metadata
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
        user_id_str = metadata.get("telegram_id") or metadata.get("user_id")
        
        if not user_id_str:
            logger.error(f"[PAYMENTS] User ID missing in metadata for payment {payment_id}")
            return False
        
        try:
            user_id = int(user_id_str)
        except (ValueError, TypeError):
            logger.error(f"[PAYMENTS] Invalid user_id in metadata: {user_id_str}")
            return False
        
        # Получаем тип лицензии
        license_type = metadata.get("license_type", "forever")
        is_lifetime = license_type == "forever"
        
        logger.info(f"[PAYMENTS] Payment {payment_id}: user_id={user_id}, license_type={license_type}")
        
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
            logger.info(f"[PAYMENTS] Renewal for user={user_id}")
            
            user = db.get_user(user_id)
            if not user or not user.get("has_license"):
                logger.error(f"[PAYMENTS] User {user_id} has no active license for renewal")
                return False
            
            existing_license_key = user.get("license_key")
            if not existing_license_key:
                logger.error(f"[PAYMENTS] User {user_id} has no license_key")
                return False
            
            # Продлеваем лицензию через API
            renewal_success = await renew_license_internal(existing_license_key, extend_days=30)
            
            if not renewal_success:
                logger.error(f"[PAYMENTS] Failed to renew license for user={user_id}")
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
                    logger.info(f"[PAYMENTS] Subscription extended to {new_expires_at} for user={user_id}")
            else:
                # Если подписки нет, создаем новую
                new_expires_at = datetime.now() + timedelta(days=30)
                db.create_subscription(user_id, existing_license_key, "monthly", new_expires_at)
                logger.info(f"[PAYMENTS] Created new subscription for user={user_id}")
            
            # Обновляем статус платежа
            await db.update_yookassa_payment_status(payment_id, "succeeded", existing_license_key)
            
            logger.info(f"[PAYMENTS] ✅ Subscription renewed for user={user_id}, payment={payment_id}")
            return True
        
        # НОВАЯ ПОКУПКА
        user = db.get_user(user_id)
        username = user.get("username", "") if user else ""
        
        # Проверяем, есть ли уже ключ у пользователя
        if user and user.get("has_license"):
            existing_key = user.get("license_key")
            logger.info(f"[PAYMENTS] User {user_id} already has key: {existing_key[:10]}...")
            
            # Обновляем статус платежа
            await db.update_yookassa_payment_status(payment_id, "succeeded", existing_key)
            
            # Создаем подписку для месячных лицензий, если её нет
            if license_type == "monthly":
                subscription = db.get_subscription(user_id)
                if not subscription:
                    expires_at = datetime.now() + timedelta(days=30)
                    db.create_subscription(user_id, existing_key, "monthly", expires_at, auto_renew=False)
                    logger.info(f"[PAYMENTS] Created subscription for user={user_id}")
            
            logger.info(f"[PAYMENTS] ✅ Payment {payment_id} processed (key already issued)")
            return True
        
        # Генерируем новый ключ
        logger.info(f"[PAYMENTS] Generating new key for user={user_id}, is_lifetime={is_lifetime}")
        license_key = await generate_license_key_internal(user_id, username, is_lifetime=is_lifetime)
        
        if not license_key:
            logger.error(f"[PAYMENTS] Failed to generate key for user={user_id}")
            return False
        
        logger.info(f"[PAYMENTS] Key generated for user={user_id}: {license_key[:10]}...")
        
        # Сохраняем ключ в БД
        db.update_user_license(user_id, license_key)
        
        # Обновляем статус платежа
        await db.update_yookassa_payment_status(payment_id, "succeeded", license_key)
        
        # Создаем подписку для месячных лицензий
        if license_type == "monthly":
            expires_at = datetime.now() + timedelta(days=30)
            db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
            logger.info(f"[PAYMENTS] Created subscription for user={user_id}, expires_at={expires_at}")
        
        logger.info(f"[PAYMENTS] ✅ Key issued for user={user_id}, payment={payment_id}")
        return True
        
    except Exception as e:
        logger.error(f"[PAYMENTS] Critical error processing payment: {e}", exc_info=True)
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
    
    try:
        # Получаем JSON данные
        data = await request.json()
        logger.info(f"[PAYMENTS] Webhook data received: {data}")
        
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

# ==== CHECK PAYMENT STATUS FOR BOT ====
@router.get("/status/{payment_id}")
async def check_payment_status(payment_id: str):
    """
    Проверка статуса платежа для бота.
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
                "user_id": str(payment_db.get("user_id", "")),
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
                    # Метаданные из ЮKassa могут быть неполными или отсутствовать
                    user_id_from_db = payment_db.get("user_id")
                    license_type_from_db = payment_db.get("license_type", "")
                    
                    # Пытаемся получить из метаданных ЮKassa, но приоритет у БД
                    user_id_final = str(yookassa_metadata.get("telegram_id") or user_id_from_db or "")
                    license_type_final = yookassa_metadata.get("license_type") or license_type_from_db or ""
                    
                    logger.info(f"[PAYMENTS] Metadata: DB(user_id={user_id_from_db}, type={license_type_from_db}), "
                              f"YooKassa(user_id={yookassa_metadata.get('telegram_id')}, type={yookassa_metadata.get('license_type')}), "
                              f"Final(user_id={user_id_final}, type={license_type_final})")
                    
                    # Получаем сумму из ответа ЮKassa
                    amount_value = payment_db.get("amount", 0) / 100  # из БД в рублях
                    if "amount" in data:
                        amount_obj = data.get("amount", {})
                        if isinstance(amount_obj, dict) and "value" in amount_obj:
                            try:
                                amount_value = float(amount_obj["value"])
                            except (ValueError, TypeError):
                                pass
                    
                    return {
                        "status": yookassa_status,
                        "metadata": {
                            "user_id": user_id_final,
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
                            "user_id": str(payment_db.get("user_id", "")),
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
                            "user_id": str(payment_db.get("user_id", "")),
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
                "user_id": str(payment_db.get("user_id", "")),
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
                "user_id": str(payment_db.get("user_id", "")),
                "license_type": payment_db.get("license_type", "")
            },
            "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
        }
