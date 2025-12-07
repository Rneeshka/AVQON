# /app/routes/payments.py
import os
import uuid
import aiohttp

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


# ==== WEBHOOK ====
@router.post("/webhook")
async def yookassa_webhook(request: Request):
    event = await request.json()
    event_type = event.get("event")
    obj = event.get("object", {})

    if event_type != "payment.succeeded":
        return JSONResponse({"status": "ignored"})

    metadata = obj.get("metadata", {})
    payment_id = obj.get("id")

    telegram_id = metadata.get("telegram_id")
    license_type = metadata.get("license_type")

    if not telegram_id or not license_type:
        logger.warning(f"[PAYMENTS] Missing metadata in webhook: {metadata}")
        return JSONResponse({"status": "error", "message": "Invalid metadata"}, status_code=400)

    db = DatabaseManager()

    logger.info(f"[PAYMENTS] Payment succeeded: {payment_id}. Issuing license to {telegram_id}")

    try:
        await db.update_yookassa_payment_status(payment_id, "succeeded")
    except Exception as e:
        logger.error(f"[PAYMENTS] Failed to update DB payment status: {e}")

    return JSONResponse({"status": "ok"})

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
