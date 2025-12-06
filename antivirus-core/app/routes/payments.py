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

    async with aiohttp.ClientSession() as session:
        async with session.post(
            YOOKASSA_API_URL,
            json=payload,
            auth=auth,
            headers=headers
        ) as response:

            data = await response.json()

            # Ошибки ЮKassa
            if response.status >= 300:
                logger.error(f"[PAYMENTS] YooKassa error {response.status}: {data}")
                raise HTTPException(
                    status_code=500,
                    detail=f"YooKassa error: {data.get('description', 'Unknown error')}"
                )

            payment_id = data["id"]
            confirmation_url = data["confirmation"]["confirmation_url"]

            logger.info(f"[PAYMENTS] Payment created: {payment_id}")

            # === Save to DB ===
            try:
                db = DatabaseManager()
                await db.create_yookassa_payment(
                    payment_id=payment_id,
                    user_id=telegram_id,
                    amount=amount * 100,   # копейки
                    license_type=license_type
                )
            except Exception as db_err:
                logger.error(f"[PAYMENTS] DB save error: {db_err}")

            return BotPaymentResponse(
                payment_id=payment_id,
                confirmation_url=confirmation_url
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
    db = DatabaseManager()
    payment = await db.get_yookassa_payment(payment_id)

    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    return {"status": payment["status"]}
