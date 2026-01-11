# /app/routes/payments.py
import os
import uuid
import hashlib
import aiohttp
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict
import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr

from app.logger import logger
from app.database import DatabaseManager
from app.config import server_config

router = APIRouter()

# Глобальная функция для получения YooKassa сессии из app state
def get_yookassa_session(request: Request) -> Optional[aiohttp.ClientSession]:
    """Получает глобальную YooKassa сессию из app.state"""
    app = request.app
    session = getattr(app.state, 'yookassa_session', None)
    if session and not session.closed:
        return session
    return None

# ==== YooKassa config ====
# Поддержка разных ключей для DEV и PROD окружений
ENVIRONMENT = os.getenv("ENV", "dev").lower()

# Для DEV окружения можно использовать тестовые ключи
if ENVIRONMENT == "dev":
    YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID_DEV") or os.getenv("YOOKASSA_SHOP_ID")
    YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY_DEV") or os.getenv("YOOKASSA_SECRET_KEY")
else:
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

# ==== DEBUG ROUTES ====
@router.get("/debug/routes")
async def debug_routes(request: Request):
    """Диагностический эндпоинт для проверки зарегистрированных роутов"""
    app = request.app
    routes = []
    for route in app.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            routes.append({
                "path": route.path,
                "methods": list(route.methods) if route.methods else [],
                "name": getattr(route, 'name', 'unknown')
            })
    
    # Фильтруем только payments роуты
    payments_routes = [r for r in routes if "/payments" in r["path"] or r["path"].startswith("/")]
    
    return {
        "status": "ok",
        "total_routes": len(routes),
        "payments_routes": payments_routes,
        "all_routes": routes[:50]  # Первые 50 для диагностики
    }


# ==== CREATE PAYMENT ====
@router.post("/create", response_model=WebPaymentResponse)
async def create_payment(request_data: WebPaymentRequest, request: Request):
    """
    Создание платежа для веб-сайта через ЮКассу.
    """
    # === Проверка конфигурации ЮКассы ===
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error(f"[PAYMENTS] YooKassa credentials not configured. SHOP_ID={bool(YOOKASSA_SHOP_ID)}, SECRET_KEY={bool(YOOKASSA_SECRET_KEY)}")
        logger.error(f"[PAYMENTS] Environment: {ENVIRONMENT}")
        logger.error(f"[PAYMENTS] For DEV: Set YOOKASSA_SHOP_ID_DEV and YOOKASSA_SECRET_KEY_DEV (or use YOOKASSA_SHOP_ID/YOOKASSA_SECRET_KEY)")
        logger.error(f"[PAYMENTS] For PROD: Set YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY")
        raise HTTPException(
            status_code=500,
            detail="Ошибка конфигурации: учетные данные платежной системы не настроены. Проверьте env.env"
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
    
    # Автоматическое определение URL сайта на основе окружения
    website_url = os.getenv("WEBSITE_URL")
    if not website_url:
        # Если WEBSITE_URL не указан, определяем автоматически по ENV
        if ENVIRONMENT == "dev":
<<<<<<< HEAD
<<<<<<< HEAD
            website_url = "https://site-dev.avqon.com"
        else:
            website_url = "https://avqon.com"
=======
            website_url = "https://www.devsite.aegis.builders"
        else:
            website_url = "https://www.aegis.builders"
>>>>>>> f6326b6 (WIP: emergency save of server changes after dev/prod desync)
=======
            website_url = "https://site-dev.avqon.com"
        else:
            website_url = "https://avqon.com"
>>>>>>> ed0e079 (refactor: rename aegis to avqon and normalize project structure)
    
    logger.info(f"[PAYMENTS] Using website URL for return_url: {website_url}")

    headers = {
        "Idempotence-Key": payment_idempotence_key
    }

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
        "description": f"AVQON {license_type.upper()} payment",

        # ===== ОБЯЗАТЕЛЬНЫЙ ЧЕК (receipt) =====
        "receipt": {
            "customer": {
                "full_name": username if username else email.split('@')[0],
                "email": email
            },
            "items": [
                {
                    "description": f"AVQON {license_type.upper()} license",
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

    # КРИТИЧНО: Используем глобальную сессию из app.state
    session = get_yookassa_session(request)
    if not session:
        logger.error("[PAYMENTS] ❌ YooKassa session not available (not initialized or closed)")
        raise HTTPException(
            status_code=500,
            detail="Ошибка конфигурации: сессия платежной системы не инициализирована"
        )

    try:
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

            # Используем безопасное чтение JSON с обработкой ошибок соединения
            try:
                data = await safe_read_json(response)
                logger.info("[PAYMENTS] YooKassa response received")
            except HTTPException:
                # Перевыбрасываем HTTPException как есть
                raise

            # Ошибки ЮKassa
            if response.status >= 300:
                error_description = data.get('description', 'Unknown error')
                error_code = data.get('code', 'N/A')
                error_type = data.get('type', 'N/A')
                
                logger.error(f"[PAYMENTS] YooKassa error {response.status} (code: {error_code}, type: {error_type}): {error_description}")
                logger.error(f"[PAYMENTS] Full error response: {data}")
                logger.error(f"[PAYMENTS] SHOP_ID used: {YOOKASSA_SHOP_ID[:5]}... (first 5 chars)")
                logger.error(f"[PAYMENTS] SECRET_KEY starts with: {YOOKASSA_SECRET_KEY[:10] if YOOKASSA_SECRET_KEY else 'None'}...")
                
                # Специальная обработка ошибок аутентификации
                if error_code == 'invalid_request' or 'shopId' in error_description.lower() or 'secret key' in error_description.lower():
                    logger.error("[PAYMENTS] ❌ CRITICAL: YooKassa credentials are invalid!")
                    logger.error(f"[PAYMENTS] Please check YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY in env.env")
                    logger.error(f"[PAYMENTS] For DEV environment, you can use YOOKASSA_SHOP_ID_DEV and YOOKASSA_SECRET_KEY_DEV")
                    raise HTTPException(
                        status_code=500,
                        detail=f"Ошибка конфигурации платежной системы: {error_description}. Проверьте настройки в env.env"
                    )
                
                raise HTTPException(
                    status_code=500,
                    detail=f"Ошибка платежной системы: {error_description}"
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

            logger.info(f"[PAYMENTS] ✅ Payment created successfully: {payment_id}")
            logger.info(f"[PAYMENTS] Confirmation URL: {confirmation_url}")
            logger.info(f"[PAYMENTS] ⚠️ CRITICAL: This payment_id will be returned to frontend: {payment_id}")
            logger.info(f"[PAYMENTS] ⚠️ Frontend MUST use this exact payment_id for /status and /license endpoints")

            # === Save to DB ===
            # КРИТИЧНО: Платеж ДОЛЖЕН быть сохранен в БД, иначе /status не найдет его
            db = DatabaseManager()
            # user_id теперь nullable - сохраняем платеж БЕЗ user_id (FK constraint убран)
            # Это позволяет сохранять платеж даже если пользователя нет в БД
            user_id = None  # Не используем user_id, так как он nullable и не обязателен
            logger.info(f"[PAYMENTS] Saving payment to DB: payment_id={payment_id}, user_id={user_id} (nullable), email={email}")
            
            try:
                logger.info(f"[PAYMENTS] Attempting to save payment to DB: payment_id={payment_id}, user_id={user_id}, amount={amount * 100}, license_type={license_type}")
                success = await db.create_yookassa_payment(
                    payment_id=payment_id,
                    user_id=user_id,
                    amount=amount * 100,   # копейки
                    license_type=license_type
                )
                logger.info(f"[PAYMENTS] create_yookassa_payment returned: success={success}")
                
                if not success:
                    # Платеж уже существует - это валидный сценарий (retry/повторный запрос)
                    logger.info(f"[PAYMENTS] Payment {payment_id} already exists in DB (retry scenario)")
                    existing = await db.get_yookassa_payment(payment_id)
                    if existing:
                        logger.info(f"[PAYMENTS] ✅ Found existing payment: status={existing.get('status')}, license_type={existing.get('license_type')}")
                        # Платеж уже существует - это нормально (retry). 
                        # confirmation_url уже получен от ЮKassa выше, просто возвращаем его
                        logger.info(f"[PAYMENTS] Returning existing payment with confirmation_url from current YooKassa response")
                        # confirmation_url уже есть из ответа ЮKassa
                        return WebPaymentResponse(
                            payment_id=payment_id,
                            confirmation_url=confirmation_url
                        )
                    else:
                        # Платеж не найден - это реальная ошибка БД (не IntegrityError)
                        logger.error(f"[PAYMENTS] ❌ CRITICAL: Failed to save payment {payment_id} to DB and payment not found!")
                        logger.error(f"[PAYMENTS] This indicates a database error (not IntegrityError). Check database connection and logs.")
                        raise HTTPException(
                            status_code=500,
                            detail="Не удалось сохранить платеж в базу данных. Обратитесь в поддержку."
                        )
                else:
                    logger.info(f"[PAYMENTS] ✅ Payment saved to database with payment_id: {payment_id}")
            except HTTPException:
                raise
            except Exception as db_err:
                logger.error(f"[PAYMENTS] ❌ CRITICAL: DB save exception: {type(db_err).__name__}: {db_err}", exc_info=True)
                logger.error(f"[PAYMENTS] Exception details: {str(db_err)}")
                # КРИТИЧНО: Не продолжаем, если не удалось сохранить в БД
                raise HTTPException(
                    status_code=500,
                    detail=f"Не удалось сохранить платеж в базу данных: {str(db_err)}. Обратитесь в поддержку."
                )

            logger.info(f"[PAYMENTS] Returning to frontend: payment_id={payment_id}, confirmation_url={confirmation_url}")
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
async def safe_read_json(response: aiohttp.ClientResponse) -> dict:
    """
    Безопасное чтение JSON из aiohttp response с обработкой ошибок соединения.
    Читает JSON внутри контекста response, с обработкой всех возможных ошибок.
    
    Args:
        response: aiohttp ClientResponse объект (должен быть внутри async with контекста)
        
    Returns:
        dict: распарсенный JSON
        
    Raises:
        HTTPException: если не удалось прочитать JSON
    """
    try:
        # Пытаемся прочитать JSON
        data = await response.json()
        return data
    except (aiohttp.ClientConnectionError, aiohttp.ServerConnectionError, ConnectionError, aiohttp.ClientPayloadError) as conn_error:
        # Ошибки соединения - соединение закрыто или прервано
        logger.error(f"[PAYMENTS] Connection error reading JSON from YooKassa: {type(conn_error).__name__}: {conn_error}")
        # Пытаемся прочитать как текст для логирования (если возможно)
        try:
            # Если response еще не закрыт, можем попробовать прочитать текст
            if not response.closed:
                text = await response.text()
                logger.error(f"[PAYMENTS] Response text (first 500 chars): {text[:500]}")
        except Exception as text_error:
            logger.error(f"[PAYMENTS] Could not read response text: {text_error}")
        
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка соединения при чтении ответа от платежной системы. Попробуйте позже."
        )
    except json.JSONDecodeError as json_error:
        # JSON decode error - ошибка формата ответа
        logger.error(f"[PAYMENTS] JSON decode error: {json_error}")
        try:
            if not response.closed:
                text = await response.text()
                logger.error(f"[PAYMENTS] Response text (first 500 chars): {text[:500]}")
        except Exception as text_error:
            logger.error(f"[PAYMENTS] Could not read response text: {text_error}")
        raise HTTPException(
            status_code=500,
            detail="Неверный формат ответа от платежной системы"
        )
    except asyncio.TimeoutError as timeout_error:
        logger.error(f"[PAYMENTS] Timeout reading JSON from YooKassa: {timeout_error}")
        raise HTTPException(
            status_code=500,
            detail="Превышено время ожидания ответа от платежной системы"
        )
    except Exception as e:
        logger.error(f"[PAYMENTS] Unexpected error reading JSON: {type(e).__name__}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при чтении ответа от платежной системы: {str(e)}"
        )


async def generate_license_key_internal(email: str, username: str, is_lifetime: bool = True) -> Optional[str]:
    """Генерирует ключ через внутренний API"""
    try:
        logger.info(f"[PAYMENTS] ===== GENERATE LICENSE KEY INTERNAL ===== email={email}, is_lifetime={is_lifetime}")
        
        admin_token = os.getenv("ADMIN_API_TOKEN", "")
        if not admin_token:
            logger.error("[PAYMENTS] ❌ ADMIN_API_TOKEN not configured - cannot generate license key")
            logger.error("[PAYMENTS] Set ADMIN_API_TOKEN in env.env file")
            return None
        
        logger.info(f"[PAYMENTS] ADMIN_API_TOKEN configured: {admin_token[:10]}... (first 10 chars)")
        
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
        
        # Используем внутренний URL из конфигурации
        base_url = os.getenv("INTERNAL_API_BASE_URL") or server_config.INTERNAL_API_BASE
        api_url = f"{base_url}/admin/api-keys/create"
        
        logger.info(f"[PAYMENTS] Calling internal API: {api_url}")
        logger.info(f"[PAYMENTS] Request data: user_id={user_id}, expires_days={expires_days}, license_type={license_type}")
        
<<<<<<< HEAD
        headers = {"X-Admin-Token": admin_token}
=======
        headers = {"Authorization": f"Bearer {admin_token}"}
>>>>>>> f6326b6 (WIP: emergency save of server changes after dev/prod desync)
        
        async with aiohttp.ClientSession() as session:
            async with session.post(api_url, json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                logger.info(f"[PAYMENTS] Internal API response status: {response.status}")
                
                if response.status == 200:
                    result = await safe_read_json(response)
                    license_key = result.get("license_key") or result.get("api_key")
                    if license_key:
                        logger.info(f"[PAYMENTS] ✅ Generated license key for {email}: {license_key[:10]}...")
                        return license_key
                    else:
                        logger.error(f"[PAYMENTS] ❌ API returned success but no key: {result}")
                        return None
                elif response.status == 403:
                    error_text = await response.text()
                    logger.error(f"[PAYMENTS] ❌ API returned 403 Forbidden - check ADMIN_API_TOKEN")
                    logger.error(f"[PAYMENTS] Error response: {error_text}")
                    return None
                else:
                    error_text = await response.text()
                    logger.error(f"[PAYMENTS] ❌ API error: {response.status} - {error_text}")
                    return None
    except Exception as e:
        logger.error(f"[PAYMENTS] ❌ Error generating license key: {e}", exc_info=True)
        return None


async def renew_license_internal(license_key: str, extend_days: int = 30) -> bool:
    """Продлевает лицензию через внутренний API"""
    try:
        admin_token = os.getenv("ADMIN_API_TOKEN", "")
        if not admin_token:
            logger.error("[PAYMENTS] ADMIN_API_TOKEN not configured")
            return False
        
        base_url = os.getenv("INTERNAL_API_BASE_URL") or server_config.INTERNAL_API_BASE
        extend_url = f"{base_url}/admin/api-keys/extend"
        
        data = {
            "api_key": license_key,
            "extend_days": extend_days
        }
        
        headers = {"X-Admin-Token": admin_token}
        
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
        
        subject = "🎉 Оплата успешно получена! Ваш лицензионный ключ AVQON"
        
        body = f"""Здравствуйте!

Благодарим вас за покупку {license_period} AVQON (Adaptive Verification & Qualitative Observation Node)!

🎉 Оплата успешно получена!

Ваш лицензионный ключ:
{license_key}

{license_text}

📦 Ссылка для установки расширения:
{install_link}

Как использовать ключ:
1. Установите расширение AVQON по ссылке выше
2. Откройте настройки расширения
3. Введите ваш лицензионный ключ для активации

Если у вас возникли вопросы, обращайтесь в поддержку:
support@avqon.com

С уважением,
Команда AVQON
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
        
        logger.info(f"[PAYMENTS] ===== PROCESSING PAYMENT SUCCEEDED ===== Payment ID: {payment_id}")
        logger.info(f"[PAYMENTS] Full payment data: {json.dumps(payment_data, ensure_ascii=False, default=str)[:1000]}")
        
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
            
            # Отправка email отключена - ключ показывается только на сайте
            # await send_license_key_email(email, existing_license_key, "monthly")
            
            return True
        
        # НОВАЯ ПОКУПКА
        user = db.get_user(user_id)
        
        # Создаем пользователя если его нет
        if not user:
            db.create_user(user_id, username, email)
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
            
            # Отправка email отключена - ключ показывается только на сайте
            # await send_license_key_email(email, existing_key, license_type)
            
            return True
        
        # Генерируем новый ключ
        logger.info(f"[PAYMENTS] ===== GENERATING NEW LICENSE KEY ===== email={email}, is_lifetime={is_lifetime}")
        license_key = await generate_license_key_internal(email, username, is_lifetime=is_lifetime)
        
        if not license_key:
            logger.error(f"[PAYMENTS] ❌ Failed to generate key for email={email}")
            logger.error(f"[PAYMENTS] Check ADMIN_API_TOKEN configuration and /admin/api-keys/create endpoint")
            return False
        
        logger.info(f"[PAYMENTS] ✅ Key generated for email={email}: {license_key[:10]}...")
        
        # Проверяем, что ключ действительно создан в api_keys
        api_key_info = db.get_api_key_info(license_key)
        if not api_key_info:
            logger.error(f"[PAYMENTS] ❌ CRITICAL: Key {license_key[:10]}... was NOT found in api_keys table after creation!")
            logger.error(f"[PAYMENTS] This means the key was not properly created in api_keys table")
        else:
            logger.info(f"[PAYMENTS] ✅ Verified: Key {license_key[:10]}... exists in api_keys table (user_id={api_key_info.get('user_id')})")
        
        # Сохраняем ключ в БД с email (обновляет users.license_key)
        db.update_user_license(user_id, license_key, email)
        logger.info(f"[PAYMENTS] ✅ Updated users.license_key for user_id={user_id}, email={email}")
        
        # Обновляем статус платежа
        await db.update_yookassa_payment_status(payment_id, "succeeded", license_key)
        
        # Создаем подписку для месячных лицензий
        if license_type == "monthly":
            expires_at = datetime.now() + timedelta(days=30)
            db.create_subscription(user_id, license_key, "monthly", expires_at, auto_renew=False)
            logger.info(f"[PAYMENTS] Created subscription for email={email}, expires_at={expires_at}")
        
        logger.info(f"[PAYMENTS] ✅ Key issued for email={email}, payment={payment_id}")
        
        # Отправка email отключена - ключ показывается только на сайте
        # await send_license_key_email(email, license_key, license_type)
        
        return True
        
    except Exception as e:
        logger.error(f"[PAYMENTS] Critical error processing payment: {e}", exc_info=True)
        return False


# ==== WEBHOOK VALIDATION ====
def validate_yookassa_ip(client_ip: str, is_dev: bool = False) -> bool:
    """
    Проверяет, что запрос пришел с IP адресов ЮKassa.
    Официальные IP диапазоны ЮKassa:
    - 185.71.76.0/27
    - 185.71.77.0/27
    - 77.75.153.0/25
    - 77.75.156.11
    - 77.75.156.35
    - 77.75.154.128/25
    
    Args:
        client_ip: IP адрес клиента
        is_dev: Если True, разрешает любые IP для разработки
    """
    import ipaddress
    
    # В dev режиме разрешаем любые IP (для тестирования)
    if is_dev:
        logger.info(f"[PAYMENTS DEV] Webhook from IP: {client_ip} (allowed in dev mode)")
        return True
    
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


# ==== WEBHOOK HANDLER (общая функция) ====
async def handle_yookassa_webhook(request: Request, is_dev: bool = False):
    """
    Общая функция обработки webhook'ов от ЮKassa.
    
    Args:
        request: FastAPI Request объект
        is_dev: Если True, используется для dev окружения (более мягкая валидация)
    """
    env_prefix = "[PAYMENTS DEV]" if is_dev else "[PAYMENTS]"
    client_ip = request.client.host if request.client else "unknown"
    
    # КРИТИЧНО: Логируем ВСЕ запросы, даже пустые
    logger.info(f"{env_prefix} ===== WEBHOOK RECEIVED ===== IP: {client_ip}, Method: {request.method}, Path: {request.url.path}")
    logger.info(f"{env_prefix} Headers: {dict(request.headers)}")
    
    # ВАЛИДАЦИЯ IP (опционально, можно отключить для разработки)
    # В dev режиме по умолчанию отключаем валидацию IP
    if is_dev:
        validate_ip = os.getenv("YOOKASSA_VALIDATE_IP", "false").lower() == "true"
    else:
        validate_ip = os.getenv("YOOKASSA_VALIDATE_IP", "true").lower() == "true"
    
    logger.info(f"{env_prefix} IP validation: {validate_ip}, is_dev: {is_dev}, client_ip: {client_ip}")
    
    if validate_ip and not validate_yookassa_ip(client_ip, is_dev=is_dev):
        logger.error(f"{env_prefix} ❌ Webhook rejected: IP {client_ip} not in YooKassa range")
        return JSONResponse(
            status_code=403,
            content={"status": "forbidden", "reason": "invalid_ip", "client_ip": client_ip, "is_dev": is_dev}
        )
    
    try:
        # Получаем JSON данные
        body_bytes = await request.body()
        logger.info(f"{env_prefix} Body size: {len(body_bytes)} bytes")
        
        if not body_bytes:
            logger.warning(f"{env_prefix} Empty body received - this might be a test request")
            return JSONResponse(
                status_code=400,
                content={"status": "error", "reason": "empty_body", "message": "Webhook endpoint is working, but body is empty"}
            )
        
        try:
            data = json.loads(body_bytes.decode('utf-8'))
        except json.JSONDecodeError as json_err:
            logger.error(f"{env_prefix} Invalid JSON in webhook: {json_err}, body preview: {body_bytes[:200]}")
            return JSONResponse(
                status_code=400,
                content={"status": "error", "reason": "invalid_json", "body_preview": body_bytes[:200].decode('utf-8', errors='ignore')}
            )
        logger.info(f"{env_prefix} Webhook data received: {json.dumps(data, ensure_ascii=False)[:500]}")
        
        # Проверяем тип события
        event_type = data.get("type")
        event = data.get("event")
        
        if event_type != "notification":
            logger.warning(f"{env_prefix} Unknown notification type: {event_type}")
            return JSONResponse(
                status_code=200,
                content={"status": "ignored", "reason": "unknown_type"}
            )

        if event != "payment.succeeded":
            logger.info(f"{env_prefix} Ignoring event: {event}")
            return JSONResponse(
                status_code=200,
                content={"status": "ignored", "reason": f"event_{event}"}
            )
        
        # Извлекаем данные платежа
        payment_object = data.get("object")
        if not payment_object:
            logger.error(f"{env_prefix} Payment object missing in webhook")
            return JSONResponse(
                status_code=200,
                content={"status": "error", "reason": "no_payment_object"}
            )
        
        # Проверяем статус и paid
        payment_status = payment_object.get("status")
        paid = payment_object.get("paid", False)

        if payment_status != "succeeded" or not paid:
            logger.info(f"{env_prefix} Payment not paid: status={payment_status}, paid={paid}")
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
                logger.warning(f"{env_prefix} Could not parse payment amount: {payment_amount_obj}")
        
        # Получаем ожидаемую сумму из метаданных или БД
        metadata = payment_object.get("metadata", {})
        license_type = metadata.get("license_type", "forever")
        expected_amount = 150.0 if license_type == "monthly" else 500.0
        
        # Допускаем небольшую погрешность (0.01 рубля)
        if payment_amount > 0 and abs(payment_amount - expected_amount) > 0.01:
            logger.warning(
                f"{env_prefix} Amount mismatch: received={payment_amount}, expected={expected_amount}, "
                f"license_type={license_type}"
            )
            # Не блокируем, но логируем
        
        # Обрабатываем платеж
        success = await process_payment_succeeded(payment_object)
        
        if success:
            logger.info(f"{env_prefix} ✅ Payment successfully processed")
            return JSONResponse(
                status_code=200,
                content={"status": "success", "message": "Payment processed", "environment": "dev" if is_dev else "prod"}
            )
        else:
            logger.error(f"{env_prefix} ❌ Payment processing failed")
            # Всегда возвращаем 200, чтобы ЮKassa не повторял запрос
            return JSONResponse(
                status_code=200,
                content={"status": "error", "message": "Processing failed", "environment": "dev" if is_dev else "prod"}
            )
    
    except Exception as e:
        logger.error(f"{env_prefix} Critical error in webhook: {e}", exc_info=True)
        # Всегда возвращаем 200 OK, чтобы ЮKassa не повторял запрос
        return JSONResponse(
            status_code=200,
            content={"status": "error", "message": "Internal server error", "environment": "dev" if is_dev else "prod"}
        )


# ==== WEBHOOK PROD ====
@router.post("/webhook/yookassa")
async def yookassa_webhook(request: Request):
    """
    Обработка webhook'ов от ЮKassa для PROD окружения.
    Принимает уведомления о платежах и автоматически выдаёт ключи.
    Использует строгую валидацию IP адресов.
    """
    return await handle_yookassa_webhook(request, is_dev=False)


# ==== WEBHOOK DEV ====
@router.post("/webhook/yookassa/dev")
async def yookassa_webhook_dev(request: Request):
    """
    Обработка webhook'ов от ЮKassa для DEV окружения.
    Принимает уведомления о платежах и автоматически выдаёт ключи.
    Использует тестовые ключи YooKassa и более мягкую валидацию IP (разрешает любые IP).
    
    Для настройки в YooKassa:
    - Используйте тестовые ключи (YOOKASSA_SHOP_ID_DEV и YOOKASSA_SECRET_KEY_DEV)
<<<<<<< HEAD
<<<<<<< HEAD
    - URL вебхука: https://dev.avqon.com/payments/webhook/yookassa/dev
=======
    - URL вебхука: https://api-dev.aegis.builders/payments/webhook/yookassa/dev
>>>>>>> f6326b6 (WIP: emergency save of server changes after dev/prod desync)
=======
    - URL вебхука: https://dev.avqon.com/payments/webhook/yookassa/dev
>>>>>>> ed0e079 (refactor: rename aegis to avqon and normalize project structure)
    - В dev режиме IP валидация отключена для удобства тестирования
    """
    # КРИТИЧНО: Логируем ВСЕ запросы СРАЗУ в начале функции
    import traceback
    logger.info(f"[PAYMENTS DEV] ===== WEBHOOK DEV ENDPOINT CALLED ===== Method: {request.method}, Path: {request.url.path}, IP: {request.client.host if request.client else 'unknown'}")
    logger.info(f"[PAYMENTS DEV] Call stack: {traceback.format_stack()[-3:-1]}")
    try:
        result = await handle_yookassa_webhook(request, is_dev=True)
        logger.info(f"[PAYMENTS DEV] ===== WEBHOOK DEV ENDPOINT COMPLETED ===== Result status: {result.status_code if hasattr(result, 'status_code') else 'unknown'}")
        return result
    except Exception as e:
        logger.error(f"[PAYMENTS DEV] ===== WEBHOOK DEV ENDPOINT ERROR ===== {e}", exc_info=True)
        raise


# ==== WEBHOOK DEV GET (для диагностики) ====
@router.get("/webhook/yookassa/dev")
async def yookassa_webhook_dev_get(request: Request):
    """Временный GET endpoint для диагностики webhook URL"""
    logger.info(f"[PAYMENTS DEV] GET request to webhook endpoint - Path: {request.url.path}, IP: {request.client.host if request.client else 'unknown'}")
    return {
        "status": "ok",
        "message": "GET endpoint works - webhook URL is accessible",
        "path": str(request.url.path),
        "method": request.method,
        "note": "YooKassa sends POST requests, not GET. This endpoint is for testing only."
    }


# ==== MANUAL PAYMENT PROCESSING (для случаев когда webhook не пришел) ====
@router.post("/process/{payment_id}")
async def manual_process_payment(payment_id: str, request: Request):
    """
    Ручная обработка платежа, если webhook не пришел.
    Используется для dev окружения для тестирования.
    """
    logger.info(f"[PAYMENTS] ===== MANUAL PAYMENT PROCESSING ===== Payment ID: {payment_id}")
    
    try:
        # Получаем данные платежа из YooKassa API
        session = get_yookassa_session(request)
        if not session:
            raise HTTPException(status_code=500, detail="YooKassa session not available")
        
        yookassa_status_url = f"{YOOKASSA_API_URL}/{payment_id}"
        logger.info(f"[PAYMENTS] Fetching payment data from YooKassa: {yookassa_status_url}")
        
        async with session.get(yookassa_status_url) as response:
            if response.status != 200:
                error_text = await response.text()
                logger.error(f"[PAYMENTS] Failed to fetch payment from YooKassa: {response.status} - {error_text}")
                raise HTTPException(status_code=500, detail=f"Failed to fetch payment: {response.status}")
            
            payment_data = await safe_read_json(response)
            logger.info(f"[PAYMENTS] Payment data from YooKassa: {json.dumps(payment_data, ensure_ascii=False, default=str)[:500]}")
            
            # Проверяем, что платеж успешен
            if payment_data.get("status") != "succeeded" or not payment_data.get("paid"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Payment not succeeded. Status: {payment_data.get('status')}, Paid: {payment_data.get('paid')}"
                )
            
            # Обрабатываем платеж
            success = await process_payment_succeeded(payment_data)
            
            if success:
                logger.info(f"[PAYMENTS] ✅ Manual payment processing successful for {payment_id}")
                return {
                    "status": "success",
                    "message": "Payment processed successfully",
                    "payment_id": payment_id
                }
            else:
                logger.error(f"[PAYMENTS] ❌ Manual payment processing failed for {payment_id}")
                raise HTTPException(status_code=500, detail="Payment processing failed")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[PAYMENTS] Error in manual payment processing: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# ==== GET LICENSE KEY BY PAYMENT ID ====
@router.get("/license/{payment_id}")
async def get_license_by_payment(payment_id: str, request: Request):
    """
    Получение лицензионного ключа по ID платежа.
    Используется для отображения ключа на сайте после успешной оплаты.
    Автоматически обрабатывает платеж, если webhook не пришел.
    """
    logger.info(f"[PAYMENTS] Getting license for payment: {payment_id}")
    logger.info(f"[PAYMENTS] ⚠️ Frontend requested license for payment_id: {payment_id}")
    
    try:
        db = DatabaseManager()
        payment_db = await db.get_yookassa_payment(payment_id)
        
        # КРИТИЧНО: Если платеж не найден в БД, проверяем YooKassa API
        if not payment_db:
            logger.warning(f"[PAYMENTS] ⚠️ Payment {payment_id} NOT FOUND in database, checking YooKassa API...")
            
            # Получаем данные платежа из YooKassa API
            try:
                session = get_yookassa_session(request)
                if session:
                    yookassa_status_url = f"{YOOKASSA_API_URL}/{payment_id}"
                    logger.info(f"[PAYMENTS] Fetching payment data from YooKassa: {yookassa_status_url}")
                    
                    async with session.get(yookassa_status_url) as response:
                        if response.status == 200:
                            payment_data = await safe_read_json(response)
                            
                            # Если платеж succeeded, автоматически обрабатываем
                            if payment_data.get("status") == "succeeded" and payment_data.get("paid"):
                                logger.info(f"[PAYMENTS] ✅ Payment found in YooKassa and succeeded, processing now...")
                                success = await process_payment_succeeded(payment_data)
                                
                                if success:
                                    # Обновляем данные из БД после обработки
                                    payment_db = await db.get_yookassa_payment(payment_id)
                                    if payment_db:
                                        license_key = payment_db.get("license_key")
                                        if license_key:
                                            logger.info(f"[PAYMENTS] ✅ License key issued automatically: {license_key[:10]}...")
                                            return {
                                                "payment_id": payment_id,
                                                "license_key": license_key,
                                                "license_type": payment_db.get("license_type", "forever"),
                                                "status": "succeeded",
                                                "auto_processed": True
                                            }
                                    else:
                                        logger.error(f"[PAYMENTS] ❌ Processing succeeded but payment still not in DB")
                                else:
                                    logger.error(f"[PAYMENTS] ❌ Automatic processing failed")
                            else:
                                logger.warning(f"[PAYMENTS] Payment status in YooKassa: {payment_data.get('status')}, paid: {payment_data.get('paid')}")
                                raise HTTPException(
                                    status_code=400,
                                    detail=f"Payment not completed yet. Status: {payment_data.get('status')}"
                                )
                        else:
                            logger.error(f"[PAYMENTS] Failed to fetch payment from YooKassa: {response.status}")
                            raise HTTPException(
                                status_code=404,
                                detail=f"Payment {payment_id} not found in database or YooKassa"
                            )
                else:
                    logger.error(f"[PAYMENTS] YooKassa session not available")
                    raise HTTPException(
                        status_code=500,
                        detail="YooKassa session not available"
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[PAYMENTS] Error checking YooKassa: {e}", exc_info=True)
                raise HTTPException(
                    status_code=404,
                    detail=f"Payment {payment_id} not found. Error: {str(e)}"
                )
        
        payment_status = payment_db.get("status", "unknown")
        license_key = payment_db.get("license_key")
        logger.info(f"[PAYMENTS] Payment {payment_id} status: {payment_status}, license_key: {'present' if license_key else 'MISSING'}")
        
        if payment_status != "succeeded":
            logger.info(f"[PAYMENTS] Payment {payment_id} not completed yet. Status: {payment_status}")
            raise HTTPException(
                status_code=400, 
                detail=f"Payment not completed yet. Current status: {payment_status}. Please wait for payment processing."
            )
        
        if not license_key:
            # КРИТИЧНО: Если webhook не пришел, автоматически обрабатываем платеж
            logger.warning(f"[PAYMENTS] ⚠️ Payment {payment_id} succeeded but license key NOT ISSUED yet")
            logger.info(f"[PAYMENTS] 🔄 Webhook not processed yet, attempting automatic processing...")
            
            # Получаем данные платежа из YooKassa API и обрабатываем
            try:
                session = get_yookassa_session(request)
                if session:
                    yookassa_status_url = f"{YOOKASSA_API_URL}/{payment_id}"
                    logger.info(f"[PAYMENTS] Fetching payment data from YooKassa: {yookassa_status_url}")
                    
                    async with session.get(yookassa_status_url) as response:
                        if response.status == 200:
                            payment_data = await safe_read_json(response)
                            
                            # Проверяем, что платеж действительно succeeded
                            if payment_data.get("status") == "succeeded" and payment_data.get("paid"):
                                logger.info(f"[PAYMENTS] ✅ Payment confirmed succeeded in YooKassa, processing now...")
                                success = await process_payment_succeeded(payment_data)
                                
                                if success:
                                    # Обновляем данные из БД после обработки
                                    payment_db = await db.get_yookassa_payment(payment_id)
                                    license_key = payment_db.get("license_key") if payment_db else None
                                    
                                    if license_key:
                                        logger.info(f"[PAYMENTS] ✅ License key issued automatically: {license_key[:10]}...")
                                        return {
                                            "payment_id": payment_id,
                                            "license_key": license_key,
                                            "license_type": payment_db.get("license_type", "forever"),
                                            "status": "succeeded",
                                            "auto_processed": True
                                        }
                                    else:
                                        logger.error(f"[PAYMENTS] ❌ Processing succeeded but license_key still missing")
                                else:
                                    logger.error(f"[PAYMENTS] ❌ Automatic processing failed")
                            else:
                                logger.warning(f"[PAYMENTS] Payment status in YooKassa: {payment_data.get('status')}, paid: {payment_data.get('paid')}")
                        else:
                            logger.warning(f"[PAYMENTS] Failed to fetch payment from YooKassa: {response.status}")
            except Exception as auto_process_error:
                logger.error(f"[PAYMENTS] Error in automatic processing: {auto_process_error}", exc_info=True)
            
            # Если автоматическая обработка не сработала, возвращаем ошибку
            logger.warning(f"[PAYMENTS] ⚠️ Could not automatically process payment, webhook may be delayed")
            raise HTTPException(
                status_code=404, 
                detail="License key not issued yet. Webhook processing may be delayed. Please try again in a few moments."
            )
        
        logger.info(f"[PAYMENTS] License key found for payment {payment_id}")
        return {
            "payment_id": payment_id,
            "license_key": license_key,
            "license_type": payment_db.get("license_type", "forever"),
            "status": "succeeded"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[PAYMENTS] Error getting license for payment {payment_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# ==== CHECK PAYMENT STATUS ====
@router.get("/status/{payment_id}")
async def check_payment_status(payment_id: str, request: Request):
    """
    Проверка статуса платежа.
    Опрашивает ЮKassa API для получения актуального статуса.
    """
    try:
        logger.info(f"[PAYMENTS] ===== Checking payment status: {payment_id} =====")
        logger.info(f"[PAYMENTS] ⚠️ Frontend requested status for payment_id: {payment_id}")
        
        # Сначала проверяем БД
        db = DatabaseManager()
        payment_db = await db.get_yookassa_payment(payment_id)
        
        # КРИТИЧНО: /status - read-only. Если платеж не найден в БД - это ошибка.
        # Платеж ДОЛЖЕН быть создан через /payments/create
        if not payment_db:
            logger.error(f"[PAYMENTS] ❌ Payment {payment_id} NOT FOUND in database!")
            logger.error(f"[PAYMENTS] ⚠️ Payment must be created via /payments/create first")
            logger.error(f"[PAYMENTS] ⚠️ This payment_id was requested by frontend: {payment_id}")
            raise HTTPException(
                status_code=404, 
                detail=f"Payment {payment_id} not found. Payment must be created via /payments/create endpoint first."
            )
        
        logger.info(f"[PAYMENTS] Payment found in DB: status={payment_db.get('status')}, license_key={'present' if payment_db.get('license_key') else 'missing'}")

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

        # КРИТИЧНО: Используем глобальную сессию из app.state (auth уже настроен в сессии)
        session = get_yookassa_session(request)
        if not session:
            logger.warning("[PAYMENTS] YooKassa session not available, returning DB status only")
            # Возвращаем статус из БД если сессия недоступна
            if payment_db:
                return {
                    "status": payment_db.get("status", "pending"),
                    "metadata": {
                        "license_type": payment_db.get("license_type", "")
                    },
                    "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
                }
            else:
                raise HTTPException(status_code=500, detail="YooKassa session not available and payment not found in DB")

        try:
            logger.info(f"[PAYMENTS] Requesting payment status from YooKassa: {yookassa_status_url}")
            
            async with session.get(yookassa_status_url) as response:
                    logger.info(f"[PAYMENTS] YooKassa HTTP response status: {response.status}")
                    
                    # Логируем заголовки ответа для отладки
                    logger.debug(f"[PAYMENTS] Response headers: {dict(response.headers)}")
                    
                    if response.status == 200:
                        # КРИТИЧНО: Читаем JSON внутри контекста response
                        data = await safe_read_json(response)
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
                        
                        # КРИТИЧНО: Если платеж succeeded, но лицензия не выдана - обрабатываем автоматически
                        if yookassa_status == "succeeded" and data.get("paid") and not payment_db.get("license_key"):
                            logger.info(f"[PAYMENTS] 🔄 Payment succeeded but license not issued, processing automatically...")
                            try:
                                success = await process_payment_succeeded(data)
                                if success:
                                    logger.info(f"[PAYMENTS] ✅ Automatic processing successful")
                                    # Обновляем данные из БД
                                    payment_db = await db.get_yookassa_payment(payment_id)
                                else:
                                    logger.error(f"[PAYMENTS] ❌ Automatic processing failed")
                            except Exception as auto_err:
                                logger.error(f"[PAYMENTS] Error in automatic processing: {auto_err}", exc_info=True)
                        
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
                        
                        # КРИТИЧНО: /status - read-only. Обработка платежа (выдача ключей) происходит только через webhook.
                        # Здесь только обновляем статус в БД, если он изменился.
                        
                        return {
                            "status": yookassa_status,
                            "metadata": {
                                "license_type": license_type_final
                            },
                            "amount": f"{amount_value:.2f}"
                        }
                    elif response.status == 404:
                        logger.warning(f"[PAYMENTS] Payment {payment_id} not found in YooKassa")
                        # Возвращаем статус из БД (если есть)
                        if payment_db:
                            return {
                                "status": payment_db.get("status", "pending"),
                                "metadata": {
                                    "license_type": payment_db.get("license_type", "")
                                },
                                "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
                            }
                        else:
                            raise HTTPException(status_code=404, detail=f"Payment {payment_id} not found in database or YooKassa.")
                    else:
                        # Для других статусов пытаемся прочитать ошибку
                        try:
                            error_text = await response.text()
                            logger.error(f"[PAYMENTS] YooKassa status check error {response.status}")
                            logger.error(f"[PAYMENTS] Error response body: {error_text[:500]}")
                        except Exception as text_err:
                            logger.error(f"[PAYMENTS] YooKassa status check error {response.status}, could not read error text: {text_err}")
                        
                        # Возвращаем статус из БД при ошибке (если есть)
                        if payment_db:
                            return {
                                "status": payment_db.get("status", "pending"),
                                "metadata": {
                                    "license_type": payment_db.get("license_type", "")
                                },
                                "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
                            }
                        else:
                            raise HTTPException(status_code=500, detail=f"Error checking payment status: YooKassa returned {response.status}")
                    
        except aiohttp.ClientError as client_error:
            logger.error(f"[PAYMENTS] Network error when checking payment status from YooKassa: {client_error}", exc_info=True)
            # Возвращаем статус из БД при сетевой ошибке (если есть)
            if payment_db:
                return {
                    "status": payment_db.get("status", "pending"),
                    "metadata": {
                        "license_type": payment_db.get("license_type", "")
                    },
                    "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
                }
            else:
                raise HTTPException(status_code=500, detail=f"Network error checking payment status: {str(client_error)}")
        except aiohttp.ServerTimeoutError:
            logger.error(f"[PAYMENTS] Timeout when checking payment status from YooKassa")
            # Возвращаем статус из БД при таймауте (если есть)
            if payment_db:
                return {
                    "status": payment_db.get("status", "pending"),
                    "metadata": {
                        "license_type": payment_db.get("license_type", "")
                    },
                    "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
                }
            else:
                raise HTTPException(status_code=500, detail="Timeout checking payment status from YooKassa")
        
        # Инициализируем payment_db для случая, если он не был определен выше
        payment_db = None
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[PAYMENTS] Unexpected error when checking payment status: {e}", exc_info=True)
        # Возвращаем статус из БД при ошибке (если есть)
        if 'payment_db' in locals() and payment_db:
            return {
                "status": payment_db.get("status", "pending"),
                "metadata": {
                    "license_type": payment_db.get("license_type", "")
                },
                "amount": f"{payment_db.get('amount', 0) / 100:.2f}"
            }
        else:
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
