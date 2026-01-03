# app/main.py
import asyncio
import contextlib
import time
import os
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path
import aiohttp
from aiohttp import BasicAuth

# КРИТИЧНО: Загружаем env.env ПЕРЕД всеми импортами, чтобы переменные были доступны
def _load_env_file():
    """Загружает переменные окружения из app/env.env"""
    env_file = Path(__file__).parent / "env.env"
    loaded_keys = []
    if env_file.exists():
        try:
            with env_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    # Не перезаписываем, если уже задано в окружении
                    if key and key not in os.environ:
                        os.environ[key] = value
                        loaded_keys.append(key)
            print(f"[ENV] Loaded {len(loaded_keys)} variables from {env_file}: {', '.join(loaded_keys)}")
        except Exception as e:
            print(f"[ENV] Warning: Failed to load env.env: {e}")
    else:
        print(f"[ENV] Warning: env.env not found at {env_file}")

_load_env_file()

from fastapi import FastAPI, HTTPException, File, UploadFile, Request, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel

from app.logger import logger
import psycopg2
from app.security import jwt_auth
from app.websocket_manager import WebSocketManager, ClientConnection
from app.schemas import (
    CheckResponse,
    UrlCheckRequest,
    FileCheckRequest,
    LocalCacheCheckRequest,
    LocalCacheSaveRequest,
    LocalCacheResponse,
    LocalCacheStatsResponse
)
from app.validators import security_validator
from app.external_apis.manager import external_api_manager
from app.admin_ui import router as admin_ui_router
from app.background_jobs import background_job_manager
from app.auth import auth_manager
from app.routes.payments import router as payments_router

# КРИТИЧНО: Безопасный импорт сервисов с обработкой ошибок
try:
    from app.services import analysis_service
except Exception as import_error:
    logger.critical(f"Failed to import analysis_service: {import_error}", exc_info=True)
    # Создаем заглушку для предотвращения полного падения
    class DummyAnalysisService:
        async def analyze_url(self, url, use_external_apis=None):
            return {"safe": None, "details": "Service unavailable", "source": "error"}
        async def analyze_file_hash(self, file_hash, use_external_apis=None):
            return {"safe": None, "details": "Service unavailable", "source": "error"}
        async def analyze_uploaded_file(self, file_content, original_filename):
            return {"safe": None, "details": "Service unavailable", "source": "error"}
    analysis_service = DummyAnalysisService()

try:
    from app.database import db_manager
except Exception as import_error:
    logger.critical(f"Failed to import db_manager: {import_error}", exc_info=True)
    db_manager = None

def check_feature_access(request: Request, required_feature: str) -> bool:
    """Проверяет доступ к конкретной функции через JWT токен"""
    user_info = getattr(request.state, 'user_info', None)
    if not user_info:
        return False
    
    # Получаем features из JWT payload или из user_info
    features = user_info.get('features', [])
    if isinstance(features, str):
        import json
        try:
            features = json.loads(features)
        except:
            features = []
    
    return required_feature in features

def require_feature(feature: str):
    """Декоратор для проверки доступа к функции"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Находим request в аргументах
            request = None
            for arg in args:
                if hasattr(arg, 'state'):
                    request = arg
                    break
            
            if not request or not check_feature_access(request, feature):
                raise HTTPException(
                    status_code=403, 
                    detail=f"Feature '{feature}' requires premium API key"
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator


async def handle_ws_message(client: ClientConnection, message: Dict[str, Any]) -> None:
    """Обрабатывает входящее сообщение от WebSocket клиента."""
    if not isinstance(message, dict):
        await ws_manager.send_error(client, None, "Invalid message format", code="invalid_format")
        return

    msg_type = (message.get("type") or "").lower()
    request_id = message.get("requestId") or message.get("id")
    payload = message.get("payload")
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        payload = {"value": payload}

    await ws_manager.mark_heartbeat(client)

    if msg_type in {"ping", "heartbeat"}:
        await ws_manager.send_json(client, {
            "type": "pong",
            "requestId": request_id,
            "timestamp": datetime.utcnow().isoformat()
        })
        return

    if msg_type == "subscribe":
        channels = []
        if isinstance(payload, list):
            channels = [str(ch) for ch in payload]
        elif isinstance(payload, dict):
            channels = [str(ch) for ch in payload.get("channels", [])]
        client.subscriptions = set(channels)
        await ws_manager.send_json(client, {
            "type": "subscribed",
            "channels": list(client.subscriptions),
            "requestId": request_id,
            "timestamp": datetime.utcnow().isoformat()
        })
        return

    if msg_type == "analyze_url":
        url = payload.get("url")
        if not url:
            await ws_manager.send_error(client, request_id, "Payload must include 'url'", code="bad_request")
            return

        use_external = payload.get("use_external_apis")
        if use_external is None:
            use_external = True

        context = payload.get("context", "generic")

        if context == "hover" and "hover_analysis" not in client.features:
            await ws_manager.send_error(client, request_id, "Hover analysis requires premium token", code="forbidden")
            return

        # КРИТИЧНО: Отправляем статус "scan_started" перед началом анализа
        try:
            await ws_manager.send_json(client, {
                "type": "scan_started",
                "requestId": request_id,
                "url": url,
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.warning(f"[WS] Failed to send scan_started status: {e}")

        try:
            logger.info(f"[WS] Starting URL analysis for: {url} (context: {context})")
            result = await analysis_service.analyze_url(url, use_external_apis=use_external)
            if not isinstance(result, dict):
                raise ValueError("Invalid response from analysis service")
            
            logger.info(f"[WS] URL analysis completed for {url}: safe={result.get('safe')}, source={result.get('source')}")
        except Exception as exc:
            logger.error(f"[WS] URL analysis failed ({url}): {exc}", exc_info=True)
            await ws_manager.send_error(client, request_id, f"URL analysis error: {type(exc).__name__}", code="analysis_error")
            return

        response_payload = {
            "kind": "url",
            "url": url,
            "context": context,
            **result
        }
        
        # КРИТИЧНО: Отправляем результат анализа
        try:
            await ws_manager.send_json(client, {
                "type": "analysis_result",
                "requestId": request_id,
                "payload": response_payload,
                "timestamp": datetime.utcnow().isoformat()
            })
            logger.info(f"[WS] Sent analysis_result for {url} to client {client.id}")
        except Exception as send_error:
            logger.error(f"[WS] Failed to send analysis_result for {url}: {send_error}", exc_info=True)
        return

    if msg_type == "analyze_file_hash":
        file_hash = payload.get("hash") or payload.get("file_hash")
        if not file_hash:
            await ws_manager.send_error(client, request_id, "Payload must include 'hash'", code="bad_request")
            return

        use_external = payload.get("use_external_apis")
        if use_external is None:
            use_external = True

        try:
            result = await analysis_service.analyze_file_hash(file_hash, use_external_apis=use_external)
            if not isinstance(result, dict):
                raise ValueError("Invalid response from analysis service")
        except Exception as exc:
            logger.error(f"[WS] File hash analysis failed ({file_hash}): {exc}", exc_info=True)
            await ws_manager.send_error(client, request_id, f"File analysis error: {type(exc).__name__}", code="analysis_error")
            return

        response_payload = {
            "kind": "file",
            "hash": file_hash,
            "fileName": payload.get("file_name") or payload.get("fileName"),
            **result
        }
        await ws_manager.send_json(client, {
            "type": "analysis_result",
            "requestId": request_id,
            "payload": response_payload,
            "timestamp": datetime.utcnow().isoformat()
        })
        return

    await ws_manager.send_error(client, request_id, f"Unknown message type: {msg_type}", code="unsupported_message")


async def websocket_cleanup_task() -> None:
    """Периодическая очистка неактивных WebSocket соединений."""
    while True:
        try:
            await ws_manager.remove_stale_clients()
        except Exception as exc:
            logger.error(f"[WS] Cleanup task error: {exc}", exc_info=True)
        await asyncio.sleep(30)

# Схемы для аутентификации
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str  # username или email
    password: str

app = FastAPI(
    title="Antivirus Core API",
    description="API ядра для антивирусного расширения браузера", 
    version="0.3.0",
)

ws_manager = WebSocketManager()
app.state.ws_manager = ws_manager
app.state.ws_cleanup_task = None

# КРИТИЧНО: WebSocket endpoint должен быть зарегистрирован ПЕРВЫМ,
# до всех HTTP‑middleware и роутеров, чтобы не перехватываться ими
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint для двусторонней связи с расширением."""
    client_ip = websocket.client.host if websocket.client else "unknown"
    # КРИТИЧНО: Логируем все заголовки для диагностики
    upgrade_header = websocket.headers.get("Upgrade", "")
    connection_header = websocket.headers.get("Connection", "")
    logger.info(f"[WS] WebSocket connection attempt from {client_ip}, Upgrade: {upgrade_header}, Connection: {connection_header}")
    
    try:
        await websocket.accept()
        logger.info(f"[WS] WebSocket connection accepted from {client_ip}")
    except Exception as e:
        logger.error(f"[WS] Failed to accept connection from {client_ip}: {e}", exc_info=True)
        return

    # Извлекаем JWT токен из WebSocket
    from app.jwt_auth import JWTAuth
    
    token = (
        websocket.query_params.get("token")
        or (
            websocket.headers.get("Authorization", "").split(" ", 1)[1].strip()
            if (websocket.headers.get("Authorization") or "").startswith("Bearer ")
            else None
        )
    )

    user_info: Optional[Dict[str, Any]] = None
    if token:
        # Верифицируем JWT токен (stateless - без БД)
        payload = JWTAuth.verify_token(token)
        
        if not payload:
            await websocket.send_json({
                "type": "error",
                "code": "unauthorized",
                "message": "Invalid or expired token"
            })
            await websocket.close(code=4403, reason="Invalid token")
            return

        user_id = payload.get("user_id") or payload.get("sub")
        if not user_id:
            await websocket.send_json({
                "type": "error",
                "code": "unauthorized",
                "message": "Token missing user_id"
            })
            await websocket.close(code=4403, reason="Invalid token")
            return

        user_info = {
            "user_id": user_id,
            "username": payload.get("username"),
            "email": payload.get("email"),
            "access_level": payload.get("access_level", "basic"),
            "features": payload.get("features", []),
            "token_payload": payload
        }
    else:
        # WebSocket может работать без токена для базового доступа
        logger.info(f"[WS] WebSocket connection without token (basic access)")

    meta = {
        "ip": websocket.client.host if websocket.client else None,
        "user_agent": websocket.headers.get("User-Agent", ""),
        "token": token[:20] + "..." if token else None,
    }

    client = await ws_manager.connect(websocket, user_info, meta)

    try:
        await ws_manager.send_json(client, {
            "type": "hello",
            "clientId": client.id,
            "features": list(client.features),
            "timestamp": datetime.utcnow().isoformat()
        })

        while True:
            message = await websocket.receive_json()
            await handle_ws_message(client, message)
    except WebSocketDisconnect:
        logger.info(f"[WS] Client disconnected gracefully: {client.id}")
    except Exception as exc:
        logger.error(f"[WS] Unexpected error for client {client.id}: {exc}", exc_info=True)
        try:
            await ws_manager.send_error(client, None, f"Server error: {type(exc).__name__}", code="server_error")
        except Exception:
            pass
    finally:
        await ws_manager.disconnect(client.id, reason="cleanup")

# Note: do not mount static at /admin/ui to avoid masking /admin/ui/* router routes

# CORS middleware ДОЛЖЕН быть первым среди HTTP-middleware, чтобы обрабатывать OPTIONS запросы
# WebSocket обработчик выше не проходит через это middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    allow_headers=["X-API-Key", "Authorization", "Content-Type", "Origin", "Accept", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol"],
    expose_headers=["*"],
    max_age=3600,
)

# Include admin ui router to serve /admin/ui -> index.html
app.include_router(admin_ui_router)

app.include_router(payments_router, prefix="/payments")

# Сжатие ответов для ускорения отдачи (после CORS, чтобы не мешать заголовкам)
app.add_middleware(GZipMiddleware, minimum_size=500)


@app.get("/ws/health")
async def websocket_health_check():
    """Проверка доступности WebSocket endpoint."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "websocket_available": True,
            "endpoint": "/ws",
            "timestamp": datetime.utcnow().isoformat()
        },
        headers={"Access-Control-Allow-Origin": "*"}
    )

# Middleware логирования запросов в БД
@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """КРИТИЧНО: Все вызовы БД обернуты в try-except для предотвращения падения"""
    # КРИТИЧНО: Логируем webhook запросы ДО всех проверок
    if "/webhook/yookassa" in request.url.path:
        logger.info(f"[WEBHOOK MIDDLEWARE] ===== WEBHOOK REQUEST DETECTED ===== Path: {request.url.path}, Method: {request.method}, IP: {request.client.host if request.client else 'unknown'}")
    
    # КРИТИЧНО: WebSocket upgrade запросы должны пропускаться без обработки
    if request.url.path == "/ws":
        upgrade_header = request.headers.get("Upgrade", "").lower()
        connection_header = request.headers.get("Connection", "").lower()
        logger.info(f"[WS DEBUG] HTTP request to /ws - Method: {request.method}, Upgrade: {upgrade_header}, Connection: {connection_header}")
        if upgrade_header == "websocket":
            logger.info(f"[WS DEBUG] WebSocket upgrade detected, passing to FastAPI router")
            return await call_next(request)
        else:
            logger.warning(f"[WS DEBUG] Request to /ws without WebSocket upgrade header - this might be a proxy issue")
            # Пропускаем дальше, пусть FastAPI сам обработает (вернет 404 если не WebSocket)
            return await call_next(request)
    
    start = time.time()
    response = None
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    except Exception as e:
        # КРИТИЧНО: Логируем ошибку, но не падаем
        logger.error(f"Request processing error in middleware: {e}", exc_info=True)
        status_code = 500
        raise
    finally:
        # КРИТИЧНО: Логирование в БД не должно ломать запросы
        try:
            duration_ms = int((time.time() - start) * 1000)
            user_id = None
            try:
                # Получаем user_id из JWT токена или из request.state
                user_info = getattr(request.state, 'user_info', None)
                if user_info:
                    user_id = user_info.get("user_id")
                else:
                    # Пытаемся извлечь из токена
                    from app.jwt_auth import JWTAuth
                    token = JWTAuth.get_token_from_request(request)
                    if token:
                        payload = JWTAuth.verify_token(token)
                        if payload:
                            user_id = payload.get("user_id") or payload.get("sub")
            except Exception:
                pass  # Игнорируем ошибки парсинга токена
            
            user_agent = request.headers.get("User-Agent", "")
            client_ip = None
            try:
                client_ip = request.headers.get("X-Forwarded-For") or (request.client.host if request.client else None)
            except Exception:
                pass  # Игнорируем ошибки получения IP
            
            # КРИТИЧНО: Логирование в БД не должно падать
            if db_manager:
                try:
                    db_manager.log_request(user_id, request.url.path, request.method, status_code, duration_ms, user_agent, client_ip)
                except Exception as db_error:
                    # Логируем ошибку БД, но не падаем
                    logger.warning(f"Failed to log request to DB (non-critical): {db_error}")
        except Exception as e:
            # Двойная защита - на случай если что-то еще упадет
            logger.error(f"Critical error in request logging middleware: {e}", exc_info=True)

# Первый middleware - фильтрация некорректных запросов
@app.middleware("http")
async def filter_invalid_requests(request: Request, call_next):
    """Фильтрует некорректные HTTP запросы"""
    
    # КРИТИЧНО: Логируем webhook запросы ДО всех проверок
    if "/webhook/yookassa" in request.url.path:
        logger.info(f"[FILTER MIDDLEWARE] ===== WEBHOOK REQUEST IN FILTER ===== Path: {request.url.path}, Method: {request.method}")
    
    # КРИТИЧНО: WebSocket upgrade запросы должны пропускаться без обработки
    # FastAPI автоматически обрабатывает их через @app.websocket, но для надежности проверяем
    if request.url.path == "/ws" and request.headers.get("Upgrade", "").lower() == "websocket":
        return await call_next(request)
    
    # OPTIONS запросы (CORS preflight) пропускаем сразу
    if request.method == "OPTIONS":
        response = await call_next(request)
        # Добавляем явные CORS заголовки для OPTIONS
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
        response.headers["Access-Control-Allow-Headers"] = "X-API-Key, Authorization, Content-Type, Origin, Accept"
        response.headers["Access-Control-Max-Age"] = "3600"
        return response
    
    # Пропускаем только корректные HTTP методы
    valid_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}
    if request.method not in valid_methods:
        logger.warning(f"Invalid HTTP method: {request.method}")
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid HTTP method"},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    
    # Пропускаем только корректные пути
    if request.url.path == "" or request.url.path == "/":
        response = await call_next(request)
        return response
    
    # Блокируем известные вредоносные пути (но разрешаем наши /admin эндпоинты)
    malicious_paths = {"/.env", "/config", "/phpmyadmin", "/wp-admin"}
    # Исключаем наши легитимные admin эндпоинты
    if (any(request.url.path.startswith(path) for path in malicious_paths) and not request.url.path.startswith("/admin/stats") and not request.url.path.startswith("/admin/api-keys") and not request.url.path.startswith("/admin/add")):
        logger.warning(f"Blocked suspicious path: {request.url.path}")
        return JSONResponse(
            status_code=404,
            content={"detail": "Not found"},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    
    
    response = await call_next(request)
    # Добавляем CORS заголовки ко всем ответам
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

# Второй middleware - API key / Bearer authentication (опциональная)
@app.middleware("http")
async def jwt_auth_middleware(request: Request, call_next):
    """
    JWT аутентификация middleware - stateless проверка без запросов к БД.
    """
    from app.jwt_auth import JWTAuth
    
    # Публичные пути - пропускаем без проверки JWT
    PUBLIC_PATHS = (
        "/auth/register",
        "/auth/login",
        "/auth/refresh",
        "/auth/forgot-password",
        "/auth/reset-password",
        "/health",
        "/health/minimal",
        "/health/hover",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/",
        "/favicon.ico",
        "/ws",
        "/ws/health",
        "/payments/debug",
        "/payments/debug/routes",
        "/payments/create",
        "/payments/webhook",
        "/payments/webhook/yookassa",
        "/payments/webhook/yookassa/dev",
        "/payments/status/",
        "/payments/license/",
        "/payments/process/",
        "/admin/api-keys/create",  # Использует ADMIN_API_TOKEN, не JWT
    )
            
    # Проверяем точное совпадение или начало пути
    is_public = request.url.path in PUBLIC_PATHS or any(request.url.path.startswith(path) for path in PUBLIC_PATHS)
    
    # Логируем для диагностики payments запросов
    if "/payments" in request.url.path:
        logger.info(f"[JWT MIDDLEWARE] Payments request: path={request.url.path}, is_public={is_public}, method={request.method}")
    
    if is_public:
        return await call_next(request)
    
    # WebSocket upgrade запросы пропускаем
    if request.url.path == "/ws" and request.headers.get("Upgrade", "").lower() == "websocket":
            return await call_next(request)
    
    # OPTIONS запросы пропускаем
    if request.method == "OPTIONS":
        return await call_next(request)
    
    # Базовые API пути - доступны без аутентификации
    basic_api_paths = ["/check/url", "/check/file", "/check/upload", "/check/domain/"]
    
    # Извлекаем JWT токен из заголовков
    token = JWTAuth.get_token_from_request(request)
    
    if not token:
        # Если токен не предоставлен, проверяем базовые пути
        if any(request.url.path.startswith(path) for path in basic_api_paths):
            request.state.user_info = None
            return await call_next(request)
        else:
            # Для защищённых путей требуется токен
            return JSONResponse(
                status_code=401,
                content={"detail": "Authorization token required"},
                headers={"Access-Control-Allow-Origin": "*", "WWW-Authenticate": "Bearer"}
            )
    
    # Верифицируем JWT токен (stateless - без БД)
    payload = JWTAuth.verify_token(token)
    
    if not payload:
        # Токен невалиден или истёк
        if any(request.url.path.startswith(path) for path in basic_api_paths):
            # Для базовых путей разрешаем без токена
            request.state.user_info = None
            return await call_next(request)
        else:
            return JSONResponse(
                status_code=401, 
                content={"detail": "Invalid or expired token"},
                headers={"Access-Control-Allow-Origin": "*", "WWW-Authenticate": "Bearer"}
            )
    
    # Сохраняем информацию о пользователе в request state
    user_id = payload.get("user_id") or payload.get("sub")
    request.state.user_info = {
        "user_id": user_id,
        "username": payload.get("username"),
        "email": payload.get("email"),
        "access_level": payload.get("access_level", "basic"),
        "features": payload.get("features", []),
        "token_payload": payload
    }
                
    # Логирование для диагностики
    is_hover_req = request.headers.get("X-Request-Source") == "hover"
    if is_hover_req:
        logger.debug(f"[JWT] Hover request authenticated: user_id={user_id}, path={request.url.path}")
    
    return await call_next(request)



# Третий middleware - обработка ошибок
@app.middleware("http")
async def error_handling_middleware(request: Request, call_next):
    """Middleware для обработки ошибок"""
    try:
        return await call_next(request)
    except HTTPException as e:
        # Передаем HTTP исключения как есть
        logger.warning(f"HTTP error {e.status_code}: {e.detail} for {request.url.path}")
        return JSONResponse(
            status_code=e.status_code,
            content={"detail": e.detail, "error_code": e.status_code},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    except Exception as e:
        # КРИТИЧНО: Детальное логирование для диагностики 500 ошибок
        import traceback
        error_trace = traceback.format_exc()
        error_type = type(e).__name__
        error_message = str(e)
        
        logger.error(
            f"[500 ERROR] Unhandled exception in {request.url.path}:\n"
            f"  Type: {error_type}\n"
            f"  Message: {error_message}\n"
            f"  Method: {request.method}\n"
            f"  Headers: {dict(request.headers)}\n"
            f"  Traceback:\n{error_trace}",
            exc_info=True
        )
        
        # В режиме разработки возвращаем больше информации
        import os
        is_debug = os.getenv("DEBUG", "false").lower() == "true"
        
        error_detail = {
            "detail": "Internal server error",
            "error_code": "INTERNAL_ERROR",
            "request_id": f"req_{int(time.time())}",
            "path": request.url.path,
            "method": request.method
        }
        
        if is_debug:
            error_detail["error_type"] = error_type
            error_detail["error_message"] = error_message[:200]  # Ограничиваем длину
        
        return JSONResponse(
            status_code=500,
            content=error_detail,
            headers={"Access-Control-Allow-Origin": "*"}
        )

@app.get("/health")
async def health_check():
    """КРИТИЧНО: Минимальный health check БЕЗ зависимостей от БД или внешних API"""
    try:
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "safe": True,
                "details": "Server running",
                "timestamp": datetime.now().isoformat(),
                "version": "0.3.0"
            },
            headers={"Access-Control-Allow-Origin": "*"}
        )
    except Exception as e:
        # Даже health check должен обрабатывать ошибки
        logger.error(f"Health check error: {e}", exc_info=True)
        return JSONResponse(
            status_code=200,  # Все равно 200, чтобы показать что сервер жив
            content={
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            },
            headers={"Access-Control-Allow-Origin": "*"}
        )

@app.get("/health/minimal")
async def minimal_health_check():
    """КРИТИЧНО: Абсолютно минимальный health check - только проверка что сервер отвечает"""
    return JSONResponse(
        status_code=200,
        content={"status": "ok"},
        headers={"Access-Control-Allow-Origin": "*"}
    )

@app.get("/health/hover")
async def health_check_hover(request: Request):
    """КРИТИЧНО: Проверка работоспособности hover системы"""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "components": {}
        }
        
        # 1. Проверка соединения с БД
        if db_manager:
            test_url = "https://example.com"
        try:
            db_test = db_manager.check_url(test_url)
            health_status["components"]["database"] = "connected"
        except (psycopg2.OperationalError, psycopg2.InterfaceError, AttributeError) as db_error:
            error_msg = str(db_error).lower()
            health_status["components"]["database"] = f"error: {str(db_error)[:50]}"
            health_status["status"] = "degraded"
        except Exception as db_error:
            logger.warning(f"Hover health check: DB error: {db_error}")
            health_status["components"]["database"] = f"error: {str(db_error)[:50]}"
            health_status["status"] = "degraded"
        else:
            health_status["components"]["database"] = "unavailable"
            health_status["status"] = "degraded"
        
        # 2. Проверка внешних API (быстрая проверка доступности)
        try:
            import asyncio
            # Быстрая проверка без реального запроса
            health_status["components"]["external_apis"] = "available"
        except Exception as api_error:
            health_status["components"]["external_apis"] = f"error: {str(api_error)[:50]}"
            health_status["status"] = "degraded"
        
        # 3. Проверка наличия JWT токена в запросе
        from app.jwt_auth import JWTAuth
        token = JWTAuth.get_token_from_request(request)
        user_info = getattr(request.state, 'user_info', None)
        has_token = bool(token) or user_info is not None
        health_status["components"]["authentication"] = "ok" if has_token else "no_token"
        
        # 4. Проверка памяти (если доступно)
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            health_status["components"]["memory_mb"] = round(memory_mb, 2)
            if memory_mb > 1000:  # Больше 1GB - предупреждение
                health_status["status"] = "degraded"
        except ImportError:
            health_status["components"]["memory"] = "unavailable"
        except Exception:
            pass
        
        logger.info(f"[HEALTH HOVER] Status: {health_status['status']}, Components: {health_status['components']}")
        
        status_code = 200 if health_status["status"] == "healthy" else (503 if health_status["status"] == "unhealthy" else 200)
        
        return JSONResponse(
            status_code=status_code,
            content={
                **health_status,
                "hover_system": "operational",
                "version": "0.3.0"
            },
            headers={"Access-Control-Allow-Origin": "*"}
        )
    except Exception as e:
        logger.error(f"Hover health check failed: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            },
            headers={"Access-Control-Allow-Origin": "*"}
        )

@app.get("/auth/validate")
async def validate_key(request: Request):
    """Проверка валидности JWT токена для клиентских приложений"""
    user_info = getattr(request.state, 'user_info', None)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    
    return {
        "valid": True,
        "user_id": user_info.get("user_id"),
        "username": user_info.get("username"),
        "email": user_info.get("email"),
        "access_level": user_info.get("access_level", "basic"),
        "features": user_info.get("features", [])
    }

@app.get("/")
async def root():
    return {"status": "success", "safe": True, "details": "DEV VERSION TEST"}

@app.get("/admin/ui")
async def admin_ui():
    """Admin UI для управления ключами"""
    import os
    # Путь к admin.html относительно app/main.py
    admin_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "admin.html")
    if not os.path.exists(admin_path):
        raise HTTPException(status_code=404, detail="Admin UI not found")
    return FileResponse(admin_path, headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    })

@app.get("/admin/ui/refresh")
async def admin_ui_refresh():
    """Admin UI с принудительным обновлением"""
    import os
    admin_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "admin.html")
    if not os.path.exists(admin_path):
        raise HTTPException(status_code=404, detail="Admin UI not found")
    return FileResponse(admin_path, headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "Last-Modified": "Thu, 01 Jan 1970 00:00:00 GMT"
    })

@app.post("/check/url", response_model=CheckResponse)
async def check_url_secure(
    url_request: UrlCheckRequest,
    request: Request
):
    """Проверка URL - базовый функционал доступен всем"""
    # КРИТИЧНО: Логирование для диагностики разницы между popup и hover запросами
    try:
        client_ip = request.headers.get("X-Forwarded-For") or (request.client.host if request.client else None)
        user_agent = request.headers.get("User-Agent", "")
        api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        is_hover = "hover" in user_agent.lower() or request.headers.get("X-Request-Source") == "hover"
        
        logger.info(f"[CHECK_URL] Request from {'HOVER' if is_hover else 'POPUP'}: url={str(url_request.url)[:50]}, has_api_key={bool(api_key)}, ip={client_ip}")
    except Exception as log_error:
        logger.warning(f"Error in request logging: {log_error}")
        is_hover = False
    
    try:
        # КРИТИЧНО: Валидация URL с обработкой ошибок
        try:
            url_str = str(url_request.url)
            validation_error = security_validator.validate_url(url_str)
        except Exception as validation_ex:
            logger.error(f"URL validation error: {validation_ex}", exc_info=True)
            return JSONResponse(
                status_code=400,
                content={"detail": f"Invalid URL format: {str(validation_ex)}", "safe": None, "source": "validation_error"},
                headers={"Access-Control-Allow-Origin": "*"}
            )
        
        if validation_error:
            logger.warning(f"[CHECK_URL] Validation error ({'HOVER' if is_hover else 'POPUP'}): {validation_error}")
            return JSONResponse(
                status_code=400,
                content={"detail": validation_error, "safe": None, "source": "validation_error"},
                headers={"Access-Control-Allow-Origin": "*"}
            )
        
        # Проверяем уровень доступа для расширенного анализа
        user_info = getattr(request.state, 'user_info', None)
        use_external_apis = True  # Включаем внешние API для всех пользователей для базовой безопасности
        
        # КРИТИЧНО: Для hover запросов всегда используем внешние API и логируем
        if is_hover:
            logger.debug(f"[CHECK_URL HOVER] Starting analysis with external APIs")
        
        # КРИТИЧНО: Используем асинхронный вызов с обработкой ошибок
        try:
            result = await analysis_service.analyze_url(url_str, use_external_apis=use_external_apis)
        except Exception as analysis_error:
            logger.error(f"Analysis service error for {url_str}: {analysis_error}", exc_info=True)
            # Возвращаем безопасный результат вместо падения
            result = {
                "safe": None,
                "threat_type": None,
                "details": f"Analysis temporarily unavailable: {type(analysis_error).__name__}",
                "source": "error"
            }
        
        # КРИТИЧНО: Проверяем что result валиден
        if not result or not isinstance(result, dict):
            logger.error(f"Invalid result from analysis_service: {result}")
            result = {
                "safe": None,
                "threat_type": None,
                "details": "Analysis returned invalid result",
                "source": "error"
            }
        
        # КРИТИЧНО: Логирование результата для диагностики
        logger.info(f"[CHECK_URL] Result ({'HOVER' if is_hover else 'POPUP'}): safe={result.get('safe')}, source={result.get('source')}")
        
        # Создаем ответ
        try:
            # КРИТИЧНО: НЕ устанавливаем safe: True по умолчанию!
            # Если safe не указан, проверяем threat_type - если есть, значит небезопасно
            safe_value = result.get("safe")
            threat_type = result.get("threat_type")
            
            # КРИТИЧНО: Если safe не указан, определяем по threat_type
            if safe_value is None:
                if threat_type:
                    # Если есть threat_type, значит небезопасно
                    safe_value = False
                else:
                    # Если нет threat_type и safe не указан - неизвестно
                    # НЕ устанавливаем True по умолчанию!
                    safe_value = None
            
            response_data = {
                "safe": safe_value,
                "threat_type": threat_type,
                "details": result.get("details", ""),
                "source": result.get("source", "unknown")
            }
            
            # КРИТИЧНО: Валидация через CheckResponse - safe может быть None
            validated = CheckResponse(**response_data)
            response_data = validated.dict()
        except Exception as schema_error:
            logger.error(f"Schema validation error: {schema_error}, result: {result}", exc_info=True)
            # Fallback - НЕ устанавливаем safe: True по умолчанию!
            response_data = {
                "safe": None,  # Неизвестно, а не безопасно!
                "threat_type": result.get("threat_type"),
                "details": result.get("details", "Analysis completed"),
                "source": result.get("source", "unknown")
            }

        # КРИТИЧНО: Фиксируем безопасные/опасные URL в локальной БД (whitelist/blacklist)
        try:
            if db_manager and url_str:
                if response_data.get("safe") is True:
                    # Безопасные URL -> cached_whitelist
                    db_manager.save_whitelist_entry(url_str, response_data)
                elif response_data.get("safe") is False:
                    # Опасные URL -> cached_blacklist
                    db_manager.save_blacklist_entry(url_str, response_data)
        except Exception as persist_error:
            logger.warning(f"Failed to persist URL verdict to cache DB for {url_str}: {persist_error}")

        return JSONResponse(
            content=response_data,
            headers={"Access-Control-Allow-Origin": "*"}
        )
    except HTTPException:
        raise
    except Exception as e:
        # КРИТИЧНО: Детальное логирование всех ошибок
        import traceback
        error_trace = traceback.format_exc()
        logger.error(
            f"[CHECK_URL] Critical error: {type(e).__name__}: {str(e)}\n"
            f"Traceback:\n{error_trace}",
            exc_info=True
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": f"Internal server error: {type(e).__name__}",
                "safe": None,
                "source": "server_error"
            },
            headers={"Access-Control-Allow-Origin": "*"}
        )

# Совместимый алиас для старых клиентов
@app.post("/scan/url", response_model=CheckResponse)
async def scan_url_alias(
    url_request: UrlCheckRequest,
    request: Request
):
    return await check_url_secure(url_request, request)

@app.post("/check/file", response_model=CheckResponse)  
async def check_file_secure(
    file_request: FileCheckRequest,
    request: Request
):
    """Проверка файла по хэшу - базовый функционал доступен всем"""
    validation_error = security_validator.validate_file_hash(file_request.file_hash)
    if validation_error:
        raise HTTPException(status_code=400, detail=validation_error)
    
    try:
        # Проверяем уровень доступа для расширенного анализа
        user_info = getattr(request.state, 'user_info', None)
        use_external_apis = user_info is not None and check_feature_access(request, "advanced_analysis")
        
        # Асинхронный вызов с учетом уровня доступа
        result = await analysis_service.analyze_file_hash(file_request.file_hash, use_external_apis=use_external_apis)
        return CheckResponse(**result)
    except Exception as e:
        logger.error(f"File hash check failed: {e}")
        raise HTTPException(status_code=500, detail="Analysis error")

@app.post("/check/upload")
async def check_uploaded_file(file: UploadFile = File(...)):
    """Анализ загруженного файла."""
    try:
        logger.info(f"File upload started: {file.filename}")
        
        # Валидация размера файла
        file_content = await file.read()
        size_validation = security_validator.validate_file_size(len(file_content))
        if size_validation:
            raise HTTPException(status_code=413, detail=size_validation)
        
        # Валидация имени файла
        sanitized_filename = security_validator.sanitize_filename(file.filename or "unknown")
        
        result = await analysis_service.analyze_uploaded_file(file_content, sanitized_filename)
        
        return {
            "status": "success",
            "filename": sanitized_filename,
            "file_size": len(file_content),
            **result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File analysis failed: {file.filename} - {str(e)}")
        raise HTTPException(status_code=500, detail=f"File analysis error: {str(e)}")
    finally:
        await file.close()

# ==== LOCAL SECURITY CACHE ENDPOINTS ====

@app.post("/local-cache/check", response_model=LocalCacheResponse)
async def local_cache_check(request_data: LocalCacheCheckRequest):
    if not db_manager:
        raise HTTPException(status_code=503, detail="Database unavailable")
    url_str = str(request_data.url)
    try:
        cached = db_manager.get_cached_security(url_str)
        if cached:
            return {"status": "hit", **cached}
        return {"status": "miss", "safe": None}
    except Exception as e:
        logger.error(f"Local cache check error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Local cache lookup failed")


@app.post("/local-cache/save")
async def local_cache_save(request_data: LocalCacheSaveRequest):
    if not db_manager:
        raise HTTPException(status_code=503, detail="Database unavailable")
    url_str = str(request_data.url)
    payload = request_data.dict()
    payload.pop("url", None)
    try:
        if request_data.safe:
            success = db_manager.save_whitelist_entry(url_str, payload)
        else:
            success = db_manager.save_blacklist_entry(url_str, payload)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to persist cache entry")
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Local cache save error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Local cache save failed")


@app.get("/local-cache/stats", response_model=LocalCacheStatsResponse)
async def local_cache_stats():
    if not db_manager:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return db_manager.get_cache_stats()

@app.get("/check/domain/{domain}")
async def check_domain(domain: str):
    """Проверка домена на наличие угроз."""
    try:
        logger.info(f"Domain check requested: {domain}")
        threats = db_manager.check_domain(domain)
        
        return {
            "status": "success",
            "domain": domain,
            "safe": len(threats) == 0,
            "threat_count": len(threats),
            "threats": threats
        }
    except Exception as e:
        logger.error(f"Domain check failed: {domain} - {str(e)}")
        raise HTTPException(status_code=500, detail=f"Domain check error: {str(e)}")

# Упрощенные административные эндпоинты
@app.get("/admin/stats")
async def get_database_stats():
    """Получение статистики базы данных."""
    try:
        stats = db_manager.get_database_stats()
        return {"status": "success", "stats": stats}
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get stats")

@app.post("/admin/add/malicious-hash")
async def add_malicious_hash(hash: str, threat_type: str, description: str = ""):
    """Добавление вредоносного хэша."""
    try:
        success = db_manager.add_malicious_hash(hash, threat_type, description)
        if success:
            return {"status": "success", "message": "Hash added to database"}
        else:
            raise HTTPException(status_code=500, detail="Failed to add hash")
    except Exception as e:
        logger.error(f"Add hash error: {e}")
        raise HTTPException(status_code=500, detail="Failed to add hash")

@app.post("/admin/api-keys/toggle")
async def toggle_api_key(api_key: str, is_active: bool, request: Request):
    """Активация/деактивация API ключа (требует JWT аутентификации)."""
    # Проверяем JWT аутентификацию
    user_info = getattr(request.state, 'user_info', None)
    if not user_info:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not db_manager:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    try:
        with db_manager._get_connection() as conn:
            cursor = conn.cursor()
            query = "UPDATE api_keys SET is_active = %s WHERE api_key = %s"
            cursor.execute(db_manager._adapt_query(query), (is_active, api_key))
            db_manager._commit_if_needed(conn)
        return {"status": "success", "api_key": api_key, "is_active": is_active}
    except Exception as e:
        logger.error(f"Toggle API key error: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle API key")

@app.post("/admin/api-keys/delete")
async def delete_api_key(api_key: str, request: Request):
    """Удаление API ключа из БД (требует JWT аутентификации)."""
    # Проверяем JWT аутентификацию
    user_info = getattr(request.state, 'user_info', None)
    if not user_info:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not db_manager:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    try:
        with db_manager._get_connection() as conn:
            cursor = conn.cursor()
            # Проверяем существование ключа
            query_select = "SELECT api_key FROM api_keys WHERE api_key = %s"
            cursor.execute(db_manager._adapt_query(query_select), (api_key,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="API key not found")
            # Удаляем ключ
            query_delete = "DELETE FROM api_keys WHERE api_key = %s"
            cursor.execute(db_manager._adapt_query(query_delete), (api_key,))
            db_manager._commit_if_needed(conn)
            logger.info(f"API key deleted: {api_key[:10]}...")
        return {"status": "success", "message": "API key deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete API key error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to delete API key")

@app.post("/admin/api-keys/validate")
async def validate_token_endpoint(request: Request):
    """Валидация JWT токена (deprecated - используйте /auth/validate)"""
    user_info = getattr(request.state, 'user_info', None)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return {
        "valid": True,
        "user_id": user_info.get("user_id"),
        "username": user_info.get("username"),
        "access_level": user_info.get("access_level"),
        "features": user_info.get("features", [])
    }

@app.post("/admin/api-keys/create")
async def create_api_key(request: Request):
    """Создание нового премиум API ключа."""
    try:
        # Проверка авторизации через X-Admin-Token
        import os
        # env.env уже загружен в начале файла через _load_env_file()
        admin_token = os.getenv("ADMIN_API_TOKEN", "")
        
        token_header = request.headers.get("X-Admin-Token", "")
        if not token_header or token_header != admin_token:
            raise HTTPException(status_code=403, detail="Invalid authorization token")
        
        # Получаем данные из JSON body
        body = await request.json()
        name = body.get("name")
        description = body.get("description", "")
        access_level = body.get("access_level", "premium")
        daily_limit = body.get("daily_limit")  # None или <=0 = без лимитов
        hourly_limit = body.get("hourly_limit")  # None или <=0 = без лимитов
        expires_days = body.get("expires_days", 30)
        
        # Для Telegram-бота и веб-платежей: если передан user_id, используем expires_days из запроса
        user_id = body.get("user_id")
        user_id_int = None
        if user_id:
            try:
                user_id_int = int(user_id)
            except (ValueError, TypeError):
                logger.warning(f"Invalid user_id format: {user_id}, ignoring")
                user_id_int = None
            
            # expires_days уже установлен из body (36500 для вечной, 30 для месячной)
            if not name:
                name = f"Telegram User {user_id_int}" if user_id_int else "Web User"
            if not description:
                username = body.get("username", "")
                license_type = "Lifetime" if expires_days >= 36500 else "Monthly"
                user_desc = f"Telegram user {user_id_int}" if user_id_int else "Web user"
                description = f"{license_type} license for {user_desc}" + (f" (@{username})" if username else "")
        
        # Валидация обязательных полей
        if not name:
            raise HTTPException(status_code=400, detail="Name is required")
        
        # Только премиум ключи
        if access_level != "premium":
            raise HTTPException(status_code=400, detail="Only premium keys can be created")
        
        api_key = db_manager.create_api_key(name, description, access_level, daily_limit, hourly_limit, expires_days, user_id=user_id_int)
        if api_key:
            response = {
                "status": "success",
                "api_key": api_key,
                "name": name,
                "access_level": access_level,
                "daily_limit": daily_limit,
                "hourly_limit": hourly_limit,
                "expires_days": expires_days,
                "features": "advanced_analysis,hover_analysis"
            }
            # Для Telegram-бота возвращаем в формате license_key
            if user_id:
                response["success"] = True
                response["license_key"] = api_key
                # Для вечных лицензий expires_at = None
                if expires_days >= 36500:
                    response["expires_at"] = None
            return response
        else:
            raise HTTPException(status_code=500, detail="Failed to create API key")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/api-keys/extend")
async def extend_api_key(request: Request):
    """Продление срока действия API ключа"""
    try:
        # Получаем данные из JSON body
        body = await request.json()
        api_key = body.get("api_key")
        extend_days = body.get("extend_days")
        
        # Валидация обязательных полей
        if not api_key:
            raise HTTPException(status_code=400, detail="API key is required")
        if not extend_days:
            raise HTTPException(status_code=400, detail="Extend days is required")
        
        # Валидация параметров
        if extend_days <= 0:
            raise HTTPException(status_code=400, detail="Extend days must be positive")
        
        success = db_manager.extend_api_key(api_key, extend_days)
        if success:
            return {
                "status": "success",
                "message": f"API key extended by {extend_days} days"
            }
        else:
            raise HTTPException(status_code=404, detail="API key not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Extend API key error: {e}")
        raise HTTPException(status_code=500, detail="Failed to extend API key")

@app.get("/admin/api-keys")
async def list_api_keys(request: Request):
    """Получение списка всех API ключей"""
    try:
        keys = db_manager.list_api_keys()
        return keys
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List API keys error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list API keys")

@app.get("/admin/api-keys/{api_key}/stats")
async def get_api_key_stats(api_key: str):
    """Получение статистики по ключу."""
    try:
        stats = db_manager.get_api_key_stats(api_key)
        if not stats:
            raise HTTPException(status_code=404, detail="API key not found")
        return {"status": "success", "stats": stats}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get key stats")
    # НОВЫЙ ЭНДПОИНТ ДЛЯ ПРОВЕРКИ IP
@app.get("/check/ip/{ip_address}")
async def check_ip_address(
    ip_address: str,
    request: Request
):
    """Проверка IP адреса - требует премиум API ключ"""
    # Проверяем доступ к функции проверки IP
    if not check_feature_access(request, "ip_check"):
        raise HTTPException(
            status_code=403, 
            detail="IP address checking requires premium API key"
        )
    
    try:
        # Валидация IP адреса
        ip_validation = security_validator.validate_ip_address(ip_address)
        if ip_validation:
            raise HTTPException(status_code=400, detail=ip_validation)
        
        result = await external_api_manager.check_ip_multiple_apis(ip_address)
        return {
            "status": "success",
            "ip": ip_address,
            **result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"IP check failed: {e}")
        raise HTTPException(status_code=500, detail="IP analysis error")

@app.post("/check/hover")
async def check_hover_analysis(request: Request):
    """Анализ по наведению - требует премиум API ключ"""
    # Проверяем доступ к функции анализа по наведению
    if not check_feature_access(request, "hover_analysis"):
        raise HTTPException(
            status_code=403, 
            detail="Hover analysis requires premium API key"
        )
    
    try:
        # Получаем данные из тела запроса
        body = await request.json()
        url = body.get("url")
        file_hash = body.get("file_hash")
        domain = body.get("domain")
        
        results = {}
        
        # Быстрый анализ URL если предоставлен
        if url:
            validation_error = security_validator.validate_url(url)
            if validation_error:
                results["url"] = {
                    "safe": None,
                    "details": f"Invalid URL: {validation_error}",
                    "source": "validation_error"
                }
            else:
                result = await analysis_service.analyze_url(url, use_external_apis=True)
                results["url"] = result
        
        # Быстрый анализ файла если предоставлен хэш
        if file_hash:
            validation_error = security_validator.validate_file_hash(file_hash)
            if validation_error:
                results["file"] = {
                    "safe": None,
                    "details": f"Invalid file hash: {validation_error}",
                    "source": "validation_error"
                }
            else:
                result = await analysis_service.analyze_file_hash(file_hash, use_external_apis=True)
                results["file"] = result
        
        # Быстрый анализ домена если предоставлен
        if domain:
            validation_error = security_validator.validate_domain(domain)
            if validation_error:
                results["domain"] = {
                    "safe": None,
                    "details": f"Invalid domain: {validation_error}",
                    "source": "validation_error"
                }
            else:
                threats = db_manager.check_domain(domain)
                results["domain"] = {
                    "safe": len(threats) == 0,
                    "threat_count": len(threats),
                    "threats": threats
                }
        
        if not results:
            raise HTTPException(status_code=400, detail="No valid input provided")
        
        return {
            "status": "success",
            "hover_analysis": True,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Hover analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Hover analysis error")

# Обработчики ошибок остаются без изменений...

# Обработчик для несуществующих маршрутов
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Обработчик 404 ошибок"""
    return JSONResponse(
        status_code=404,
        content={
            "detail": f"Маршрут не найден: {request.url.path}",
            "available_endpoints": [
                "GET /",
                "GET /health", 
                "POST /check/url",
                "POST /check/file",
                "POST /check/upload",
                "GET /check/domain/{domain}",
                "GET /check/ip/{ip_address}",
                "GET /admin/stats",
                "POST /admin/add/malicious-hash",
                "POST /admin/api-keys/create",
                "GET /docs",
                "GET /redoc"
            ]
        }
    )

# ===== PASSWORD RECOVERY ENDPOINTS =====

@app.post("/auth/forgot-password")
async def forgot_password(request: Request):
    """
    Запрос на восстановление пароля.
    Отправляет код восстановления на email.
    """
    try:
        body = await request.json()
        email = body.get("email", "").strip().lower()
        
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")
        
        # Генерируем код восстановления
        reset_code = db_manager.generate_reset_code(email)
        
    # ====== EMAIL SENDING ======
        from app.auth import AuthManager

        sent = AuthManager._send_email(
            to_email=email,
            subject="AVQON Password Reset Code",
            body=f"Ваш код восстановления пароля: {reset_code}"
        )

        if not sent:
            logger.error(f"FAILED TO SEND EMAIL TO {email}")
    # ===========================
        if not reset_code:
            # Не показываем, что email не найден (безопасность)
            return {
                "status": "success",
                "message": "Если email зарегистрирован, код отправлен"
            }
        
        # В реальном приложении здесь бы отправлялся email
        # Пока просто логируем код для тестирования
        logger.info(f"Password reset code for {email}: {reset_code}")
        
        return {
            "status": "success",
            "message": "Код восстановления отправлен на email",
            "debug_code": reset_code  # Только для разработки!
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
@app.post("/auth/reset-password")
async def reset_password(request: Request):
    """
    Сброс пароля с помощью кода восстановления.
    """
    try:
        body = await request.json()
        code = (body.get("token") or body.get("code", "")).strip()
        new_password = body.get("new_password", "").strip()
        
        if not code or not new_password:
            raise HTTPException(status_code=400, detail="Code and new_password are required")
        
        if len(new_password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
        # Проверяем код восстановления → получаем user_id
        user_id = db_manager.get_user_id_by_token(code)
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired code")
        
        # Хешируем пароль
        password_hash = auth_manager.hash_password(new_password)
        
        # Обновляем пароль
        if not db_manager.update_password(user_id, password_hash):
            raise HTTPException(status_code=500, detail="Failed to reset password")
        
        # Удаляем токен восстановления
        db_manager.delete_reset_tokens(user_id)
        
        return {
            "status": "success",
            "message": "Пароль успешно изменен"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
# ===== ACCOUNT AUTHENTICATION ENDPOINTS =====

@app.post("/auth/register")
async def register_account(request: RegisterRequest):
    """
    Регистрация нового аккаунта с выдачей JWT токенов.
    """
    success, user_id, error_msg, tokens = auth_manager.register(
        username=request.username,
        email=request.email,
        password=request.password
    )
    
    if not success:
        raise HTTPException(
            status_code=400,
            detail=error_msg or "Ошибка регистрации"
        )
    
    response = {
        "status": "success",
        "message": "Аккаунт успешно создан",
        "user_id": user_id,
        **tokens
    }
    
    return response

@app.post("/auth/login")
async def login_account(request: LoginRequest, http_request: Request):
    """
    Авторизация в существующем аккаунте с выдачей JWT токенов.
    
    Возвращает JWT access_token и refresh_token для stateless аутентификации.
    """
    success, account_data, tokens, error_msg = auth_manager.login(
        username=request.username,
        password=request.password
    )
    
    if not success:
        raise HTTPException(
            status_code=401,
            detail=error_msg or "Ошибка авторизации"
        )
    
    return {
        "status": "success",
        "message": "Успешная авторизация",
        "account": account_data,
        **tokens
    }

@app.post("/auth/refresh")
async def refresh_token(request: Request):
    """
    Обновление access token через refresh token.
    Возвращает новые access_token и refresh_token.
    """
    try:
        body = await request.json()
        refresh_token_str = body.get("refresh_token")
        
        if not refresh_token_str:
            raise HTTPException(
                status_code=400,
                detail="refresh_token is required"
            )
        
        # Обновляем токены через AuthManager
        tokens = auth_manager.refresh_access_token(refresh_token_str)
        
        if not tokens:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired refresh token"
            )
        
        return {
            "status": "success",
            "message": "Tokens refreshed successfully",
            **tokens
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Refresh token error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )

@app.post("/auth/validate-session")
async def validate_session(request: Request):
    """
    Проверка валидности JWT токена (deprecated endpoint name - используйте /auth/validate).
    Поддерживается для обратной совместимости.
    """
    # Используем JWT из request.state (установлен middleware)
    user_info = getattr(request.state, 'user_info', None)
    
    if not user_info:
        # Пробуем извлечь токен напрямую
        from app.jwt_auth import JWTAuth
        token = JWTAuth.get_token_from_request(request)
        if token:
            payload = JWTAuth.verify_token(token)
            if payload:
                user_id = payload.get("user_id") or payload.get("sub")
                return {
                    "status": "valid",
                    "valid": True,
                    "user_id": user_id
                }
        
            return {
                "status": "invalid",
                "valid": False
            }
        
        return {
            "status": "valid",
            "valid": True,
        "user_id": user_info.get("user_id")
        }

@app.get("/auth/me")
async def get_current_user(request: Request):
    """
    Получение информации о текущем пользователе из JWT токена.
    """
    # Получаем информацию о пользователе из JWT middleware
    user_info = getattr(request.state, 'user_info', None)
    
    if not user_info:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please provide a valid JWT token."
        )
    
    # Если есть user_id, получаем полную информацию из БД
    user_id = user_info.get("user_id")
    if user_id and db_manager:
        try:
            account = db_manager.get_account_by_id(user_id)
            if account:
                user_data = {
                    "id": account["id"],
                    "username": account["username"],
                    "email": account["email"],
                    "created_at": account["created_at"],
                    "last_login": account["last_login"]
                }
                return {
                    "status": "premium" if user_info.get("access_level") == "premium" else "basic",
                    "account": user_data,
                    "access_level": user_info.get("access_level", "basic"),
                    "features": user_info.get("features", [])
                }
        except Exception as e:
            logger.warning(f"Failed to get account from DB: {e}")
    
    # Возвращаем информацию из JWT токена
    return {
        "status": "premium" if user_info.get("access_level") == "premium" else "basic",
        "user_id": user_info.get("user_id"),
        "username": user_info.get("username"),
        "email": user_info.get("email"),
        "access_level": user_info.get("access_level", "basic"),
        "features": user_info.get("features", [])
    }

class BindApiKeyRequest(BaseModel):
    api_key: str

@app.post("/auth/bind-api-key")
async def bind_api_key(request: Request, bind_request: BindApiKeyRequest):
    """
    Привязывает API ключ к текущему аккаунту пользователя.
    Требует JWT токен в заголовке Authorization.
    """
    # Получаем информацию о пользователе из JWT middleware
    user_info = getattr(request.state, 'user_info', None)
    
    if not user_info:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please provide a valid JWT token."
        )
    
    user_id = user_info.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid user ID in token"
        )
    
    api_key = bind_request.api_key.strip()
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="API key is required"
        )
    
    if not db_manager:
        raise HTTPException(
            status_code=500,
            detail="Database unavailable"
        )
    
    # Привязываем ключ к аккаунту
    success = db_manager.bind_api_key_to_account(api_key, user_id)
    
    if not success:
        raise HTTPException(
            status_code=400,
            detail="Failed to bind API key. Key may not exist, already bound to another account, or invalid."
        )
    
    logger.info(f"API key {api_key[:10]}... bound to account {user_id}")
    
    return {
        "status": "success",
        "message": "API key successfully bound to account",
        "user_id": user_id
    }

@app.on_event("startup")
async def startup_event():
    """Инициализация при старте сервера"""
    logger.info("🚀 AVQON Server starting up...")
    
    # КРИТИЧНО: Проверяем что база данных инициализирована и таблицы созданы
    if db_manager:
        try:
            # Проверяем что таблицы существуют (PostgreSQL)
            with db_manager._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT table_name FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name IN ('cached_whitelist', 'cached_blacklist', 'accounts')
                """)
                rows = cursor.fetchall()
                tables = {row["table_name"] for row in rows}
                
                if len(tables) < 3:
                    logger.warning("⚠️ Some database tables missing. Tables should be created via init.sql")
                    logger.info(f"Found tables: {tables}")
                else:
                    logger.info("✅ Database tables verified")
        except Exception as e:
            logger.error(f"❌ Database verification failed: {e}", exc_info=True)
            logger.warning("⚠️ Service will continue with limited functionality (JWT auth will work)")
    else:
        logger.warning("⚠️ db_manager is None - service will run with limited functionality")
        logger.info("ℹ️ JWT authentication will work without database")
    
    # Проверяем подключение к базе
    if db_manager:
        try:
            conn = db_manager._get_connection()
            conn.close()
            logger.info("Database connection established successfully")
        except Exception as db_conn_error:
            logger.error(f"Database connection check failed: {db_conn_error}")
    
    # Сбрасываем лимиты при запуске
    if db_manager:
        try:
            db_manager.reset_rate_limits()
            logger.info("Rate limits reset")
        except Exception as reset_error:
            logger.warning(f"Failed to reset rate limits: {reset_error}")
    
    # Запускаем фоновый менеджер задач
    try:
        await background_job_manager.start()
        logger.info("Background job manager started")
    except Exception as bg_error:
        logger.error(f"Failed to start background job manager: {bg_error}")

    # Запускаем WebSocket cleanup task
    try:
        if not hasattr(app.state, 'ws_cleanup_task') or not app.state.ws_cleanup_task:
            app.state.ws_cleanup_task = asyncio.create_task(websocket_cleanup_task())
            logger.info("WebSocket cleanup task started")
    except Exception as ws_error:
        logger.error(f"Failed to start WebSocket cleanup task: {ws_error}", exc_info=True)
    
    # КРИТИЧНО: Проверяем что WebSocket endpoint зарегистрирован
    ws_routes = [r for r in app.routes if hasattr(r, 'path') and r.path == '/ws']
    if ws_routes:
        logger.info(f"✅ WebSocket endpoint /ws registered: {ws_routes[0]}")
    else:
        logger.error("❌ CRITICAL: WebSocket endpoint /ws NOT FOUND in registered routes!")
        logger.error(f"Available routes: {[r.path for r in app.routes if hasattr(r, 'path')][:20]}")
    
    # Проверка конфигурации ЮКассы
    try:
        from app.routes.payments import YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY
        shop_id_status = "SET" if YOOKASSA_SHOP_ID else "MISSING"
        secret_key_status = "SET" if YOOKASSA_SECRET_KEY else "MISSING"
        logger.info(f"💳 YooKassa config check: SHOP_ID={shop_id_status}, SECRET_KEY={secret_key_status}")
        if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
            logger.warning("⚠️ YooKassa credentials not configured! Payments will fail.")
            logger.warning("   Set YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY in app/env.env")
        else:
            logger.info(f"✅ YooKassa configured: SHOP_ID={YOOKASSA_SHOP_ID[:5]}...")
    except Exception as yk_check_error:
        logger.error(f"❌ Failed to check YooKassa config: {yk_check_error}")
    
    # === YooKassa aiohttp session init (CRITICAL) ===
    try:
        from app.routes.payments import YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY

        if YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY:
            app.state.yookassa_session = aiohttp.ClientSession(
                auth=BasicAuth(YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY),
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.info("✅ YooKassa aiohttp session initialized")
        else:
            app.state.yookassa_session = None
            logger.warning("⚠️ YooKassa aiohttp session NOT initialized (missing credentials)")
    except Exception as e:
        app.state.yookassa_session = None
        logger.error(f"❌ Failed to initialize YooKassa session: {e}", exc_info=True)
    
    logger.info("✅ AVQON Server startup complete")

@app.on_event("shutdown")
async def shutdown_event():
    """Остановка приложения."""
    try:
        await background_job_manager.stop()
        logger.info("Background job manager stopped")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

    cleanup_task = getattr(app.state, "ws_cleanup_task", None)
    if cleanup_task:
        cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            try:
                await cleanup_task
            except Exception as e:
                logger.error(f"WebSocket cleanup task stop error: {e}", exc_info=True)
        app.state.ws_cleanup_task = None

    try:
        await ws_manager.close_all()
    except Exception as exc:
        logger.error(f"Error closing WebSocket clients: {exc}", exc_info=True)

    # 🔥 ЗАКРЫВАЕМ YooKassa session В КОНЦЕ
    session = getattr(app.state, "yookassa_session", None)
    if session and not session.closed:
        await session.close()
        logger.info("🛑 YooKassa aiohttp session closed")
