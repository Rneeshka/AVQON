"""
Middleware для админ-сервиса
"""
import time
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from collections import defaultdict
from datetime import datetime, timedelta

from app.core.config import settings

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware для ограничения частоты запросов
    """
    
    def __init__(self, app, requests_per_second: int = 10):
        super().__init__(app)
        self.requests_per_second = requests_per_second
        self.requests = defaultdict(list)
        self.window_seconds = 1
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Пропускаем health check и статические файлы
        if request.url.path in ["/health", "/api/auth/login-page"] or request.url.path.startswith("/static/"):
            return await call_next(request)
        
        # Получаем IP клиента
        client_ip = request.client.host if request.client else "unknown"
        
        # Проверяем rate limit
        now = time.time()
        window_start = now - self.window_seconds
        
        # Очищаем старые запросы
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip]
            if req_time > window_start
        ]
        
        # Проверяем лимит
        if len(self.requests[client_ip]) >= self.requests_per_second:
            logger.warning(f"Rate limit exceeded for {client_ip} on {request.url.path}")
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."}
            )
        
        # Добавляем текущий запрос
        self.requests[client_ip].append(now)
        
        return await call_next(request)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware для логирования запросов
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        # Логируем запрос
        client_ip = request.client.host if request.client else "unknown"
        logger.info(f"Request: {request.method} {request.url.path} from {client_ip}")
        
        try:
            response = await call_next(request)
            
            # Вычисляем время обработки
            process_time = time.time() - start_time
            
            # Логируем ответ
            logger.info(
                f"Response: {request.method} {request.url.path} "
                f"status={response.status_code} "
                f"time={process_time:.3f}s"
            )
            
            # Добавляем заголовок с временем обработки
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(
                f"Error: {request.method} {request.url.path} "
                f"error={str(e)} "
                f"time={process_time:.3f}s",
                exc_info=True
            )
            raise

