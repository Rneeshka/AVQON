# app/security.py
from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Any
from app.database import db_manager
from app.logger import logger

class RateLimiter:
    def __init__(self):
        self._cache = {}
    
    def is_rate_limited(self, api_key: str, endpoint: str) -> bool:
        try:
            # Простой лимит: не более N запросов в минуту на ключ
            # N вычисляем из почасового лимита ключа, если доступен
            from time import time
            from app.database import db_manager
            minute_window_seconds = 60
            key = f"{api_key}:{endpoint}"
            now = int(time())
            window_start = now - minute_window_seconds
            # Получаем лимит из БД
            key_info = db_manager.get_api_key_info(api_key)
            per_minute_limit =  max(10, int((key_info.get('rate_limit_hourly', 100) or 100) / 60)) if key_info else 60
            # Очистка старых отметок
            timestamps = [t for t in self._cache.get(key, []) if t >= window_start]
            if len(timestamps) >= per_minute_limit:
                self._cache[key] = timestamps
                return True
            timestamps.append(now)
            self._cache[key] = timestamps
            return False
        except Exception:
            return False

class APIKeyAuth(HTTPBearer):
    def __init__(self, rate_limiter: RateLimiter):
        super().__init__(auto_error=False)
        self.rate_limiter = rate_limiter
    
    async def __call__(self, request: Request) -> Dict[str, Any]:
        # 1) Пытаемся извлечь Bearer токен
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        api_key = None
        if credentials and credentials.scheme == "Bearer" and credentials.credentials:
            api_key = credentials.credentials
        else:
            # 2) Фолбэк на X-API-Key
            api_key = request.headers.get("X-API-Key")
            if not api_key:
                raise HTTPException(status_code=401, detail="API key required. Use X-API-Key or Authorization: Bearer.")
        
        # Проверяем rate limiting
        if self.rate_limiter.is_rate_limited(api_key, request.url.path):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Проверяем валидность ключа
        is_valid, message = db_manager.validate_api_key(api_key)
        if not is_valid:
            raise HTTPException(status_code=401, detail=message)
        
        # Получаем информацию о ключе
        key_info = db_manager.get_api_key_info(api_key)
        if not key_info:
            raise HTTPException(status_code=401, detail="API key not found")
        
        return key_info

# Инициализация
rate_limiter = RateLimiter()
api_key_auth = APIKeyAuth(rate_limiter)