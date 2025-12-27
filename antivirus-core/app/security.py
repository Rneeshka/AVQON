# app/security.py
"""
JWT аутентификация для FastAPI - заменяет старый APIKeyAuth
"""
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Any, Optional
from app.jwt_auth import JWTAuth
from app.logger import logger

class RateLimiter:
    """Rate limiter для JWT токенов (опционально)"""
    def __init__(self): 
        self._cache = {}
    
    def is_rate_limited(self, user_id: int, endpoint: str) -> bool:
        """
        Проверяет rate limit для пользователя.
        В будущем можно интегрировать с БД для персистентных лимитов.
        """
        try:
            from time import time
            minute_window_seconds = 60
            key = f"{user_id}:{endpoint}"
            now = int(time())
            window_start = now - minute_window_seconds
            
            # Простой лимит: 100 запросов в минуту на пользователя
            per_minute_limit = 100
            
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

class JWTAuthDependency(HTTPBearer):
    """
    FastAPI dependency для JWT аутентификации.
    Заменяет старый APIKeyAuth.
    """
    def __init__(self, rate_limiter: Optional[RateLimiter] = None):
        super().__init__(auto_error=False)
        self.rate_limiter = rate_limiter
    
    async def __call__(self, request: Request) -> Dict[str, Any]:
        """
        Извлекает и верифицирует JWT токен из запроса.
        Stateless - без запросов к БД.
        """
        # Публичные пути - пропускаем без проверки JWT
        PUBLIC_PATHS = {
            "/auth/forgot-password",
            "/auth/reset-password",
            "/auth/login",
            "/auth/register",
            "/auth/refresh",
            "/health",
            "/health/minimal",
            "/health/hover",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/",
        }

        if request.url.path in PUBLIC_PATHS:
            return {}  # пропускаем без JWT токена
        
        # Извлекаем Bearer токен
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        
        if not credentials or credentials.scheme != "Bearer" or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="JWT token required. Use Authorization: Bearer <token>",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        token = credentials.credentials
        
        # Верифицируем JWT токен (stateless - без БД)
        payload = JWTAuth.verify_token(token, token_type="access")
        
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        user_id = payload.get("user_id") or payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing user_id",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Проверяем rate limiting (опционально)
        if self.rate_limiter and self.rate_limiter.is_rate_limited(user_id, request.url.path):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        # Возвращаем информацию о пользователе из токена
        return {
            "user_id": user_id,
            "username": payload.get("username"),
            "email": payload.get("email"),
            "access_level": payload.get("access_level", "basic"),
            "features": payload.get("features", []),
            "token_payload": payload
        }

# Инициализация
rate_limiter = RateLimiter()
jwt_auth = JWTAuthDependency(rate_limiter)
