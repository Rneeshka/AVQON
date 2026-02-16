"""
Зависимости для FastAPI
"""
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
import jwt
from app.core.config import settings
from app.core.security import decode_token

# Временно отключаем зависимость от репозитория, чтобы избежать циклических импортов
# from app.db.repositories import AdminRepository


security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    """
    Получает текущего пользователя из JWT токена (из заголовка или cookie)
    """
    token = None
    
    # Сначала пытаемся получить из заголовка Authorization
    if credentials:
        token = credentials.credentials
    else:
        # Если нет в заголовке, пытаемся получить из cookie
        token = request.cookies.get("admin_token")
    
    if not token:
        # Для HTML страниц перенаправляем на страницу входа
        if request.url.path.startswith("/api/"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization required",
            )
        else:
            # Для HTML страниц - редирект на логин
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/api/auth/login-page"}
            )
    
    try:
        payload = decode_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        
        user_id: Optional[str] = payload.get("sub")
        role: Optional[str] = payload.get("role", "viewer")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        
        return {
            "user_id": user_id,
            "role": role,
            "username": payload.get("username", "unknown")
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


def require_role(allowed_roles: list):
    """
    Декоратор для проверки роли пользователя
    """
    async def role_checker(request: Request, current_user: dict = Depends(get_current_user)) -> dict:
        if current_user["role"] not in allowed_roles:
            if request.url.path.startswith("/api/"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied. Required roles: {', '.join(allowed_roles)}"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                    headers={"Location": "/api/auth/login-page"}
                )
        return current_user
    return role_checker


# Зависимости для разных ролей (используются как Depends(RequireAdmin))
def RequireAdmin():
    return require_role(["admin"])

def RequireModerator():
    return require_role(["admin", "moderator"])

def RequireViewer():
    return require_role(["admin", "moderator", "viewer"])


async def get_db_repository():
    """
    Получает репозиторий для работы с БД
    """
    from app.db.repositories import AdminRepository
    return AdminRepository()

