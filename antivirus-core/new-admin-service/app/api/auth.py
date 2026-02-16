"""
Роутер для аутентификации
"""
from fastapi import APIRouter, Depends, HTTPException, status, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
from datetime import timedelta

from app.core.config import settings
from app.core.security import verify_password, create_access_token, hash_password
from app.core.dependencies import get_db_repository
from app.db.repositories import AdminRepository

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
templates = Jinja2Templates(directory="app/templates")


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


# Простая таблица пользователей в памяти (в продакшене использовать БД)
# Для первой версии используем хардкод, потом можно добавить таблицу admin_users
ADMIN_USERS = {
    settings.ADMIN_DEFAULT_USER: {
        "password_hash": hash_password(settings.ADMIN_DEFAULT_PASSWORD) if not settings.ADMIN_PASSWORD_HASH else settings.ADMIN_PASSWORD_HASH,
        "role": "admin"
    }
}


@router.get("/login-page", response_class=HTMLResponse)
async def login_page(request: Request):
    """
    Страница входа
    """
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None}
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Вход в систему (HTML форма)
    """
    # Проверяем пользователя
    user = ADMIN_USERS.get(username)
    
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверное имя пользователя или пароль"},
            status_code=401
        )
    
    # Создаем токен
    access_token = create_access_token(
        data={
            "sub": username,
            "username": username,
            "role": user["role"]
        },
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    # Редирект на главную страницу с установкой cookie
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="admin_token",
        value=access_token,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=settings.ENVIRONMENT == "prod",
        samesite="lax"
    )
    
    return response


@router.post("/login-json", response_model=LoginResponse)
async def login_json(
    request: LoginRequest,
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Вход в систему (JSON)
    """
    user = ADMIN_USERS.get(request.username)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    if not verify_password(request.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    access_token = create_access_token(
        data={
            "sub": request.username,
            "username": request.username,
            "role": user["role"]
        },
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return LoginResponse(
        access_token=access_token,
        role=user["role"],
        username=request.username
    )


@router.get("/logout")
async def logout(request: Request):
    """
    Выход из системы
    """
    response = RedirectResponse(url="/api/auth/login-page", status_code=303)
    response.delete_cookie("admin_token")
    return response


@router.get("/me")
async def get_current_user_info(
    current_user: dict = Depends(lambda: None)  # Будет заменено на реальную зависимость
):
    """
    Получает информацию о текущем пользователе
    """
    # TODO: Реализовать через get_current_user dependency
    return {"username": "admin", "role": "admin"}

