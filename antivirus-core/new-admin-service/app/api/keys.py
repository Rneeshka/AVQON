"""
Роутер для управления API ключами
"""
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from urllib.parse import quote
from datetime import datetime, timezone

from app.core.dependencies import RequireModerator, get_db_repository
from app.db.repositories import AdminRepository

router = APIRouter(prefix="/keys", tags=["API Keys"])

templates = Jinja2Templates(directory="app/templates")


def format_time_remaining(expires_at_str):
    """Форматирует оставшееся время до истечения"""
    if not expires_at_str:
        return "Бессрочно"
    try:
        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        
        delta = expires_at - now
        if delta.total_seconds() < 0:
            return "Истёк"
        
        days = delta.days
        hours = delta.seconds // 3600
        
        if days > 0:
            return f"{days}д {hours}ч"
        elif hours > 0:
            return f"{hours}ч"
        else:
            minutes = delta.seconds // 60
            return f"{minutes}м" if minutes > 0 else "Скоро истечёт"
    except:
        return "Неизвестно"


@router.get("", response_class=HTMLResponse)
async def keys_page(
    request: Request,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Страница управления API ключами
    """
    keys = repository.get_api_keys(limit=200)
    
    return templates.TemplateResponse(
        "keys.html",
        {
            "request": request,
            "keys": keys,
            "user": current_user,
            "format_time_remaining": format_time_remaining
        }
    )


@router.post("/create")
async def create_key_action(
    request: Request,
    name: str = Form(...),
    description: Optional[str] = Form(None),
    access_level: str = Form("premium"),
    daily_limit: int = Form(10000),
    hourly_limit: int = Form(10000),
    expires_days: int = Form(30),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Создает новый API ключ
    """
    api_key = repository.create_api_key(
        name=name,
        description=description or "",
        access_level=access_level,
        daily_limit=daily_limit,
        hourly_limit=hourly_limit,
        expires_days=expires_days
    )
    
    redirect = RedirectResponse(url="/keys", status_code=303)
    if api_key:
        safe_msg = quote(f"Создан {access_level} ключ: {api_key}")
        redirect.set_cookie("flash", safe_msg, max_age=10)
    else:
        safe_msg = quote("Не удалось создать ключ")
        redirect.set_cookie("flash", safe_msg, max_age=10)
    
    return redirect


@router.post("/extend")
async def extend_key_action(
    request: Request,
    api_key: str = Form(...),
    extend_days: int = Form(...),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Продлевает API ключ
    """
    ok = repository.extend_api_key(api_key, extend_days)
    
    redirect = RedirectResponse(url="/keys", status_code=303)
    msg = quote("Ключ продлён" if ok else "Ключ не найден или ошибка продления")
    redirect.set_cookie("flash", msg, max_age=10)
    
    return redirect

