"""
Роутер для опасной зоны
"""
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import quote
import logging

import os
from app.core.config import settings
from app.core.dependencies import RequireAdmin, get_db_repository
from app.db.repositories import AdminRepository

router = APIRouter(prefix="/danger", tags=["Danger Zone"])

templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger(__name__)


@router.get("", response_class=HTMLResponse)
async def danger_zone_page(
    request: Request,
    current_user: dict = Depends(RequireAdmin),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Страница опасной зоны
    """
    return templates.TemplateResponse(
        "danger.html",
        {
            "request": request,
            "user": current_user
        }
    )


@router.post("/clear-all")
async def clear_all_database_action(
    request: Request,
    password: str = Form(...),
    confirm: str = Form(None),
    current_user: dict = Depends(RequireAdmin),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Полная очистка базы данных
    """
    # Пароль для защиты (из переменных окружения)
    ADMIN_PASSWORD = os.getenv("ADMIN_DANGER_ZONE_PASSWORD", "90~kz=Ut!I123nikita12364")
    
    if password != ADMIN_PASSWORD:
        redirect = RedirectResponse(url="/danger", status_code=303)
        redirect.set_cookie("flash", quote("❌ Неверный пароль!"), max_age=10)
        return redirect
    
    if not confirm:
        redirect = RedirectResponse(url="/danger", status_code=303)
        redirect.set_cookie("flash", quote("❌ Необходимо подтвердить операцию!"), max_age=10)
        return redirect
    
    try:
        # Очищаем in-memory кэш сервиса анализа
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "app"))
            from services import analysis_service
            analysis_service.clear_cache()
        except Exception as e:
            logger.warning(f"Failed to clear in-memory cache: {e}")
        
        results = repository.clear_all_database_data()
        total_deleted = sum([v for k, v in results.items() if k not in ['cache_whitelist.jsonl', 'cache_blacklist.jsonl']])
        files_deleted = sum([1 for k in ['cache_whitelist.jsonl', 'cache_blacklist.jsonl'] if results.get(k, 0) > 0])
        
        msg = f"✅ База данных полностью очищена! Удалено записей: {total_deleted}, файлов: {files_deleted}, кэш: {results.get('cache.db', 0)}"
        logger.warning(f"FULL DATABASE CLEAR executed by admin - {total_deleted} records, {files_deleted} files, {results.get('cache.db', 0)} cache entries deleted")
    except Exception as e:
        logger.error(f"Clear all database error: {e}")
        msg = f"❌ Ошибка очистки: {str(e)}"
    
    redirect = RedirectResponse(url="/", status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect

