"""
Роутер для управления кэшем
"""
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import quote
import logging

from app.core.dependencies import RequireViewer, RequireModerator, get_db_repository
from app.db.repositories import AdminRepository
from app.services.admin_service import AdminService

router = APIRouter(prefix="/cache", tags=["Cache"])

templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger(__name__)


@router.get("", response_class=HTMLResponse)
async def cache_page(
    request: Request,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Страница управления кэшем
    """
    whitelist_entries = repository.get_all_cached_whitelist(limit=500)
    blacklist_entries = repository.get_all_cached_blacklist(limit=500)
    
    return templates.TemplateResponse(
        "cache.html",
        {
            "request": request,
            "whitelist_entries": whitelist_entries,
            "blacklist_entries": blacklist_entries,
            "user": current_user
        }
    )


@router.post("/refresh")
async def refresh_cache_action(
    request: Request,
    target: str = Form("all"),
    limit: int = Form(10),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Обновляет кэш
    """
    service = AdminService(repository)
    summary = await service.refresh_cache_entries(target, int(limit))
    
    redirect = RedirectResponse(url="/", status_code=303)
    msg = quote(
        f"Обновлено: {summary['processed']}, "
        f"white: {summary['whitelist']}, "
        f"black: {summary['blacklist']}, "
        f"ошибок: {summary['errors']}"
    )
    redirect.set_cookie("flash", msg, max_age=10)
    return redirect


@router.post("/clear")
async def clear_cache_action(
    request: Request,
    target: str = Form(...),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Очищает кэш
    """
    try:
        if target == "whitelist":
            count = repository.clear_cached_whitelist()
            msg = f"Очищено {count} записей из whitelist"
        elif target == "blacklist":
            count = repository.clear_cached_blacklist()
            msg = f"Очищено {count} записей из blacklist"
        elif target == "all":
            whitelist_count = repository.clear_cached_whitelist()
            blacklist_count = repository.clear_cached_blacklist()
            msg = f"Очищено {whitelist_count} whitelist и {blacklist_count} blacklist записей"
        else:
            msg = "Неверный параметр"
    except Exception as e:
        logger.error(f"Clear cache error: {e}")
        msg = f"Ошибка очистки: {str(e)}"
    
    redirect = RedirectResponse(url="/cache", status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect

