"""
Роутер для управления угрозами
"""
from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from urllib.parse import quote
import logging

from app.core.dependencies import RequireViewer, RequireModerator, get_db_repository
from app.db.repositories import AdminRepository
from app.services.admin_service import AdminService

router = APIRouter(prefix="/threats", tags=["Threats"])

templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger(__name__)


@router.get("", response_class=HTMLResponse)
async def threats_page(
    request: Request,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Страница управления угрозами
    """
    service = AdminService(repository)
    threats_by_type = service.get_threats_by_type()
    
    return templates.TemplateResponse(
        "threats.html",
        {
            "request": request,
            "threats_by_type": threats_by_type,
            "user": current_user
        }
    )


@router.post("/add")
async def add_threat_action(
    request: Request,
    type: str = Form(...),
    value: str = Form(...),
    threat_level: str = Form("suspicious"),
    source: str = Form("manual"),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Добавляет угрозу
    """
    try:
        if type == "url":
            threat_type = "malware" if threat_level == "malicious" else "phishing"
            severity = "high" if threat_level == "malicious" else "medium"
            success = repository.add_malicious_url(
                value,
                threat_type,
                f"Manual addition: {threat_level}",
                severity
            )
        elif type == "hash":
            threat_type = "malware" if threat_level == "malicious" else "trojan"
            severity = "high" if threat_level == "malicious" else "medium"
            success = repository.add_malicious_hash(
                value,
                threat_type,
                f"Manual addition: {threat_level}",
                severity
            )
        else:
            success = False
    except Exception as e:
        logger.error(f"Add threat error: {e}")
        success = False
    
    redirect = RedirectResponse(url="/threats", status_code=303)
    msg = quote("Угроза добавлена" if success else "Ошибка добавления угрозы")
    redirect.set_cookie("flash", msg, max_age=10)
    return redirect


@router.get("/search", response_class=HTMLResponse)
async def search_urls_page(
    request: Request,
    q: str = Query("", description="Поисковый запрос"),
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Страница поиска URL
    """
    results = {"malicious_urls": [], "cached_blacklist": [], "cached_whitelist": []}
    
    if q:
        try:
            results = repository.search_urls_in_database(q, limit=50)
        except Exception as e:
            logger.error(f"Search URLs error: {e}")
    
    return templates.TemplateResponse(
        "threats_search.html",
        {
            "request": request,
            "query": q,
            "results": results,
            "user": current_user
        }
    )


@router.post("/remove")
async def remove_url_action(
    request: Request,
    url: str = Form(...),
    type: str = Form(...),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Удаляет URL
    """
    try:
        if type == "malicious":
            success = repository.remove_malicious_url(url)
            msg = f"URL удален из malicious_urls" if success else "URL не найден в malicious_urls"
        elif type == "blacklist":
            success = repository.remove_cached_blacklist_url(url)
            msg = f"URL удален из blacklist кэша" if success else "URL не найден в blacklist кэша"
        elif type == "all":
            success = repository.mark_url_as_safe(url)
            msg = f"URL помечен как безопасный" if success else "URL не найден"
        else:
            msg = "Неверный тип"
            success = False
    except Exception as e:
        logger.error(f"Remove URL error: {e}")
        msg = f"Ошибка удаления: {str(e)}"
        success = False
    
    redirect = RedirectResponse(url=f"/threats/search?q={quote(url)}", status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect


@router.post("/recheck")
async def recheck_url_action(
    request: Request,
    url: str = Form(...),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Перепроверяет URL
    """
    service = AdminService(repository)
    result = await service.recheck_url(url)
    
    redirect = RedirectResponse(url=f"/threats/search?q={quote(url)}", status_code=303)
    redirect.set_cookie("flash", quote(result.get("message", "Ошибка")), max_age=10)
    return redirect


@router.post("/clear")
async def clear_threats_action(
    request: Request,
    target: str = Form(...),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Очищает угрозы
    """
    try:
        if target == "urls":
            count = repository.clear_malicious_urls()
            msg = f"Очищено {count} вредоносных URL"
        elif target == "hashes":
            count = repository.clear_malicious_hashes()
            msg = f"Очищено {count} вредоносных хэшей"
        elif target == "all_urls":
            result = repository.clear_all_url_data()
            msg = f"Очищено: {result['malicious_urls']} URL, {result['cached_whitelist']} whitelist, {result['cached_blacklist']} blacklist"
        elif target == "all":
            url_count = repository.clear_malicious_urls()
            hash_count = repository.clear_malicious_hashes()
            msg = f"Очищено {url_count} URL и {hash_count} хэшей"
        else:
            msg = "Неверный параметр"
    except Exception as e:
        logger.error(f"Clear threats error: {e}")
        msg = f"Ошибка очистки: {str(e)}"
    
    redirect = RedirectResponse(url="/threats", status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect

