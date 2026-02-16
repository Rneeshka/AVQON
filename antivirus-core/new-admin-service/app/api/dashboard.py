"""
Роутер для дашборда
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, Any

from app.core.dependencies import get_db_repository, RequireViewer
from app.db.repositories import AdminRepository
from app.services.admin_service import AdminService

router = APIRouter(prefix="", tags=["Dashboard"])

# Инициализация шаблонов
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Главная страница дашборда
    """
    service = AdminService(repository)
    stats = service.get_dashboard_stats()
    
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "stats": stats,
            "user": current_user
        }
    )


@router.get("/api/dashboard/chart-data", response_class=JSONResponse)
async def get_chart_data(
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    API endpoint для получения данных графиков
    """
    service = AdminService(repository)
    chart_data = service.get_chart_data()
    
    # Добавляем данные о кэше
    cache_stats = repository.get_cache_stats()
    chart_data["cache_ratio"] = {
        "hits": cache_stats.get("whitelist_hits", 0) + cache_stats.get("blacklist_hits", 0),
        "entries": cache_stats.get("whitelist_entries", 0) + cache_stats.get("blacklist_entries", 0)
    }
    
    return chart_data

