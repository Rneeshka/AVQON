"""
Роутер для дашборда
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
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

