"""
Роутер для просмотра логов
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.core.dependencies import RequireViewer, get_db_repository
from app.db.repositories import AdminRepository

router = APIRouter(prefix="/logs", tags=["Logs"])

templates = Jinja2Templates(directory="app/templates")


@router.get("", response_class=HTMLResponse)
async def logs_page(
    request: Request,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Страница просмотра логов
    """
    logs = repository.get_all_logs(limit=200)
    
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "logs": logs,
            "user": current_user
        }
    )

