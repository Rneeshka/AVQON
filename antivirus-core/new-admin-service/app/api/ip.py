"""
Роутер для IP репутации
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.core.dependencies import RequireViewer, get_db_repository
from app.db.repositories import AdminRepository

router = APIRouter(prefix="/ip", tags=["IP Reputation"])

templates = Jinja2Templates(directory="app/templates")


@router.get("", response_class=HTMLResponse)
async def ip_page(
    request: Request,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Страница IP репутации
    """
    rows = repository.list_ip_reputation(200)
    
    return templates.TemplateResponse(
        "ip.html",
        {
            "request": request,
            "ip_reputations": rows,
            "user": current_user
        }
    )

