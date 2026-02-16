"""
Простая панель модерации крауд‑агрегатов.
"""
from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import quote
import logging

from app.core.dependencies import RequireModerator, RequireViewer, get_db_repository
from app.db.repositories import AdminRepository

router = APIRouter(prefix="/crowd", tags=["Crowd"])
templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger(__name__)


@router.get("", response_class=HTMLResponse)
async def crowd_page(
    request: Request,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository),
    domain: str = Query("", alias="domain"),
    date_from: str = Query("", alias="date_from"),
    date_to: str = Query("", alias="date_to"),
):
    """
    Страница с агрегированной сводкой по крауд‑репортам. Фильтры: domain, date_from, date_to.
    """
    summary = repository.get_crowd_summary(
        limit=200,
        domain_substring=domain.strip() or None,
        date_from=date_from.strip() or None,
        date_to=date_to.strip() or None,
    )
    items = summary.get("items", [])
    return templates.TemplateResponse(
        "crowd.html",
        {
            "request": request,
            "items": items,
            "count": summary.get("count", len(items)),
            "user": current_user,
            "filter_domain": domain,
            "filter_date_from": date_from,
            "filter_date_to": date_to,
        },
    )


@router.get("/reports/{domain}", response_class=HTMLResponse)
async def crowd_reports_by_domain(
    request: Request,
    domain: str,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository),
):
    """Просмотр отдельных репортов по домену."""
    reports = repository.get_crowd_reports_by_domain(domain=domain, limit=200)
    return templates.TemplateResponse(
        "crowd_reports.html",
        {
            "request": request,
            "domain": domain,
            "reports": reports,
            "user": current_user,
        },
    )


@router.post("/confirm-threat")
async def confirm_crowd_as_threat(
    request: Request,
    domain: str = Form(""),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository),
):
    """Подтвердить домен как угрозу: добавить в malicious_urls и очистить крауд‑данные."""
    domain = (domain or "").strip()
    if not domain:
        redirect = RedirectResponse(url="/crowd", status_code=303)
        redirect.set_cookie("flash", quote("Укажите домен"), max_age=10)
        return redirect
    ok = repository.confirm_crowd_as_threat(domain=domain)
    msg = f"Домен {domain} добавлен в список угроз, крауд‑данные очищены" if ok else f"Ошибка при подтверждении {domain}"
    redirect = RedirectResponse(url="/crowd", status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect


@router.post("/clear")
async def clear_crowd_action(
    request: Request,
    domain: str = Form(""),
    mode: str = Form("domain"),
    current_user: dict = Depends(RequireModerator),
    repository: AdminRepository = Depends(get_db_repository),
):
    """
    Очищает крауд‑данные:
    - по конкретному домену (mode=domain),
    - или все целиком (mode=all).
    """
    try:
        if mode == "all":
            ok = repository.clear_all_crowd()
            msg = "Все крауд‑репорты очищены" if ok else "Не удалось очистить крауд‑репорты"
        else:
            ok = repository.clear_crowd_for_domain(domain)
            msg = (
                f"Крауд‑репорты для {domain} очищены"
                if ok
                else f"Не удалось очистить крауд‑репорты для {domain}"
            )
    except Exception as e:
        logger.error(f"Crowd clear error: {e}")
        msg = f"Ошибка очистки: {str(e)}"

    redirect = RedirectResponse(url="/crowd", status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect

