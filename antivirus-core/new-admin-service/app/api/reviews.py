"""
Роутер для просмотра отзывов
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.core.dependencies import RequireViewer, get_db_repository
from app.db.repositories import AdminRepository

router = APIRouter(prefix="/reviews", tags=["Reviews"])

templates = Jinja2Templates(directory="app/templates")


@router.get("", response_class=HTMLResponse)
async def reviews_page(
    request: Request,
    current_user: dict = Depends(RequireViewer),
    repository: AdminRepository = Depends(get_db_repository)
):
    """
    Страница просмотра отзывов
    """
    reviews = repository.get_all_reviews(limit=500)
    stats = repository.get_review_stats()
    
    # Вычисляем проценты для каждого рейтинга заранее
    rating_percentages = {}
    total = stats.get('total', 1) or 1
    rating_dist = stats.get('rating_distribution', {})
    for rating in range(1, 6):
        rating_str = str(rating)
        count = rating_dist.get(rating_str, 0) or 0
        percentage = (count / total * 100) if total > 0 else 0
        rating_percentages[rating] = round(percentage, 1)
    
    return templates.TemplateResponse(
        "reviews.html",
        {
            "request": request,
            "reviews": reviews,
            "stats": stats,
            "rating_percentages": rating_percentages,
            "user": current_user
        }
    )

