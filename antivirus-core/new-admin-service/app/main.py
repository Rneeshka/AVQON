"""
Главный файл FastAPI приложения для админ-сервиса
"""
import os
import sys
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.api import auth, dashboard, keys, threats, cache, logs, ip, danger

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Управление жизненным циклом приложения
    """
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Host: {settings.HOST}:{settings.PORT}")
    if settings.DATABASE_URL:
        logger.info(f"Database: {settings.DATABASE_URL[:30]}...")
    else:
        logger.warning("DATABASE_URL not set - database features will be unavailable")
    logger.info(f"Allowed origins: {', '.join(settings.ALLOWED_ORIGINS)}")
    
    yield
    
    logger.info(f"Shutting down {settings.APP_NAME}")


# Создаем приложение
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# Инициализация шаблонов
templates = Jinja2Templates(directory="app/templates")

# Добавляем фильтры для Jinja2
from urllib.parse import unquote
templates.env.filters["urldecode"] = lambda u: unquote(u) if u else ""

# Подключаем статические файлы
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip middleware
app.add_middleware(GZipMiddleware, minimum_size=500)

# Rate limiting middleware
from app.core.middleware import RateLimitMiddleware, LoggingMiddleware
app.add_middleware(
    RateLimitMiddleware,
    requests_per_second=settings.RATE_LIMIT_PER_SECOND
)

# Logging middleware
app.add_middleware(LoggingMiddleware)

# Подключаем роутеры (auth должен быть первым)
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(keys.router)
app.include_router(threats.router)
app.include_router(cache.router)
app.include_router(logs.router)
app.include_router(ip.router)
app.include_router(danger.router)


@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT
    }


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """
    Обработчик 404 ошибок
    """
    if request.url.path.startswith("/api/"):
        return {"detail": "Not found"}
    return templates.TemplateResponse(
        "404.html",
        {"request": request},
        status_code=404
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )

