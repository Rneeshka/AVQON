"""Главный файл бота"""
import asyncio
import logging
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

from config import BOT_TOKEN

# Импортируем yookassa_client для инициализации конфигурации ЮKassa ДО всех платежей
try:
    from yookassa_client import YOOKASSA_AVAILABLE
    if YOOKASSA_AVAILABLE:
        logger = logging.getLogger(__name__)
        logger.info("ЮKassa конфигурация инициализирована при запуске бота")
except Exception as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Не удалось инициализировать ЮKassa при запуске: {e}")

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Импортируем yookassa_client для инициализации конфигурации ЮKassa ДО всех платежей
try:
    from yookassa_client import YOOKASSA_AVAILABLE
    if YOOKASSA_AVAILABLE:
        logger.info("ЮKassa конфигурация инициализирована при запуске бота")
    else:
        logger.warning("ЮKassa недоступна при запуске бота")
except Exception as e:
    logger.warning(f"Не удалось инициализировать ЮKassa при запуске: {e}")

# Безопасный импорт обработчиков
try:
    from handlers import common, purchase, info, admin
except Exception as e:
    logger.error(f"Ошибка при импорте обработчиков: {e}", exc_info=True)
    raise


async def main():
    """Главная функция запуска бота"""
    # Создаем бота и диспетчер
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    dp = Dispatcher()
    
    # Регистрируем роутеры
    try:
        dp.include_router(common.router)
        logger.info("Роутер common зарегистрирован")
    except Exception as e:
        logger.error(f"Ошибка при регистрации роутера common: {e}", exc_info=True)
    
    try:
        dp.include_router(purchase.router)
        logger.info("Роутер purchase зарегистрирован")
    except Exception as e:
        logger.error(f"Ошибка при регистрации роутера purchase: {e}", exc_info=True)
    
    try:
        dp.include_router(info.router)
        logger.info("Роутер info зарегистрирован")
    except Exception as e:
        logger.error(f"Ошибка при регистрации роутера info: {e}", exc_info=True)
    
    try:
        dp.include_router(admin.router)
        logger.info("Роутер admin зарегистрирован")
    except Exception as e:
        logger.error(f"Ошибка при регистрации роутера admin: {e}", exc_info=True)
    
    logger.info("Бот запущен!")
    
    # Запускаем polling
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Бот остановлен")

