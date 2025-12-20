"""Конфигурация бота"""
import os
from dotenv import load_dotenv

load_dotenv()

# Токен бота
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# API для генерации ключей
API_KEY = os.getenv("API_KEY", "")
API_URL = os.getenv("API_URL", "")

# Админ
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))

# Настройки ЮKassa
YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID", "1208526")
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY", "live_6mWfP4mXP6BZGMfhX2iMn1BzlXJlUq7RYoQnU9sm-Os")
YOOKASSA_TEST_MODE = os.getenv("YOOKASSA_TEST_MODE", "False").lower() == "true"
YOOKASSA_PROVIDER_TOKEN = os.getenv("YOOKASSA_PROVIDER_TOKEN", "")  # Для Telegram Payments (не используется с ЮKassa)

# База данных (единая для бота и backend)
# Используем DATABASE_PATH если задан, иначе DB_PATH, иначе дефолтный путь
# По умолчанию используем /opt/Aegis/data/aegis.db для продакшена
DB_PATH = os.getenv("DATABASE_PATH") or os.getenv("DB_PATH", "/opt/aegis/data/aegis.db")

# Лимиты акции
TOTAL_LICENSES = 1000
LICENSE_PRICE_LIFETIME = 500  # Вечная лицензия за 500₽
LICENSE_PRICE_MONTHLY = 150  # Месячная подписка за 150₽

# Совместимость со старой логикой
LICENSE_PRICE = LICENSE_PRICE_LIFETIME

# Ссылки
OWNERS_CHAT_LINK = os.getenv("OWNERS_CHAT_LINK", "https://t.me/aegis_owners")
INSTALLATION_LINK = os.getenv(
    "INSTALLATION_LINK",
    "https://chromewebstore.google.com/detail/bedaaeaeddnodmmkfmfealepbbbdoegl"
)
SUPPORT_TECH = os.getenv("SUPPORT_TECH", "@aegis_tech")
SUPPORT_FINANCE = os.getenv("SUPPORT_FINANCE", "@aegis_finance")
SUPPORT_PARTNERS = os.getenv("SUPPORT_PARTNERS", "@aegis_partners")

# Проверка обязательных переменных
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не установлен в .env файле")

# Предупреждения для опциональных переменных (будут использоваться при генерации ключей)
if not API_KEY or API_KEY == "ваш_секретный_ключ_для_нашего_API":
    import warnings
    warnings.warn("API_KEY не установлен или использует значение по умолчанию. Генерация ключей не будет работать.")
if not API_URL or API_URL == "https://ваш-сервер.com/api/v1/generate-license":
    import warnings
    warnings.warn("API_URL не установлен или использует значение по умолчанию. Генерация ключей не будет работать.")

# Новый backend URL для оплаты
BACKEND_URL = os.getenv("BACKEND_URL", "https://api.aegis.builders")

# Эндпоинты платежей backend AEGIS
PAYMENTS_CREATE_URL = f"{BACKEND_URL}/payments/create"
PAYMENTS_STATUS_URL = f"{BACKEND_URL}/payments/status"

