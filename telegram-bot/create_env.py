"""Скрипт для создания .env файла"""
env_content = """# Токен бота от BotFather
BOT_TOKEN=***REMOVED_BOT_TOKEN***

# Секретный ключ для API генерации ключей (из antivirus-core/app/env.env)
API_KEY=***REMOVED_API_KEY***

# URL API сервера генерации ключей (используем существующий endpoint)
API_URL=https://api.aegis.builders/admin/api-keys/create

# ID администратора (твой Telegram ID)
# ВАЖНО: Замени на свой реальный Telegram ID! Узнай у бота @userinfobot
ADMIN_ID=***REMOVED_ADMIN_ID***

# Режим тестирования (True/False)
TEST_MODE=True

# Путь к базе данных
DB_PATH=data/bot.db

# Ссылка на чат владельцев (опционально)
OWNERS_CHAT_LINK=https://t.me/aegis_owners

# Ссылка на установку расширения (опционально)
INSTALLATION_LINK=https://chrome.google.com/webstore
"""

with open('.env', 'w', encoding='utf-8') as f:
    f.write(env_content)

print("✅ Файл .env создан успешно!")

