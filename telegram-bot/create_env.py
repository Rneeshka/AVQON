"""Скрипт для создания .env файла"""
env_content = """# Токен бота от BotFather
BOT_TOKEN=8565002586:AAGt-fZwaQyMvCNUWzgxg9AYYKWQKCO4naw

# Секретный ключ для API генерации ключей (из antivirus-core/app/env.env)
API_KEY=secure_admin_token_2024_antivirus_core

# URL API сервера генерации ключей (используем существующий endpoint)
API_URL=https://api.aegis.builders/admin/api-keys/create

# ID администратора (твой Telegram ID)
# ВАЖНО: Замени на свой реальный Telegram ID! Узнай у бота @userinfobot
ADMIN_ID=123456789

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

