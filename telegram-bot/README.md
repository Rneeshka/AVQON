# Telegram-бот для продажи лицензий AEGIS

Бот для продажи доступа к продукту AEGIS через Telegram.

## Установка

1. Установи зависимости:
```bash
pip install -r requirements.txt
```

2. Создай файл `.env` на основе `.env.example`:
```bash
cp .env.example .env
```

3. Заполни `.env` файл:
- `BOT_TOKEN` - токен бота от BotFather
- `API_KEY` - секретный ключ для API генерации ключей
- `API_URL` - URL вашего API сервера
- `ADMIN_ID` - ваш Telegram ID

## Запуск

```bash
python bot.py
```

## Структура проекта

```
telegram-bot/
├── bot.py              # Главный файл запуска
├── config.py           # Конфигурация
├── database.py         # Работа с БД
├── api_client.py       # Клиент для API генерации ключей
├── handlers/           # Обработчики команд и кнопок
│   ├── common.py       # Общие команды (/start)
│   ├── purchase.py     # Покупка лицензий
│   ├── info.py         # Информационные разделы (FAQ, поддержка)
│   └── admin.py        # Админ-команды
├── data/               # База данных (создается автоматически)
└── requirements.txt    # Зависимости
```

## Админ-команды

- `/stats` - статистика бота
- `/user <user_id>` - информация о пользователе
- `/give_key <user_id>` - выдать ключ вручную

## API интеграция

Бот интегрируется с вашим API для генерации ключей:
- Endpoint: `POST /api/v1/generate-license`
- Headers: `Authorization: Bearer {API_KEY}`
- Body: `{"user_id": "...", "username": "..."}`

## База данных

Используется SQLite с двумя таблицами:
- `users` - пользователи и их лицензии
- `payments` - история платежей

