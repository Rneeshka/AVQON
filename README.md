Aegis — Антивирусное расширение и API ядро

Лёгкое, быстрое и локально работающее решение для проверки URL и файлов. Aegis объединяет браузерное расширение (Chrome/Chromium) и FastAPI‑сервер, который использует локальный кэш + внешние сервисы (VirusTotal, Google Safe Browsing, AbuseIPDB).

 Возможности

Проверка URL и файлов на вредоносность

Быстрые ответы за счёт локального кэша

Интеграции с внешними API (при наличии ключей)

WebSocket‑связь с расширением

Нативный хост для безопасной работы с файлами

 Структура проекта
Aegis/
aegis_start/ — браузерное расширение (popup, background, native host)

antivirus-core/ — FastAPI-сервер ядра и утилиты

data/ — sqlite-базы и кэши

logs/ — лог-файлы
1) Установка зависимостей
python -m venv .venv
source .venv/bin/activate
pip install -r antivirus-core/requirements.txt
2) Запуск API
cd antivirus-core
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
3) Установка расширения (Chrome)
chrome://extensions → Режим разработчика → Загрузить распакованное
Выбрать папку aegis_start/
Основные API‑эндпоинты
GET  /health
POST /check/url
POST /scan/url
POST /check/file
POST /local-cache/check

Пример запроса:

curl -X POST http://127.0.0.1:8000/check/url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com"}'
 API‑ключи

Для работы с VirusTotal, Google Safe Browsing и AbuseIPDB добавьте переменные окружения с вашими ключами. Без них ядро работает в базовом режиме..