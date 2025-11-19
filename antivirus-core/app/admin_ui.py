from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from typing import Optional
from urllib.parse import quote
import os
from datetime import datetime, timedelta

from app.database import db_manager

router = APIRouter(prefix="/admin/ui", tags=["Админ UI"])


def _layout(request: Request, title: str, body: str) -> str:
    root_path = request.scope.get("root_path", "")
    # Гарантируем, что суффиксы не дублируют слеши
    def p(path: str) -> str:
        if not path:
            return root_path or "/"
        if path.startswith("/"):
            path = path[1:]
        if root_path.endswith("/"):
            return f"{root_path}{path}"
        return f"{root_path}/{path}"

    return f"""
<!DOCTYPE html>
<html lang=\"ru\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{title}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; background: #f6f7f9; color: #111827; }}
    header {{ background: #111827; color: white; padding: 16px 24px; }}
    header a {{ color: #d1d5db; margin-right: 16px; text-decoration: none; }}
    header a.active {{ color: #ffffff; font-weight: 600; }}
    main {{ padding: 24px; max-width: 1100px; margin: 0 auto; }}
    .card {{ background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; margin-bottom: 16px; }}
    .row {{ display: flex; gap: 16px; flex-wrap: wrap; }}
    .col {{ flex: 1 1 300px; }}
    h1 {{ margin: 0 0 12px; font-size: 20px; }}
    h2 {{ margin: 0 0 12px; font-size: 18px; }}
    form {{ display: grid; gap: 8px; }}
    label {{ font-size: 14px; color: #374151; }}
    input, select, textarea {{ padding: 10px; border: 1px solid #d1d5db; border-radius: 8px; }}
    button {{ background: #2563eb; color: white; border: 0; padding: 10px 14px; border-radius: 8px; cursor: pointer; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; font-size: 14px; }}
    .muted {{ color: #6b7280; }}
    .badge-basic {{ background: #e5e7eb; color: #374151; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
    .badge-premium {{ background: #fbbf24; color: #92400e; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
  </style>
  <script>function nav(h){{ window.location.href = h; }}</script>
  <link rel=\"icon\" href=\"data:,\" />
  <meta name=\"robots\" content=\"noindex\" />
</head>
<body>
  <header>
    <nav>
      <a href=\"{p('admin/ui')}\">Обзор</a>
      <a href=\"{p('admin/ui/keys')}\">Ключи API</a>
      <a href=\"{p('admin/ui/threats')}\">Угрозы</a>
      <a href=\"{p('admin/ui/ip')}\">IP репутация</a>
      <a href=\"{p('admin/ui/logs')}\">Логи</a>
      <a href=\"{p('docs')}\" style=\"float:right\">Документация</a>
    </nav>
  </header>
  <main>
    {body}
  </main>
</body>
</html>
"""


@router.get("", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = db_manager.get_database_stats()
    body = f"""
    <div class="card">
      <h1>Панель администратора</h1>
      <p class="muted">Краткая сводка состояния системы</p>
    </div>
    <div class="row">
      <div class="card col"><h2>Угрозы</h2><div>Хэши: <b>{stats.get('malicious_hashes', 0)}</b></div><div>URL: <b>{stats.get('malicious_urls', 0)}</b></div><div>Всего угроз: <b>{stats.get('total_threats', 0)}</b></div></div>
      <div class="card col"><h2>API ключи</h2><div>Активных ключей: <b>{stats.get('active_api_keys', 0)}</b></div><div>Всего запросов: <b>{stats.get('total_requests', 0)}</b></div></div>
    </div>
    <div class="row">
      <div class="card col">
        <h2>Быстрые действия</h2>
        <div style=\"display:grid;gap:8px\">
          <button onclick=\"nav('{request.scope.get('root_path','') + ('/admin/ui/keys' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/keys')}')\">Создать API ключ</button>
          <button onclick=\"nav('{request.scope.get('root_path','') + ('/admin/ui/threats' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats')}')\">Добавить угрозу</button>
        </div>
      </div>
    </div>
    """
    return _layout(request, "Админ панель – обзор", body)


@router.get("/keys", response_class=HTMLResponse)
async def keys_page(request: Request):
    # Получаем список ключей (минимальная информация)
    keys = []
    try:
        with db_manager._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT api_key, name, is_active, access_level, rate_limit_daily, rate_limit_hourly,
                       requests_total, requests_today, requests_hour, created_at, last_used, expires_at,
                       user_id, 
                       (SELECT username FROM accounts WHERE accounts.id = api_keys.user_id) as username,
                       (SELECT email FROM accounts WHERE accounts.id = api_keys.user_id) as email,
                       (SELECT password_hash FROM accounts WHERE accounts.id = api_keys.user_id) as password_hash
                FROM api_keys
                ORDER BY created_at DESC
                LIMIT 200
            """)
            keys = [dict(row) for row in cur.fetchall()]
    except Exception:
        keys = []

    from datetime import datetime, timezone
    
    def format_time_remaining(expires_at_str):
        if not expires_at_str:
            return "Бессрочно"
        try:
            expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            
            delta = expires_at - now
            if delta.total_seconds() < 0:
                return "Истёк"
            
            days = delta.days
            hours = delta.seconds // 3600
            
            if days > 0:
                return f"{days}д {hours}ч"
            elif hours > 0:
                return f"{hours}ч"
            else:
                minutes = delta.seconds // 60
                return f"{minutes}м" if minutes > 0 else "Скоро истечёт"
        except:
            return "Неизвестно"
    
    free_account_html = '<span style="color: #059669;">Свободен</span>'
    rows = "".join([
        (
            f"<tr><td><code>{k['api_key']}</code></td><td>{k['name']}</td><td>{'да' if k['is_active'] else 'нет'}</td>"
            f"<td><span class=\"badge-{k.get('access_level', 'basic')}\">{k.get('access_level', 'basic')}</span></td>"
            f"<td>{k['username'] if k['username'] else free_account_html}</td>"
            f"<td>{k['email'] or '-'}</td>"
            f"<td>{'***' if k['password_hash'] else '-'}</td>"
            f"<td>{k['rate_limit_daily']}/{k['rate_limit_hourly']}</td>"
            f"<td>{k['requests_today']}/{k['requests_hour']}</td>"
            f"<td>{k['requests_total']}</td>"
            f"<td class=\"muted\">{k['last_used']}</td><td class=\"muted\">{k['expires_at'] or '-'}</td>"
            f"<td><span style=\"color: #059669; font-weight: 500;\">{format_time_remaining(k['expires_at'])}</span></td></tr>"
        )
        for k in keys
    ])

    body = f"""
    <div class="card">
      <h1>Ключи API</h1>
      <p class="muted">Создание и просмотр API ключей</p>
    </div>
    <div class="card">
      <h2>Создать новый премиум-ключ</h2>
      <form method="post" action="{request.scope.get('root_path','') + ('/admin/ui/keys/create' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/keys/create')}">
        <label>Название клиента</label>
        <input name="name" required placeholder="Например: Браузерное расширение" />
        <label>Описание (необязательно)</label>
        <input name="description" placeholder="Краткое описание" />
        <input type="hidden" name="access_level" value="premium" />
        <div class="muted">Уровень доступа: <b>premium</b></div>
        <label>Срок действия (дней)</label>
        <select name="expires_days">
          <option value="7">7</option>
          <option value="30" selected>30</option>
          <option value="90">90</option>
          <option value="365">365</option>
        </select>
        <label>Дневной лимит</label>
        <input name="daily_limit" type="number" min="1" value="1000" />
        <label>Почасовой лимит</label>
        <input name="hourly_limit" type="number" min="1" value="100" />
        <button type="submit">Создать ключ</button>
      </form>
    </div>
    <div class="card">
      <h2>Продлить ключ</h2>
      <form method="post" action="{request.scope.get('root_path','') + ('/admin/ui/keys/extend' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/keys/extend')}">
        <label>API ключ</label>
        <input name="api_key" required placeholder="PREMI*-*****-..." />
        <label>Продлить на (дней)</label>
        <select name="extend_days">
          <option value="7">7</option>
          <option value="30" selected>30</option>
          <option value="90">90</option>
          <option value="365">365</option>
        </select>
        <button type="submit">Продлить</button>
      </form>
    </div>
    <div class="card">
      <h2>Список ключей</h2>
      <div style="overflow:auto">
        <table>
          <thead><tr><th>Ключ</th><th>Имя</th><th>Активен</th><th>Уровень</th><th>Username</th><th>Email</th><th>Пароль</th><th>Лимиты (день/час)</th><th>Запросы (сегодня/час)</th><th>Всего</th><th>Последнее использование</th><th>Истекает</th><th>Осталось</th></tr></thead>
          <tbody>{rows or '<tr><td colspan=13 class="muted">Ключей пока нет</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    """
    return _layout(request, "Админ панель – ключи API", body)


@router.post("/keys/create")
async def create_key_action(
    request: Request,
    name: str = Form(...),
    description: Optional[str] = Form(None),
    access_level: str = Form("premium"),
    daily_limit: int = Form(1000),
    hourly_limit: int = Form(100),
    expires_days: int = Form(30),
):
    access_level = "premium"
    api_key = db_manager.create_api_key(name, description or "", access_level, daily_limit, hourly_limit, expires_days)
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/keys" if not prefix.endswith('/') else "admin/ui/keys")), status_code=303)
    if api_key:
        safe_msg = quote(f"Создан {access_level} ключ: {api_key}")
        redirect.set_cookie("flash", safe_msg, max_age=10)
    else:
        safe_msg = quote("Не удалось создать ключ")
        redirect.set_cookie("flash", safe_msg, max_age=10)
    return redirect


@router.post("/keys/extend")
async def extend_key_action(
    request: Request,
    api_key: str = Form(...),
    extend_days: int = Form(...),
):
    ok = db_manager.extend_api_key(api_key, extend_days)
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/keys" if not prefix.endswith('/') else "admin/ui/keys")), status_code=303)
    msg = quote("Ключ продлён" if ok else "Ключ не найден или ошибка продления")
    redirect.set_cookie("flash", msg, max_age=10)
    return redirect


@router.get("/threats", response_class=HTMLResponse)
async def threats_page(request: Request):
    # Получаем все угрозы из универсальной таблицы
    threats = db_manager.get_all_threats()
    
    # Группируем по типам
    hash_threats = [t for t in threats if t['type'] == 'hash']
    url_threats = [t for t in threats if t['type'] == 'url']
    ip_threats = [t for t in threats if t['type'] == 'ip']
    domain_threats = [t for t in threats if t['type'] == 'domain']

    hash_rows = "".join([
        f"<tr><td><code>{h['value']}</code></td><td>{h['threat_level']}</td><td>{h['source']}</td><td>{h['created_at']}</td></tr>"
        for h in hash_threats
    ])
    url_rows = "".join([
        f"<tr><td>{u['value']}</td><td>{u['threat_level']}</td><td>{u['source']}</td><td>{u['created_at']}</td></tr>"
        for u in url_threats
    ])
    ip_rows = "".join([
        f"<tr><td>{i['value']}</td><td>{i['threat_level']}</td><td>{i['source']}</td><td>{i['created_at']}</td></tr>"
        for i in ip_threats
    ])
    domain_rows = "".join([
        f"<tr><td>{d['value']}</td><td>{d['threat_level']}</td><td>{d['source']}</td><td>{d['created_at']}</td></tr>"
        for d in domain_threats
    ])

    body = f"""
    <div class="card">
      <h1>База угроз (упрощенная)</h1>
      <p class="muted">Универсальная таблица для всех типов угроз</p>
    </div>
    <div class="row">
      <div class="card col">
        <h2>Добавить угрозу</h2>
        <form method=\"post\" action=\"{request.scope.get('root_path','') + ('/admin/ui/threats/add' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats/add')}\">
          <label>Тип угрозы</label>
          <select name=\"type\" required>
            <option value=\"hash\">Хэш файла</option>
            <option value=\"url\">URL</option>
            <option value=\"ip\">IP адрес</option>
            <option value=\"domain\">Домен</option>
          </select>
          <label>Значение</label>
          <input name=\"value\" required placeholder=\"Введите значение угрозы\" />
          <label>Уровень угрозы</label>
          <select name=\"threat_level\">
            <option value=\"safe\">Безопасно</option>
            <option value=\"suspicious\" selected>Подозрительно</option>
            <option value=\"malicious\">Вредоносно</option>
          </select>
          <label>Источник</label>
          <select name=\"source\">
            <option value=\"manual\" selected>Ручное добавление</option>
            <option value=\"external_api\">Внешний API</option>
            <option value=\"scan\">Автоматическое сканирование</option>
          </select>
          <button type=\"submit\">Добавить</button>
        </form>
      </div>
      <div class="card col">
        <h2>Статистика угроз</h2>
        <div class=\"stats\">
          <div><strong>Хэши:</strong> {len(hash_threats)}</div>
          <div><strong>URL:</strong> {len(url_threats)}</div>
          <div><strong>IP адреса:</strong> {len(ip_threats)}</div>
          <div><strong>Домены:</strong> {len(domain_threats)}</div>
          <div><strong>Всего:</strong> {len(threats)}</div>
        </div>
      </div>
    </div>
    <div class="card">
      <h2>Все угрозы</h2>
      <div style=\"max-height:400px;overflow:auto\">
        <table>
          <thead><tr><th>Тип</th><th>Значение</th><th>Уровень</th><th>Источник</th><th>Дата</th></tr></thead>
          <tbody>
            {hash_rows}
            {url_rows}
            {ip_rows}
            {domain_rows}
          </tbody>
        </table>
      </div>
    </div>
    """
    return _layout(request, "Админ панель – угрозы", body)


@router.post("/threats/add")
async def add_threat_action(
    request: Request,
    type: str = Form(...),
    value: str = Form(...),
    threat_level: str = Form("suspicious"),
    source: str = Form("manual"),
):
    """Универсальный обработчик для добавления угроз"""
    success = db_manager.add_threat(type, value, threat_level, source)
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/threats" if not prefix.endswith('/') else "admin/ui/threats")), status_code=303)
    msg = quote("Угроза добавлена" if success else "Ошибка добавления угрозы")
    redirect.set_cookie("flash", msg, max_age=10)
    return redirect


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    # Получаем логи из упрощенной таблицы logs
    logs = db_manager.get_all_logs()
    
    tr = "".join([
        (
            f"<tr><td class=\"muted\">{log['created_at']}</td><td><code>{log['api_key_hash'] or '-'}</code></td><td>{log['method']} {log['endpoint']}</td>"
            f"<td>{log['status_code']}</td><td>{log['response_time_ms'] or '-'}</td><td>{log['client_ip'] or '-'}</td></tr>"
        )
        for log in logs[:200]  # Ограничиваем 200 записями
    ])

    body = f"""
    <div class="card">
      <h1>Логи запросов (упрощенные)</h1>
      <p class="muted">Последние события API из таблицы logs</p>
    </div>
    <div class="card">
      <h2>Статистика</h2>
      <div class=\"stats\">
        <div><strong>Всего записей:</strong> {len(logs)}</div>
        <div><strong>Показано:</strong> {min(len(logs), 200)}</div>
      </div>
    </div>
    <div class="card">
      <div style=\"max-height:600px;overflow:auto\">
        <table>
          <thead><tr><th>Время</th><th>API ключ</th><th>Запрос</th><th>Статус</th><th>Время ответа</th><th>IP</th></tr></thead>
          <tbody>{tr or '<tr><td colspan=6 class="muted">Логи пусты</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    """
    return _layout(request, "Админ панель – логи", body)


@router.get("/ip", response_class=HTMLResponse)
async def ip_page(request: Request):
    try:
        rows = db_manager.list_ip_reputation(200)
    except Exception:
        rows = []
    tr = "".join([
        f"<tr><td>{r['ip']}</td><td>{r.get('threat_type') or '-'}</td><td>{r.get('reputation_score') if r.get('reputation_score') is not None else '-'}</td><td>{r.get('source') or '-'}</td><td class=\"muted\">{r.get('last_updated') or '-'}</td><td>{r.get('detection_count') or 0}</td></tr>"
        for r in rows
    ])

    body = f"""
    <div class="card">
      <h1>IP репутация</h1>
      <p class="muted">Сводка по известным IP из внешних источников</p>
    </div>
    <div class="card">
      <div style=\"overflow:auto\">
        <table>
          <thead><tr><th>IP</th><th>Тип угрозы</th><th>Оценка</th><th>Источник</th><th>Обновлено</th><th>Счетчик</th></tr></thead>
          <tbody>{tr or '<tr><td colspan=6 class="muted">Пока нет данных</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    """
    return _layout(request, "Админ панель – IP", body)


