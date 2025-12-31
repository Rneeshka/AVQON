import logging
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from typing import Optional
from urllib.parse import quote
import os
from datetime import datetime, timedelta

from app.database import db_manager
from app.services import analysis_service

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
      <a href=\"{p('admin/ui/cache')}\">Кэш URL</a>
      <a href=\"{p('admin/ui/ip')}\">IP репутация</a>
      <a href=\"{p('admin/ui/logs')}\">Логи</a>
      <a href=\"{p('admin/ui/danger')}\" style=\"color: #dc2626;\">⚠️ Опасная зона</a>
      <a href=\"{p('docs')}\" style=\"float:right\">Документация</a>
    </nav>
  </header>
  <main>
    {body}
  </main>
</body>
</html>
"""


async def _refresh_cache_entries(target: str, limit: int):
    limit = max(1, min(limit, 50))
    targets = []
    target = target.lower()
    if target in ("whitelist", "all"):
        targets.append("whitelist")
    if target in ("blacklist", "all"):
        targets.append("blacklist")
    if not targets:
        targets = ["all"]
    if "all" in targets:
        targets = ["whitelist", "blacklist"]

    summary = {"processed": 0, "whitelist": 0, "blacklist": 0, "errors": 0}
    entries = []
    for store in targets:
        entries.extend(db_manager.get_cached_entries(store, limit))

    # Ограничиваем общее число обновлений
    entries = entries[:limit]

    for entry in entries:
        url = entry.get("url")
        payload = entry.get("payload") or {}
        if not url:
            url = payload.get("url")
        if not url:
            domain = entry.get("domain") or payload.get("domain")
            if domain:
                url = f"https://{domain}"
        if not url:
            summary["errors"] += 1
            continue
        try:
            result = await analysis_service.analyze_url(url, use_external_apis=True)
            summary["processed"] += 1
            if result.get("safe") is True:
                db_manager.save_whitelist_entry(url, result)
                summary["whitelist"] += 1
            elif result.get("safe") is False:
                db_manager.save_blacklist_entry(url, result)
                summary["blacklist"] += 1
        except Exception as exc:
            summary["errors"] += 1
            logging.getLogger(__name__).warning(f"Cache refresh failed for {url}: {exc}")

    return summary


@router.get("", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = db_manager.get_database_stats()
    cache_stats = db_manager.get_cache_stats()
    prefix = request.scope.get("root_path", "")
    refresh_action = prefix + ("/admin/ui/cache/refresh" if not prefix.endswith("/") else "admin/ui/cache/refresh")
    body = f"""
    <div class="card">
      <h1>Панель администратора</h1>
      <p class="muted">Краткая сводка состояния системы</p>
    </div>
    <div class="row">
      <div class="card col"><h2>Угрозы</h2><div>Хэши: <b>{stats.get('malicious_hashes', 0)}</b></div><div>URL: <b>{stats.get('malicious_urls', 0)}</b></div><div>Всего угроз: <b>{stats.get('total_threats', 0)}</b></div></div>
      <div class="card col"><h2>API ключи</h2><div>Активных ключей: <b>{stats.get('active_api_keys', 0)}</b></div><div>Всего запросов: <b>{stats.get('total_requests', 0)}</b></div></div>
    </div>
    <div class="card">
      <h2>Локальная база (hover-cache)</h2>
      <div class="row">
        <div class="col"><div>Белый список: <b>{cache_stats.get('whitelist_entries', 0)}</b></div></div>
        <div class="col"><div>Чёрный список: <b>{cache_stats.get('blacklist_entries', 0)}</b></div></div>
        <div class="col"><div>Хитов кэша: <b>{cache_stats.get('whitelist_hits', 0) + cache_stats.get('blacklist_hits', 0)}</b></div></div>
      </div>
      <form method="post" action="{refresh_action}" style="margin-top:12px; display:grid; gap:8px; max-width:400px;">
        <label>Что обновить</label>
        <select name="target">
          <option value="all" selected>Белый и чёрный списки</option>
          <option value="whitelist">Только белый список</option>
          <option value="blacklist">Только чёрный список</option>
        </select>
        <label>Сколько записей пересканировать (старейшие)</label>
        <input type="number" name="limit" min="1" max="50" value="10" />
        <button type="submit">Обновить локальную базу</button>
        <p class="muted" style="font-size:12px;">Обновление вручную: мы пересканируем N самых старых записей через VirusTotal и перезапишем их в базе.</p>
      </form>
    </div>
    <div class="row">
      <div class="card col">
        <h2>Быстрые действия</h2>
        <div style=\"display:grid;gap:8px\">
          <button onclick=\"nav('{request.scope.get('root_path','') + ('/admin/ui/keys' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/keys')}')\">Создать API ключ</button>
          <button onclick=\"nav('{request.scope.get('root_path','') + ('/admin/ui/threats' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats')}')\">Добавить угрозу</button>
        </div>
      </div>
      <div class="card col" style="border: 2px solid #dc2626;">
        <h2 style="color: #dc2626;">⚠️ Опасная зона</h2>
        <p class="muted" style="color: #dc2626;">Полная очистка базы данных</p>
        <button onclick=\"nav('{request.scope.get('root_path','') + ('/admin/ui/danger' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/danger')}')\" style=\"background: #dc2626; margin-top: 8px;\">Открыть опасную зону</button>
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
                       api_keys.user_id, 
                       COALESCE(
                           (SELECT username FROM accounts WHERE accounts.id = api_keys.user_id),
                           (SELECT username FROM users WHERE users.user_id = api_keys.user_id)
                       ) as username,
                       COALESCE(
                           (SELECT email FROM accounts WHERE accounts.id = api_keys.user_id),
                           (SELECT email FROM users WHERE users.user_id = api_keys.user_id)
                       ) as email,
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
        <input name="daily_limit" type="number" min="1" value="10000" />
        <label>Почасовой лимит</label>
        <input name="hourly_limit" type="number" min="1" value="10000" />
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
    daily_limit: int = Form(10000),
    hourly_limit: int = Form(10000),
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


@router.post("/cache/refresh")
async def refresh_cache_action(
    request: Request,
    target: str = Form("all"),
    limit: int = Form(10)
):
    summary = await _refresh_cache_entries(target, int(limit))
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui" if not prefix.endswith('/') else "admin/ui")), status_code=303)
    msg = quote(f"Обновлено: {summary['processed']}, white: {summary['whitelist']}, black: {summary['blacklist']}, ошибок: {summary['errors']}")
    redirect.set_cookie("flash", msg, max_age=10)
    return redirect


@router.get("/threats", response_class=HTMLResponse)
async def threats_page(request: Request):
    # Получаем все угрозы из реальных таблиц
    threats = db_manager.get_all_threats()
    
    # Группируем по типам
    hash_threats = [t for t in threats if t.get('type') == 'hash']
    url_threats = [t for t in threats if t.get('type') == 'url']
    ip_threats = [t for t in threats if t.get('type') == 'ip']
    domain_threats = [t for t in threats if t.get('type') == 'domain']

    hash_rows = "".join([
        f"<tr><td><code>{h['value'][:64]}...</code></td><td>{h.get('threat_type', '-')}</td><td>{h.get('threat_level', '-')}</td><td>{h.get('source', '-')}</td><td>{h.get('detection_count', 0)}</td><td class=\"muted\">{h.get('created_at', '-')}</td></tr>"
        for h in hash_threats
    ])
    url_rows = "".join([
        f"<tr><td><a href=\"{u['value']}\" target=\"_blank\">{u['value'][:80]}{'...' if len(u['value']) > 80 else ''}</a></td><td>{u.get('threat_type', '-')}</td><td>{u.get('threat_level', '-')}</td><td>{u.get('source', '-')}</td><td>{u.get('detection_count', 0)}</td><td class=\"muted\">{u.get('created_at', '-')}</td></tr>"
        for u in url_threats
    ])
    ip_rows = "".join([
        f"<tr><td>{i['value']}</td><td>{i.get('threat_level', '-')}</td><td>{i.get('source', '-')}</td><td class=\"muted\">{i.get('created_at', '-')}</td></tr>"
        for i in ip_threats
    ])
    domain_rows = "".join([
        f"<tr><td>{d['value']}</td><td>{d.get('threat_level', '-')}</td><td>{d.get('source', '-')}</td><td class=\"muted\">{d.get('created_at', '-')}</td></tr>"
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
      <h2>Вредоносные URL</h2>
      <div style=\"max-height:400px;overflow:auto\">
        <table>
          <thead><tr><th>URL</th><th>Тип угрозы</th><th>Уровень</th><th>Источник</th><th>Обнаружений</th><th>Дата</th></tr></thead>
          <tbody>{url_rows or '<tr><td colspan=6 class="muted">Нет вредоносных URL</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <h2>Вредоносные хэши</h2>
      <div style=\"max-height:400px;overflow:auto\">
        <table>
          <thead><tr><th>Хэш</th><th>Тип угрозы</th><th>Уровень</th><th>Источник</th><th>Обнаружений</th><th>Дата</th></tr></thead>
          <tbody>{hash_rows or '<tr><td colspan=6 class="muted">Нет вредоносных хэшей</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <h2>Поиск и удаление URL</h2>
      <p class="muted">Найдите конкретный URL и удалите его из базы данных, если он ошибочно помечен как опасный</p>
      <form method="get" action="{request.scope.get('root_path','') + ('/admin/ui/threats/search' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats/search')}" style="margin-top:12px; display:grid; gap:8px;">
        <label>Поиск URL или домена</label>
        <input name="q" type="text" placeholder="Введите URL или домен для поиска" required />
        <button type="submit">Найти</button>
      </form>
    </div>
    <div class="card">
      <h2>Очистка базы данных</h2>
      <p class="muted" style="color: #dc2626; font-weight: 600;">⚠️ ВНИМАНИЕ: Эти действия необратимы!</p>
      <form method="post" action="{request.scope.get('root_path','') + ('/admin/ui/threats/clear' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats/clear')}" style="margin-top:12px; display:grid; gap:8px;">
        <label>Что очистить</label>
        <select name="target" required>
          <option value="urls">Только вредоносные URL</option>
          <option value="hashes">Только вредоносные хэши</option>
          <option value="all_urls">Все URL данные (URL + кэш)</option>
          <option value="all">ВСЕ угрозы (URL + хэши)</option>
        </select>
        <button type="submit" style="background: #dc2626;">Очистить</button>
      </form>
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
    try:
        if type == "url":
            threat_type = "malware" if threat_level == "malicious" else "phishing"
            severity = "high" if threat_level == "malicious" else "medium"
            success = db_manager.add_malicious_url(value, threat_type, f"Manual addition: {threat_level}", severity)
        elif type == "hash":
            threat_type = "malware" if threat_level == "malicious" else "trojan"
            severity = "high" if threat_level == "malicious" else "medium"
            success = db_manager.add_malicious_hash(value, threat_type, f"Manual addition: {threat_level}", severity)
        else:
            success = False
    except Exception as e:
        logging.getLogger(__name__).error(f"Add threat error: {e}")
        success = False
    
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/threats" if not prefix.endswith('/') else "admin/ui/threats")), status_code=303)
    msg = quote("Угроза добавлена" if success else "Ошибка добавления угрозы")
    redirect.set_cookie("flash", msg, max_age=10)
    return redirect


@router.get("/threats/search", response_class=HTMLResponse)
async def search_urls_page(request: Request, q: str = ""):
    """Страница поиска URL в базе данных"""
    results = {"malicious_urls": [], "cached_blacklist": [], "cached_whitelist": []}
    
    if q:
        try:
            results = db_manager.search_urls_in_database(q, limit=50)
        except Exception as e:
            logging.getLogger(__name__).error(f"Search URLs error: {e}")
    
    malicious_rows = "".join([
        f"<tr><td><a href=\"{m['url']}\" target=\"_blank\">{m['url'][:80]}{'...' if len(m['url']) > 80 else ''}</a></td>"
        f"<td>{m.get('domain', '-')}</td>"
        f"<td>{m.get('threat_type', '-')}</td>"
        f"<td>{m.get('severity', '-')}</td>"
        f"<td>{m.get('detection_count', 0)}</td>"
        f"<td class=\"muted\">{m.get('last_updated', '-')}</td>"
        f"<td><form method=\"post\" action=\"{request.scope.get('root_path','') + ('/admin/ui/threats/remove' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats/remove')}\" style=\"display:inline;\">"
        f"<input type=\"hidden\" name=\"url\" value=\"{m['url']}\" />"
        f"<input type=\"hidden\" name=\"type\" value=\"malicious\" />"
        f"<button type=\"submit\" style=\"background: #dc2626; padding: 4px 8px; font-size: 12px;\">Удалить</button>"
        f"</form>"
        f"<form method=\"post\" action=\"{request.scope.get('root_path','') + ('/admin/ui/threats/recheck' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats/recheck')}\" style=\"display:inline; margin-left:4px;\">"
        f"<input type=\"hidden\" name=\"url\" value=\"{m['url']}\" />"
        f"<button type=\"submit\" style=\"background: #059669; padding: 4px 8px; font-size: 12px;\">Перепроверить</button>"
        f"</form></td></tr>"
        for m in results["malicious_urls"]
    ])
    
    blacklist_rows = "".join([
        f"<tr><td><a href=\"{b['url']}\" target=\"_blank\">{b['url'][:80]}{'...' if len(b['url']) > 80 else ''}</a></td>"
        f"<td>{b.get('domain', '-')}</td>"
        f"<td>{b.get('threat_type', '-')}</td>"
        f"<td>{b.get('hit_count', 0)}</td>"
        f"<td class=\"muted\">{b.get('last_seen', '-')}</td>"
        f"<td><form method=\"post\" action=\"{request.scope.get('root_path','') + ('/admin/ui/threats/remove' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats/remove')}\" style=\"display:inline;\">"
        f"<input type=\"hidden\" name=\"url\" value=\"{b['url']}\" />"
        f"<input type=\"hidden\" name=\"type\" value=\"blacklist\" />"
        f"<button type=\"submit\" style=\"background: #dc2626; padding: 4px 8px; font-size: 12px;\">Удалить</button>"
        f"</form>"
        f"<form method=\"post\" action=\"{request.scope.get('root_path','') + ('/admin/ui/threats/recheck' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/threats/recheck')}\" style=\"display:inline; margin-left:4px;\">"
        f"<input type=\"hidden\" name=\"url\" value=\"{b['url']}\" />"
        f"<button type=\"submit\" style=\"background: #059669; padding: 4px 8px; font-size: 12px;\">Перепроверить</button>"
        f"</form></td></tr>"
        for b in results["cached_blacklist"]
    ])
    
    body = f"""
    <div class="card">
      <h1>Поиск URL в базе данных</h1>
      <p class="muted">Найдите URL, который ошибочно помечен как опасный, и удалите его</p>
    </div>
    <div class="card">
      <form method="get" style="display:grid; gap:8px;">
        <label>Поиск URL или домена</label>
        <input name="q" type="text" value="{q}" placeholder="Введите URL или домен" required />
        <button type="submit">Найти</button>
      </form>
    </div>
    {f'''
    <div class="card">
      <h2>Найдено в malicious_urls: {len(results["malicious_urls"])}</h2>
      <div style="max-height:400px;overflow:auto;">
        <table>
          <thead><tr><th>URL</th><th>Домен</th><th>Тип угрозы</th><th>Уровень</th><th>Обнаружений</th><th>Обновлено</th><th>Действие</th></tr></thead>
          <tbody>{malicious_rows or '<tr><td colspan=7 class="muted">Не найдено</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <h2>Найдено в cached_blacklist: {len(results["cached_blacklist"])}</h2>
      <div style="max-height:400px;overflow:auto;">
        <table>
          <thead><tr><th>URL</th><th>Домен</th><th>Тип угрозы</th><th>Хитов</th><th>Последний раз</th><th>Действие</th></tr></thead>
          <tbody>{blacklist_rows or '<tr><td colspan=6 class="muted">Не найдено</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    ''' if q else ''}
    """
    return _layout(request, "Поиск URL", body)


@router.post("/threats/remove")
async def remove_url_action(
    request: Request,
    url: str = Form(...),
    type: str = Form(...),
):
    """Удаление конкретного URL из базы данных"""
    try:
        if type == "malicious":
            success = db_manager.remove_malicious_url(url)
            msg = f"URL удален из malicious_urls" if success else "URL не найден в malicious_urls"
        elif type == "blacklist":
            success = db_manager.remove_cached_blacklist_url(url)
            msg = f"URL удален из blacklist кэша" if success else "URL не найден в blacklist кэша"
        elif type == "all":
            success = db_manager.mark_url_as_safe(url)
            msg = f"URL помечен как безопасный (удален из всех списков)" if success else "URL не найден"
        else:
            msg = "Неверный тип"
            success = False
    except Exception as e:
        logging.getLogger(__name__).error(f"Remove URL error: {e}")
        msg = f"Ошибка удаления: {str(e)}"
        success = False
    
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/threats/search?q=" + quote(url) if not prefix.endswith('/') else "admin/ui/threats/search?q=" + quote(url))), status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect


@router.post("/threats/recheck")
async def recheck_url_action(
    request: Request,
    url: str = Form(...),
):
    """Принудительная перепроверка URL (игнорирует БД)"""
    try:
        # Удаляем из БД и кэша
        db_manager.mark_url_as_safe(url)
        
        # Делаем новый анализ, игнорируя БД
        result = await analysis_service.analyze_url(url, use_external_apis=True, ignore_database=True)
        
        if result.get("safe") is True:
            # Если URL безопасен, сохраняем в whitelist
            db_manager.save_whitelist_entry(url, result)
            msg = f"✅ URL перепроверен и помечен как безопасный"
        elif result.get("safe") is False:
            # Если все еще опасен, сохраняем обратно в blacklist (но не в malicious_urls)
            db_manager.save_blacklist_entry(url, result)
            msg = f"⚠️ URL перепроверен и все еще помечен как опасный: {result.get('threat_type', 'unknown')}"
        else:
            msg = f"❓ URL перепроверен, результат неопределенный"
    except Exception as e:
        logging.getLogger(__name__).error(f"Recheck URL error: {e}")
        msg = f"Ошибка перепроверки: {str(e)}"
    
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/threats/search?q=" + quote(url) if not prefix.endswith('/') else "admin/ui/threats/search?q=" + quote(url))), status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect


@router.post("/threats/clear")
async def clear_threats_action(
    request: Request,
    target: str = Form(...),
):
    """Очистка базы данных угроз"""
    try:
        if target == "urls":
            count = db_manager.clear_malicious_urls()
            msg = f"Очищено {count} вредоносных URL"
        elif target == "hashes":
            count = db_manager.clear_malicious_hashes()
            msg = f"Очищено {count} вредоносных хэшей"
        elif target == "all_urls":
            result = db_manager.clear_all_url_data()
            msg = f"Очищено: {result['malicious_urls']} URL, {result['cached_whitelist']} whitelist, {result['cached_blacklist']} blacklist"
        elif target == "all":
            url_count = db_manager.clear_malicious_urls()
            hash_count = db_manager.clear_malicious_hashes()
            msg = f"Очищено {url_count} URL и {hash_count} хэшей"
        else:
            msg = "Неверный параметр"
    except Exception as e:
        logging.getLogger(__name__).error(f"Clear threats error: {e}")
        msg = f"Ошибка очистки: {str(e)}"
    
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/threats" if not prefix.endswith('/') else "admin/ui/threats")), status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
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


@router.get("/cache", response_class=HTMLResponse)
async def cache_page(request: Request):
    """Страница для просмотра всех URL из кэша (whitelist и blacklist)"""
    try:
        whitelist_entries = db_manager.get_all_cached_whitelist(limit=500)
        blacklist_entries = db_manager.get_all_cached_blacklist(limit=500)
    except Exception as e:
        logging.getLogger(__name__).error(f"Get cache entries error: {e}")
        whitelist_entries = []
        blacklist_entries = []
    
    whitelist_rows = "".join([
        f"<tr><td><a href=\"https://{w['domain']}\" target=\"_blank\">{w['domain']}</a></td>"
        f"<td>{w.get('confidence', '-')}</td>"
        f"<td>{w.get('detection_ratio', '-')}</td>"
        f"<td>{w.get('source', '-')}</td>"
        f"<td>{w.get('hit_count', 0)}</td>"
        f"<td class=\"muted\">{w.get('last_seen', '-')}</td></tr>"
        for w in whitelist_entries
    ])
    
    blacklist_rows = "".join([
        f"<tr><td><a href=\"{b['url']}\" target=\"_blank\">{b['url'][:80]}{'...' if len(b['url']) > 80 else ''}</a></td>"
        f"<td>{b.get('domain', '-')}</td>"
        f"<td>{b.get('threat_type', '-')}</td>"
        f"<td>{b.get('source', '-')}</td>"
        f"<td>{b.get('hit_count', 0)}</td>"
        f"<td class=\"muted\">{b.get('last_seen', '-')}</td></tr>"
        for b in blacklist_entries
    ])
    
    body = f"""
    <div class="card">
      <h1>Кэш URL</h1>
      <p class="muted">Все URL, проанализированные системой и сохраненные в кэш</p>
    </div>
    <div class="row">
      <div class="card col">
        <h2>Статистика</h2>
        <div>
          <div><strong>Whitelist записей:</strong> {len(whitelist_entries)}</div>
          <div><strong>Blacklist записей:</strong> {len(blacklist_entries)}</div>
          <div><strong>Всего:</strong> {len(whitelist_entries) + len(blacklist_entries)}</div>
        </div>
      </div>
      <div class="card col">
        <h2>Очистка кэша</h2>
        <p class="muted" style="color: #dc2626; font-weight: 600;">⚠️ ВНИМАНИЕ: Действие необратимо!</p>
        <form method="post" action="{request.scope.get('root_path','') + ('/admin/ui/cache/clear' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/cache/clear')}" style="margin-top:12px; display:grid; gap:8px;">
          <label>Что очистить</label>
          <select name="target" required>
            <option value="whitelist">Только whitelist</option>
            <option value="blacklist">Только blacklist</option>
            <option value="all">Весь кэш</option>
          </select>
          <button type="submit" style="background: #dc2626;">Очистить кэш</button>
        </form>
      </div>
    </div>
    <div class="card">
      <h2>Whitelist (безопасные домены)</h2>
      <div style=\"max-height:400px;overflow:auto\">
        <table>
          <thead><tr><th>Домен</th><th>Уверенность</th><th>Соотношение</th><th>Источник</th><th>Хитов</th><th>Последний раз</th></tr></thead>
          <tbody>{whitelist_rows or '<tr><td colspan=6 class="muted">Whitelist пуст</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <h2>Blacklist (опасные URL)</h2>
      <div style=\"max-height:400px;overflow:auto\">
        <table>
          <thead><tr><th>URL</th><th>Домен</th><th>Тип угрозы</th><th>Источник</th><th>Хитов</th><th>Последний раз</th></tr></thead>
          <tbody>{blacklist_rows or '<tr><td colspan=6 class="muted">Blacklist пуст</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    """
    return _layout(request, "Админ панель – кэш URL", body)


@router.post("/cache/clear")
async def clear_cache_action(
    request: Request,
    target: str = Form(...),
):
    """Очистка кэша URL"""
    try:
        if target == "whitelist":
            count = db_manager.clear_cached_whitelist()
            msg = f"Очищено {count} записей из whitelist"
        elif target == "blacklist":
            count = db_manager.clear_cached_blacklist()
            msg = f"Очищено {count} записей из blacklist"
        elif target == "all":
            whitelist_count = db_manager.clear_cached_whitelist()
            blacklist_count = db_manager.clear_cached_blacklist()
            msg = f"Очищено {whitelist_count} whitelist и {blacklist_count} blacklist записей"
        else:
            msg = "Неверный параметр"
    except Exception as e:
        logging.getLogger(__name__).error(f"Clear cache error: {e}")
        msg = f"Ошибка очистки: {str(e)}"
    
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/cache" if not prefix.endswith('/') else "admin/ui/cache")), status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect


@router.get("/danger", response_class=HTMLResponse)
async def danger_zone_page(request: Request):
    """Страница опасной зоны - полная очистка базы данных"""
    body = f"""
    <div class="card" style="border: 2px solid #dc2626;">
      <h1 style="color: #dc2626;">⚠️ ОПАСНАЯ ЗОНА</h1>
      <p style="color: #dc2626; font-weight: 600; font-size: 16px;">
        ВНИМАНИЕ: Все операции на этой странице необратимы!
      </p>
    </div>
    <div class="card" style="border: 2px solid #dc2626;">
      <h2 style="color: #dc2626;">Полная очистка базы данных</h2>
      <p class="muted">
        Эта операция удалит <strong>ВСЕ</strong> данные из следующих таблиц:
      </p>
      <ul style="color: #dc2626;">
        <li>Все вредоносные URL (malicious_urls)</li>
        <li>Все вредоносные хэши (malicious_hashes)</li>
        <li>Весь whitelist кэш (cached_whitelist)</li>
        <li>Весь blacklist кэш (cached_blacklist)</li>
        <li>Всю IP репутацию (ip_reputation)</li>
        <li>Все логи запросов (request_logs)</li>
        <li>Все фоновые задачи (background_jobs)</li>
      </ul>
      <p style="color: #059669; font-weight: 600; margin-top: 16px;">
        ✅ Сохранятся: API ключи, аккаунты пользователей
      </p>
      <form method="post" action="{request.scope.get('root_path','') + ('/admin/ui/danger/clear-all' if not request.scope.get('root_path','').endswith('/') else 'admin/ui/danger/clear-all')}" style="margin-top:20px; display:grid; gap:12px; max-width:500px;">
        <label style="font-weight: 600; color: #dc2626;">Пароль для подтверждения:</label>
        <input name="password" type="password" required placeholder="Введите пароль" style="padding: 12px; font-size: 14px;" />
        <label style="font-weight: 600; color: #dc2626;">
          <input type="checkbox" name="confirm" required style="margin-right: 8px;" />
          Я понимаю, что это действие необратимо и удалит все данные
        </label>
        <button type="submit" style="background: #dc2626; padding: 14px; font-size: 16px; font-weight: 600;">
          🗑️ ПОЛНОСТЬЮ ОЧИСТИТЬ БАЗУ ДАННЫХ
        </button>
      </form>
      <div style="margin-top: 20px; padding: 12px; background: #fef3c7; border-radius: 8px;">
        <p style="margin: 0; font-size: 13px; color: #92400e;">
          <strong>Примечание:</strong> Эта операция также очистит:
          <ul style="margin: 8px 0 0 20px; padding: 0;">
            <li>JSONL файлы кэша (cache_whitelist.jsonl, cache_blacklist.jsonl)</li>
            <li>Диск-кэш (cache.db)</li>
            <li>In-memory кэш сервиса анализа</li>
          </ul>
          <strong style="color: #dc2626;">ВНИМАНИЕ:</strong> Кэш в браузерном расширении нужно очищать отдельно:
          <ol style="margin: 8px 0 0 20px; padding: 0;">
            <li>Откройте расширение Aegis</li>
            <li>Перейдите в настройки</li>
            <li>Найдите опцию "Очистить кэш" или выполните в консоли браузера: <code style="background: #fff; padding: 2px 4px; border-radius: 3px;">chrome.storage.local.clear()</code></li>
          </ol>
        </p>
      </div>
    </div>
    """
    return _layout(request, "⚠️ Опасная зона", body)


@router.post("/danger/clear-all")
async def clear_all_database_action(
    request: Request,
    password: str = Form(...),
    confirm: str = Form(None),
):
    """Полная очистка базы данных с проверкой пароля"""
    # Пароль для защиты
    ADMIN_PASSWORD = "90~kz=Ut!I123nikita12364"
    
    if password != ADMIN_PASSWORD:
        prefix = request.scope.get("root_path", "")
        redirect = RedirectResponse(url=(prefix + ("/admin/ui/danger" if not prefix.endswith('/') else "admin/ui/danger")), status_code=303)
        redirect.set_cookie("flash", quote("❌ Неверный пароль!"), max_age=10)
        return redirect
    
    if not confirm:
        prefix = request.scope.get("root_path", "")
        redirect = RedirectResponse(url=(prefix + ("/admin/ui/danger" if not prefix.endswith('/') else "admin/ui/danger")), status_code=303)
        redirect.set_cookie("flash", quote("❌ Необходимо подтвердить операцию!"), max_age=10)
        return redirect
    
    try:
        # Очищаем in-memory кэш сервиса анализа
        try:
            analysis_service.clear_cache()
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to clear in-memory cache: {e}")
        
        results = db_manager.clear_all_database_data()
        total_deleted = sum([v for k, v in results.items() if k not in ['cache_whitelist.jsonl', 'cache_blacklist.jsonl']])
        files_deleted = sum([1 for k in ['cache_whitelist.jsonl', 'cache_blacklist.jsonl'] if results.get(k, 0) > 0])
        
        msg = f"✅ База данных полностью очищена! Удалено записей: {total_deleted}, файлов: {files_deleted}, кэш: {results.get('cache.db', 0)}"
        logging.getLogger(__name__).warning(f"FULL DATABASE CLEAR executed by admin - {total_deleted} records, {files_deleted} files, {results.get('cache.db', 0)} cache entries deleted")
    except Exception as e:
        logging.getLogger(__name__).error(f"Clear all database error: {e}")
        msg = f"❌ Ошибка очистки: {str(e)}"
    
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui" if not prefix.endswith('/') else "admin/ui")), status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect


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


