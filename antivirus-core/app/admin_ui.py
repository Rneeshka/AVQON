import logging
import sys
from fastapi import APIRouter, Request, Form, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse
from typing import Optional, List
from urllib.parse import quote, unquote
import os
import json
import html
import csv
import io
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
      <a href=\"{p('admin/ui/reviews')}\">Отзывы</a>
      <a href=\"{p('admin/ui/crowd-reports')}\">Крауд-репорты</a>
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


def _p(request: Request, path: str) -> str:
    root = request.scope.get("root_path", "")
    if not path:
        return root or "/"
    if path.startswith("/"):
        path = path[1:]
    return f"{root.rstrip('/')}/{path}" if root else f"/{path}"


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = db_manager.get_database_stats()
    cache_stats = db_manager.get_cache_stats()
    prefix = request.scope.get("root_path", "")
    refresh_action = _p(request, "admin/ui/cache/refresh")

    # Данные для графиков и блоков
    requests_by_day = db_manager.get_requests_by_day(14)
    requests_by_hour = db_manager.get_requests_by_hour(24)
    threat_dist = db_manager.get_threat_types_distribution()
    top_domains = db_manager.get_top_cached_domains(15)
    recent_errors = db_manager.get_recent_errors(50)

    # Системная информация
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    try:
        import fastapi
        fastapi_ver = getattr(fastapi, "__version__", "?")
    except Exception:
        fastapi_ver = "?"
    cpu_ram = "—"
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        cpu_ram = f"CPU: {cpu}% | RAM: {mem.percent}% ({mem.used // (1024*1024)} МБ / {mem.total // (1024*1024)} МБ)"
    except Exception:
        pass
    uptime = "—"
    if hasattr(request.app.state, "start_time"):
        try:
            delta = datetime.utcnow() - request.app.state.start_time
            days, r = divmod(delta.total_seconds(), 86400)
            hours, r = divmod(r, 3600)
            mins = int(r // 60)
            uptime = f"{int(days)}д {int(hours)}ч {mins}м"
        except Exception:
            pass
    ws_count = 0
    ws_total_messages = 0
    ws_messages_per_sec = "—"
    ws_top_clients = []
    try:
        ws_manager = getattr(request.app.state, "ws_manager", None)
        if ws_manager:
            ws_count = ws_manager.get_connection_count() if hasattr(ws_manager, "get_connection_count") else ws_manager.active_connections_count()
            ws_total_messages = getattr(ws_manager, "get_total_messages", lambda: 0)()
            ws_top_clients = getattr(ws_manager, "get_top_clients_by_activity", lambda limit=5: [])(5)
            if hasattr(request.app.state, "start_time"):
                try:
                    delta = (datetime.utcnow() - request.app.state.start_time).total_seconds()
                    if delta > 0:
                        ws_messages_per_sec = f"{(ws_total_messages / delta):.2f}"
                except Exception:
                    pass
    except Exception:
        pass
    db_status = "PostgreSQL (активно)"  # можно улучшить проверкой соединения

    # Статус внешних API
    try:
        from app.external_apis.manager import external_api_manager
        api_status = external_api_manager.enabled_apis
    except Exception:
        api_status = {}

    # Эффективность кэша (hit ratio)
    total_hits = (cache_stats.get("whitelist_hits") or 0) + (cache_stats.get("blacklist_hits") or 0)
    total_entries = (cache_stats.get("whitelist_entries") or 0) + (cache_stats.get("blacklist_entries") or 0)
    cache_ratio = f"{(total_hits / (total_entries or 1)):.1f}" if total_entries else "0"
    cache_bytes = cache_stats.get("bytes_estimated", 0)
    cache_size_mb = f"{(cache_bytes / (1024*1024)):.2f} МБ" if cache_bytes else "—"

    # JSON для графиков (экранируем для JS)
    chart_days = json.dumps([r["date"] for r in requests_by_day])
    chart_days_counts = json.dumps([r["count"] for r in requests_by_day])
    chart_threat_labels = json.dumps(list(threat_dist.keys()) or ["Нет данных"])
    chart_threat_data = json.dumps(list(threat_dist.values()) or [0])
    chart_domain_labels = json.dumps([d["domain"][:30] for d in top_domains])
    chart_domain_data = json.dumps([d["hits"] for d in top_domains])

    # Гео (топ IP и топ стран по ip2location), версии расширения, прогноз
    top_ips = db_manager.get_top_ips_from_logs(15)
    top_countries = db_manager.get_top_countries_from_logs(15)
    geo_available = False
    try:
        from app.geo_ip import is_available
        geo_available = is_available()
    except Exception:
        pass
    version_stats = db_manager.get_extension_version_stats()
    avg_per_day = db_manager.get_requests_avg_per_day(7)
    forecast_7d = int(avg_per_day * 7) if avg_per_day else 0
    chart_version_labels = json.dumps(list(version_stats.keys()) or ["Нет данных"])
    chart_version_data = json.dumps(list(version_stats.values()) or [0])
    geo_ip_rows = "".join([f"<tr><td>{html.escape(str(r.get('ip') or '-'))}</td><td>{r.get('requests', 0)}</td></tr>" for r in top_ips])
    geo_country_rows = "".join([
        f"<tr><td>{html.escape(str(c.get('country_code') or '—'))}</td><td>{html.escape(str(c.get('country_name') or '—'))}</td><td>{c.get('requests', 0)}</td></tr>"
        for c in top_countries
    ])
    ws_top_rows = "".join([f"<tr><td>{html.escape(str(c.get('id', '')))}</td><td>{c.get('ip', '—')}</td><td>{c.get('user_id') or '—'}</td><td>{c.get('messages', 0)}</td></tr>" for c in ws_top_clients])

    errors_rows = "".join([
        f"<tr><td class=\"muted\">{e.get('ts', '-')}</td><td>{e.get('method', '-')} {e.get('endpoint', '-')[:60]}</td>"
        f"<td><span style=\"color:#dc2626;\">{e.get('status_code', '-')}</span></td><td>{e.get('response_time_ms') or '-'}</td><td>{e.get('client_ip_truncated') or '-'}</td></tr>"
        for e in recent_errors[:30]
    ])

    api_status_html = "".join([
        f"<div><span class=\"badge-{'premium' if api_status.get(k) else 'basic'}\">{k}</span> {'Вкл' if api_status.get(k) else 'Выкл'}</div>"
        for k in ("virustotal", "google_safe_browsing", "abuseipdb", "urlscan")
    ])

    flash = unquote(request.cookies.get("flash", ""))
    flash_escaped = html.escape(flash) if flash else ""
    flash_block = f'<div class="card" style="background:#ecfdf5; border-color:#059669;"><strong>Результат:</strong> {flash_escaped}</div>' if flash_escaped else ""

    body = f"""
    {flash_block}
    <div class="card">
      <h1>📊 Панель администратора</h1>
      <p class="muted">Дашборд мониторинга и управления</p>
    </div>

    <div class="card">
      <h2>🖥 Системная информация</h2>
      <div class="row" style="gap:12px;">
        <div class="col"><strong>Python:</strong> {py_ver}</div>
        <div class="col"><strong>FastAPI:</strong> {fastapi_ver}</div>
        <div class="col"><strong>Ресурсы:</strong> {cpu_ram}</div>
        <div class="col"><strong>Uptime:</strong> {uptime}</div>
        <div class="col"><strong>WebSocket:</strong> {ws_count} соединений</div>
        <div class="col"><strong>БД:</strong> {db_status}</div>
      </div>
    </div>

    <div class="card">
      <h2>🌐 Статус внешних API</h2>
      <div class="row" style="gap:16px;">{api_status_html or '<div class="muted">Не загружено</div>'}</div>
    </div>

    <div class="card">
      <h2>🔌 WebSocket мониторинг</h2>
      <div class="row" style="gap:16px;">
        <div class="col"><strong>Активные соединения:</strong> {ws_count}</div>
        <div class="col"><strong>Всего сообщений:</strong> {ws_total_messages}</div>
        <div class="col"><strong>Сообщ/сек (средн.):</strong> {ws_messages_per_sec}</div>
      </div>
      <h3 style="margin:12px 0 8px; font-size:14px;">Топ клиентов по активности</h3>
      <div style="max-height:120px;overflow:auto">
        <table><thead><tr><th>ID</th><th>IP</th><th>User ID</th><th>Сообщений</th></tr></thead><tbody>{ws_top_rows or '<tr><td colspan=4 class="muted">Нет данных</td></tr>'}</tbody></table>
      </div>
    </div>

    <div class="row">
      <div class="card col"><h2>Угрозы</h2><div>Хэши: <b>{stats.get('malicious_hashes', 0)}</b></div><div>URL: <b>{stats.get('malicious_urls', 0)}</b></div><div>Всего: <b>{stats.get('total_threats', 0)}</b></div></div>
      <div class="card col"><h2>API ключи</h2><div>Активных: <b>{stats.get('active_api_keys', 0)}</b></div><div>Всего запросов: <b>{stats.get('total_requests', 0)}</b></div></div>
      <div class="card col"><h2>Кэш URL</h2><div>Whitelist: <b>{cache_stats.get('whitelist_entries', 0)}</b></div><div>Blacklist: <b>{cache_stats.get('blacklist_entries', 0)}</b></div><div>Хитов: <b>{total_hits}</b> · Hit ratio: <b>{cache_ratio}</b></div><div>Размер: {cache_size_mb}</div></div>
    </div>

    <div class="row">
      <div class="card col" style="flex:1.5;">
        <h2>📈 Запросы по дням (14 дней)</h2>
        <canvas id="chartRequestsDay" height="200"></canvas>
      </div>
      <div class="card col">
        <h2>🥧 Типы угроз</h2>
        <canvas id="chartThreats" height="200"></canvas>
      </div>
    </div>
    <div class="card">
      <h2>🔗 Топ запрашиваемых доменов (кэш)</h2>
      <canvas id="chartDomains" height="180"></canvas>
    </div>

    <div class="row">
      <div class="card col">
        <h2>🌍 Гео: топ IP</h2>
        <div style="max-height:160px;overflow:auto"><table><thead><tr><th>IP</th><th>Запросов</th></tr></thead><tbody>{geo_ip_rows or '<tr><td colspan=2 class="muted">Нет данных</td></tr>'}</tbody></table></div>
      </div>
      <div class="card col">
        <h2>🌍 Топ стран по трафику</h2>
        <p class="muted" style="font-size:12px;">{ 'IP2Location подключён' if geo_available else 'Укажите IP2LOCATION_BIN_PATH и установите: pip install IP2Location' }</p>
        <div style="max-height:160px;overflow:auto"><table><thead><tr><th>Код</th><th>Страна</th><th>Запросов</th></tr></thead><tbody>{geo_country_rows or '<tr><td colspan=3 class="muted">Нет данных или IP2Location не настроен</td></tr>'}</tbody></table></div>
      </div>
      <div class="card col">
        <h2>📦 Версия расширения → пользователи</h2>
        <canvas id="chartVersion" height="160"></canvas>
      </div>
      <div class="card col">
        <h2>📈 Предиктивная аналитика</h2>
        <div><strong>Среднее запросов/день (7 дн.):</strong> {avg_per_day:.0f}</div>
        <div><strong>Прогноз на 7 дней:</strong> ~{forecast_7d}</div>
        <p class="muted" style="font-size:12px;">На основе request_logs</p>
      </div>
    </div>

    <div id="notifications-toast" style="position:fixed;top:16px;right:16px;z-index:9999;max-width:360px;display:none;"></div>

    <div class="card">
      <h2>🚨 Последние ошибки (status ≥ 400)</h2>
      <div style="max-height:280px;overflow:auto">
        <table>
          <thead><tr><th>Время</th><th>Запрос</th><th>Код</th><th>Мс</th><th>IP</th></tr></thead>
          <tbody>{errors_rows or '<tr><td colspan=5 class="muted">Ошибок нет</td></tr>'}</tbody>
        </table>
      </div>
      <p class="muted" style="margin-top:8px;"><a href="{_p(request, 'admin/ui/logs')}">Все логи →</a></p>
    </div>

    <div class="card">
      <h2>Локальная база (обновление кэша)</h2>
      <form method="post" action="{refresh_action}" style="margin-top:12px; display:grid; gap:8px; max-width:400px;">
        <select name="target">
          <option value="all" selected>Белый и чёрный списки</option>
          <option value="whitelist">Только белый список</option>
          <option value="blacklist">Только чёрный список</option>
        </select>
        <input type="number" name="limit" min="1" max="50" value="10" />
        <button type="submit">Обновить локальную базу</button>
      </form>
    </div>

    <div class="row">
      <div class="card col">
        <h2>🧪 Тест URL</h2>
        <p class="muted">Ручная проверка URL через админку</p>
        <form method="post" action="{_p(request, 'admin/ui/test-url')}" style="display:grid;gap:8px;">
          <input name="url" placeholder="https://example.com" required />
          <button type="submit">Проверить URL</button>
        </form>
      </div>
      <div class="card col">
        <h2>Быстрые действия</h2>
        <div style="display:grid;gap:8px">
          <button onclick="nav('{_p(request, 'admin/ui/keys')}')">Ключи API</button>
          <button onclick="nav('{_p(request, 'admin/ui/threats')}')">Угрозы</button>
          <button onclick="nav('{_p(request, 'admin/ui/reviews')}')">Отзывы</button>
          <button onclick="nav('{_p(request, 'admin/ui/cache')}')">Кэш</button>
        </div>
      </div>
      <div class="card col" style="border: 2px solid #dc2626;">
        <h2 style="color: #dc2626;">⚠️ Опасная зона</h2>
        <button onclick="nav('{_p(request, 'admin/ui/danger')}')" style="background: #dc2626;">Открыть</button>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
    (function() {{
      var days = {chart_days};
      var daysCounts = {chart_days_counts};
      var threatLabels = {chart_threat_labels};
      var threatData = {chart_threat_data};
      var domainLabels = {chart_domain_labels};
      var domainData = {chart_domain_data};

      if (document.getElementById('chartRequestsDay') && days.length) {{
        new Chart(document.getElementById('chartRequestsDay'), {{
          type: 'bar',
          data: {{ labels: days, datasets: [{{ label: 'Запросы', data: daysCounts, backgroundColor: 'rgba(37,99,235,0.6)' }}] }},
          options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
        }});
      }}
      if (document.getElementById('chartThreats') && threatLabels.length) {{
        new Chart(document.getElementById('chartThreats'), {{
          type: 'doughnut',
          data: {{ labels: threatLabels, datasets: [{{ data: threatData, backgroundColor: ['#2563eb','#dc2626','#059669','#f59e0b','#8b5cf6'] }}] }},
          options: {{ responsive: true }}
        }});
      }}
      if (document.getElementById('chartDomains') && domainLabels.length) {{
        new Chart(document.getElementById('chartDomains'), {{
          type: 'bar',
          data: {{ labels: domainLabels, datasets: [{{ label: 'Хитов', data: domainData, backgroundColor: 'rgba(5,150,105,0.6)' }}] }},
          options: {{ indexAxis: 'y', responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ beginAtZero: true }} }} }}
        }});
      }}
      var versionLabels = {chart_version_labels};
      var versionData = {chart_version_data};
      if (document.getElementById('chartVersion') && versionLabels.length) {{
        new Chart(document.getElementById('chartVersion'), {{
          type: 'doughnut',
          data: {{ labels: versionLabels, datasets: [{{ data: versionData, backgroundColor: ['#2563eb','#059669','#f59e0b','#8b5cf6','#ec4899'] }}] }},
          options: {{ responsive: true }}
        }});
      }}
    }})();
    (function notificationPoll() {{
      var base = document.querySelector('nav a[href*="admin/ui"]') ? (document.querySelector('nav a[href]').href.replace(/\\/admin\\/ui.*$/, '') || '') : '';
      fetch((base || '') + '/admin/ui/notifications/critical')
        .then(function(r) {{ return r.json(); }})
        .then(function(data) {{
          if (data && data.count > 0 && data.recent && data.recent.length > 0) {{
            var el = document.getElementById('notifications-toast');
            el.style.display = 'block';
            el.style.background = '#fef2f2';
            el.style.border = '1px solid #dc2626';
            el.style.borderRadius = '8px';
            el.style.padding = '12px';
            el.innerHTML = '<strong>⚠️ Критические ошибки (' + data.count + ')</strong><br><small>' + (data.recent[0].endpoint || '') + ' ' + (data.recent[0].status_code || '') + '</small>';
          }}
        }})
        .catch(function() {{}});
      setTimeout(notificationPoll, 30000);
    }})();
    </script>
    """
    return _layout(request, "Админ панель – обзор", body)


@router.post("/test-url")
async def test_url_action(request: Request, url: str = Form(...)):
    """Ручная проверка URL через админку (тест анализа)."""
    try:
        result = await analysis_service.analyze_url(url.strip(), use_external_apis=True, ignore_database=False)
        safe = result.get("safe")
        threat = result.get("threat_type") or "—"
        source = result.get("source") or "—"
        if safe is True:
            msg = f"✅ URL безопасен. Источник: {source}"
        elif safe is False:
            msg = f"⚠️ Угроза: {threat}. Источник: {source}"
        else:
            msg = f"❓ Результат неопределён. Источник: {source}"
    except Exception as e:
        msg = f"❌ Ошибка: {str(e)}"
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=prefix + ("/admin/ui" if not prefix.endswith("/") else "admin/ui"), status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=15)
    return redirect


@router.get("/notifications/critical")
async def notifications_critical(request: Request):
    """Критические ошибки (5xx) для уведомлений в дашборде."""
    recent = db_manager.get_critical_errors_count(10)
    return {"count": len(recent), "recent": recent}


@router.get("/export/keys")
async def export_keys_csv(request: Request):
    """Экспорт ключей API в CSV."""
    keys = []
    try:
        with db_manager._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT api_key, name, is_active, access_level, rate_limit_daily, rate_limit_hourly,
                       requests_total, requests_today, requests_hour, created_at, last_used, expires_at
                FROM api_keys ORDER BY created_at DESC
            """)
            keys = [dict(row) for row in cur.fetchall()]
    except Exception:
        pass
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["api_key", "name", "is_active", "access_level", "rate_limit_daily", "rate_limit_hourly", "requests_total", "requests_today", "requests_hour", "created_at", "last_used", "expires_at"])
    for k in keys:
        writer.writerow([k.get("api_key"), k.get("name"), k.get("is_active"), k.get("access_level"), k.get("rate_limit_daily"), k.get("rate_limit_hourly"), k.get("requests_total"), k.get("requests_today"), k.get("requests_hour"), k.get("created_at"), k.get("last_used"), k.get("expires_at")])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=api_keys.csv"})


@router.get("/export/reviews")
async def export_reviews_csv(request: Request):
    """Экспорт отзывов в CSV."""
    reviews_list = db_manager.get_all_reviews(limit=5000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "rating", "text", "extension_version", "created_at", "user_id", "username", "email", "device_id"])
    for r in reviews_list:
        writer.writerow([r.get("id"), r.get("rating"), (r.get("text") or "")[:500], r.get("extension_version"), r.get("created_at"), r.get("user_id"), r.get("username"), r.get("email"), r.get("device_id")])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=reviews.csv"})


@router.get("/export/logs")
async def export_logs_csv(request: Request, from_date: Optional[str] = None, to_date: Optional[str] = None):
    """Выгрузка логов за период в CSV (из request_logs, если есть; иначе из logs)."""
    logs = db_manager.get_all_logs()
    if from_date or to_date:
        try:
            from datetime import datetime as dt
            filtered = []
            for row in logs:
                ts = row.get("created_at") or row.get("timestamp") or ""
                if not ts:
                    continue
                if from_date and str(ts)[:10] < from_date:
                    continue
                if to_date and str(ts)[:10] > to_date:
                    continue
                filtered.append(row)
            logs = filtered
        except Exception:
            pass
    output = io.StringIO()
    writer = csv.writer(output)
    cols = ["endpoint", "method", "status_code", "response_time_ms", "client_ip", "api_key_hash", "created_at"]
    writer.writerow(cols)
    for row in logs[:10000]:
        writer.writerow([row.get(c) for c in cols])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=logs.csv"})


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
    toggle_action = _p(request, "admin/ui/keys/toggle-active")
    bulk_action = _p(request, "admin/ui/keys/bulk")
    import_action = _p(request, "admin/ui/keys/import-csv")
    export_keys_url = _p(request, "admin/ui/export/keys")
    rows = "".join([
        (
            f"<tr><td><input type=\"checkbox\" name=\"api_key\" value=\"{html.escape(k['api_key'])}\" form=\"bulk-form\"/></td>"
            f"<td><code>{k['api_key']}</code></td><td>{k['name']}</td><td>{'да' if k['is_active'] else 'нет'}</td>"
            f"<td><span class=\"badge-{k.get('access_level', 'basic')}\">{k.get('access_level', 'basic')}</span></td>"
            f"<td>{k['username'] if k['username'] else free_account_html}</td>"
            f"<td>{k['email'] or '-'}</td>"
            f"<td>{'***' if k['password_hash'] else '-'}</td>"
            f"<td>{k['rate_limit_daily']}/{k['rate_limit_hourly']}</td>"
            f"<td>{k['requests_today']}/{k['requests_hour']}</td>"
            f"<td>{k['requests_total']}</td>"
            f"<td class=\"muted\">{k['last_used']}</td><td class=\"muted\">{k['expires_at'] or '-'}</td>"
            f"<td><span style=\"color: #059669; font-weight: 500;\">{format_time_remaining(k['expires_at'])}</span></td>"
            f"<td><form method=\"post\" action=\"{toggle_action}\" style=\"display:inline;\"><input type=\"hidden\" name=\"api_key\" value=\"{html.escape(k['api_key'])}\"/><input type=\"hidden\" name=\"active\" value=\"{'0' if k['is_active'] else '1'}\"/><button type=\"submit\" style=\"padding:4px 8px;font-size:12px;background:{'#dc2626' if k['is_active'] else '#059669'};\">{'Заблокировать' if k['is_active'] else 'Разблокировать'}</button></form></td></tr>"
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
      <form method="post" action="{_p(request, 'admin/ui/keys/extend')}">
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
      <h2>Массовые операции</h2>
      <form id="bulk-form" method="post" action="{bulk_action}" style="display:grid;gap:8px;grid-template-columns:auto 1fr auto auto;">
        <label style="grid-column:1;">Выберите ключи выше, затем:</label>
        <select name="action" style="grid-column:2;">
          <option value="block">Заблокировать выбранные</option>
          <option value="unblock">Разблокировать выбранные</option>
          <option value="extend">Продлить выбранные</option>
        </select>
        <input type="number" name="extend_days" value="30" min="1" placeholder="Дней (для продления)" style="grid-column:3;" />
        <button type="submit" style="grid-column:4;">Применить</button>
      </form>
    </div>
    <div class="card">
      <h2>Импорт ключей из CSV</h2>
      <p class="muted" style="font-size:12px;">Колонки: name, description, access_level, expires_days, daily_limit, hourly_limit (опционально: api_key для указания своего ключа)</p>
      <form method="post" action="{import_action}" enctype="multipart/form-data" style="display:grid;gap:8px;">
        <input type="file" name="file" accept=".csv" required />
        <button type="submit">Импорт CSV</button>
      </form>
    </div>
    <div class="card">
      <h2>Список ключей</h2>
      <p><a href="{export_keys_url}">📥 Экспорт в CSV</a></p>
      <div style="overflow:auto">
        <table>
          <thead><tr><th><input type="checkbox" id="select-all-keys" title="Выбрать все"/></th><th>Ключ</th><th>Имя</th><th>Активен</th><th>Уровень</th><th>Username</th><th>Email</th><th>Пароль</th><th>Лимиты (день/час)</th><th>Запросы (сегодня/час)</th><th>Всего</th><th>Последнее использование</th><th>Истекает</th><th>Осталось</th><th>Действие</th></tr></thead>
          <tbody>{rows or '<tr><td colspan=15 class="muted">Ключей пока нет</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <script>
    document.getElementById('select-all-keys') && document.getElementById('select-all-keys').addEventListener('change', function() {{
      var cbs = document.querySelectorAll('tbody input[name=api_key][type=checkbox]');
      cbs.forEach(function(cb) {{ cb.checked = this.checked; }}, this);
    }});
    </script>
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


@router.post("/keys/toggle-active")
async def toggle_key_active_action(
    request: Request,
    api_key: str = Form(...),
    active: str = Form("1"),
):
    is_active = active.strip() == "1"
    ok = db_manager.set_api_key_active(api_key, is_active)
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/keys" if not prefix.endswith('/') else "admin/ui/keys")), status_code=303)
    msg = quote("Ключ разблокирован" if (ok and is_active) else ("Ключ заблокирован" if ok else "Ошибка"))
    redirect.set_cookie("flash", msg, max_age=10)
    return redirect


@router.post("/keys/bulk")
async def keys_bulk_action(request: Request):
    """Массовые операции: блокировка, разблокировка, продление выбранных ключей."""
    form = await request.form()
    action = form.get("action", "block")
    extend_days = int(form.get("extend_days", 30) or 30)
    keys = form.getlist("api_key")
    if not keys:
        msg = quote("Выберите хотя бы один ключ")
    else:
        done = 0
        for key in keys:
            if action == "block":
                if db_manager.set_api_key_active(key, False):
                    done += 1
            elif action == "unblock":
                if db_manager.set_api_key_active(key, True):
                    done += 1
            elif action == "extend":
                if db_manager.extend_api_key(key, extend_days):
                    done += 1
        msg = quote(f"Обработано ключей: {done} из {len(keys)}")
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/keys" if not prefix.endswith('/') else "admin/ui/keys")), status_code=303)
    redirect.set_cookie("flash", msg, max_age=10)
    return redirect


@router.post("/keys/import-csv")
async def keys_import_csv_action(request: Request, file: UploadFile = Form(...)):
    """Импорт API ключей из CSV (колонки: name, description, access_level, expires_days, daily_limit, hourly_limit)."""
    created = 0
    errors = 0
    try:
        content = (await file.read()).decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            name = (row.get("name") or row.get("Name") or "").strip()
            if not name:
                errors += 1
                continue
            desc = (row.get("description") or row.get("Description") or "").strip()
            access = (row.get("access_level") or "premium").strip() or "premium"
            days = int(row.get("expires_days") or row.get("expires_days") or "30")
            daily = int(row.get("daily_limit") or row.get("rate_limit_daily") or "10000")
            hourly = int(row.get("hourly_limit") or row.get("rate_limit_hourly") or "1000")
            key = db_manager.create_api_key(name, desc, access, daily, hourly, days)
            if key:
                created += 1
            else:
                errors += 1
    except Exception as e:
        logging.getLogger(__name__).error(f"Import keys CSV error: {e}")
        created, errors = 0, 1
    prefix = request.scope.get("root_path", "")
    redirect = RedirectResponse(url=(prefix + ("/admin/ui/keys" if not prefix.endswith('/') else "admin/ui/keys")), status_code=303)
    redirect.set_cookie("flash", quote(f"Импорт: создано {created}, ошибок {errors}"), max_age=10)
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


@router.get("/reviews", response_class=HTMLResponse)
async def reviews_page(request: Request):
    """Страница отзывов пользователей (из расширения)."""
    try:
        reviews_list = db_manager.get_all_reviews(limit=500)
        review_stats = db_manager.get_review_stats()
    except Exception as e:
        logging.getLogger(__name__).error(f"Get reviews error: {e}")
        reviews_list = []
        review_stats = {"total": 0, "average_rating": 0.0, "rating_distribution": {}}

    total = review_stats.get("total", 0)
    avg_rating = review_stats.get("average_rating", 0.0)
    dist = review_stats.get("rating_distribution", {})

    rows = "".join([
        f"<tr><td>{r.get('id')}</td><td>{'★' * (r.get('rating') or 0)}{'☆' * (5 - (r.get('rating') or 0))}</td>"
        f"<td>{ (r.get('text') or '-')[:200] }{'...' if (r.get('text') or '') and len(r.get('text', '')) > 200 else ''}</td>"
        f"<td>{r.get('username') or r.get('device_id') or '-'}</td><td>{r.get('email') or '-'}</td>"
        f"<td>{r.get('extension_version') or '-'}</td><td class=\"muted\">{r.get('created_at')}</td></tr>"
        for r in reviews_list
    ])

    body = f"""
    <div class="card">
      <h1>Отзывы пользователей</h1>
      <p class="muted">Отзывы из браузерного расширения AVQON · <a href="{_p(request, 'admin/ui/export/reviews')}">Экспорт в CSV</a></p>
    </div>
    <div class="row">
      <div class="card col">
        <h2>Статистика</h2>
        <div><strong>Всего отзывов:</strong> {total}</div>
        <div><strong>Средняя оценка:</strong> {avg_rating:.1f}</div>
        <div><strong>По оценкам:</strong> {', '.join([f'{k}★: {v}' for k, v in sorted(dist.items(), reverse=True)]) or '-'}</div>
      </div>
    </div>
    <div class="card">
      <h2>Список отзывов</h2>
      <div style="max-height:600px;overflow:auto">
        <table>
          <thead><tr><th>ID</th><th>Оценка</th><th>Текст</th><th>Пользователь / device</th><th>Email</th><th>Версия расширения</th><th>Дата</th></tr></thead>
          <tbody>{rows or '<tr><td colspan=7 class="muted">Отзывов пока нет</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    """
    return _layout(request, "Админ панель – Отзывы", body)


@router.get("/crowd-reports", response_class=HTMLResponse)
async def crowd_reports_page(
    request: Request,
    status: str = "all",
    period: str = "all",
):
    """
    Страница модерации крауд‑репортов (плоский список отдельных отчётов).
    Фильтры:
    - статус: all | pending | approved | rejected
    - период: all | today | week | month
    """
    if not db_manager:
        body = """
        <div class="card">
          <h1>Крауд-репорты</h1>
          <p class="muted">База данных недоступна, модерация временно невозможна.</p>
        </div>
        """
        return _layout(request, "Админ панель – крауд-репорты", body)

    status_normalized = (status or "all").strip().lower()
    if status_normalized not in ("all", "pending", "approved", "rejected"):
        status_normalized = "all"

    period_normalized = (period or "all").strip().lower()
    now = datetime.utcnow()
    date_from = None
    date_to = None
    if period_normalized == "today":
        date_from = datetime(now.year, now.month, now.day)
    elif period_normalized == "week":
        date_from = now - timedelta(days=7)
    elif period_normalized == "month":
        date_from = now - timedelta(days=30)

    # Получаем список репортов и количество ожидающих модерации
    reports = db_manager.list_crowd_reports(
        status=None if status_normalized == "all" else status_normalized,
        date_from=date_from,
        date_to=date_to,
        limit=300,
        offset=0,
    )
    pending_count = db_manager.count_crowd_reports(status="pending")

    def row_status(row: dict) -> str:
        if row.get("confirmed"):
            return "approved"
        if row.get("rejected"):
            return "rejected"
        return "pending"

    status_badge = {
        "pending": '<span class="badge-basic">pending</span>',
        "approved": '<span class="badge-premium">approved</span>',
        "rejected": '<span class="badge-basic" style="background:#fee2e2;color:#b91c1c;">rejected</span>',
    }

    rows = []
    for r in reports:
        st = row_status(r)
        st_html = status_badge.get(st, status_badge["pending"])
        threat = (r.get("threat_type") or "—").lower()
        if threat == "other":
            threat = "other"
        comment = (r.get("comment") or "").strip()
        if len(comment) > 120:
            comment_display = html.escape(comment[:120]) + "…"
        else:
            comment_display = html.escape(comment) or "—"
        url = r.get("url") or ""
        url_display = html.escape(url[:80]) + ("…" if len(url) > 80 else "")
        device_id = (r.get("device_id") or "").strip()
        device_short = device_id[:8] + "…" if device_id and len(device_id) > 8 else device_id or "—"
        created_at = r.get("created_at") or "-"

        approve_action = _p(request, f"admin/ui/crowd-reports/{r.get('id')}/approve")
        reject_action = _p(request, f"admin/ui/crowd-reports/{r.get('id')}/reject")

        rows.append(
            f"<tr>"
            f"<td>{r.get('id')}</td>"
            f"<td><a href=\"{html.escape(url)}\" target=\"_blank\" rel=\"noopener\">{url_display}</a></td>"
            f"<td>{html.escape(threat) if threat != '—' else '—'}</td>"
            f"<td>{comment_display}</td>"
            f"<td>{html.escape(device_short)}</td>"
            f"<td class=\"muted\">{created_at}</td>"
            f"<td>{st_html}</td>"
            f"<td>"
            f"<form method=\"post\" action=\"{approve_action}\" style=\"display:inline;margin-right:4px;\">"
            f"<button type=\"submit\" style=\"padding:4px 8px;font-size:12px;background:#059669;color:#fff;border-radius:4px;\">Одобрить</button>"
            f"</form>"
            f"<form method=\"post\" action=\"{reject_action}\" style=\"display:inline;\">"
            f"<button type=\"submit\" style=\"padding:4px 8px;font-size:12px;background:#dc2626;color:#fff;border-radius:4px;\">Отклонить</button>"
            f"</form>"
            f"</td>"
            f"</tr>"
        )

    rows_html = "".join(rows) if rows else '<tr><td colspan="8" class="muted">Репортов пока нет</td></tr>'

    # Выпадающие фильтры
    def opt(val: str, label: str, cur: str) -> str:
        sel = " selected" if cur == val else ""
        return f'<option value="{val}"{sel}>{label}</option>'

    status_filter_html = "".join(
        [
            opt("all", "Все", status_normalized),
            opt("pending", "Только ожидающие", status_normalized),
            opt("approved", "Только одобренные", status_normalized),
            opt("rejected", "Только отклонённые", status_normalized),
        ]
    )
    period_filter_html = "".join(
        [
            opt("all", "За всё время", period_normalized),
            opt("today", "Сегодня", period_normalized),
            opt("week", "Последние 7 дней", period_normalized),
            opt("month", "Последние 30 дней", period_normalized),
        ]
    )

    body = f"""
    <div class="card">
      <h1>Крауд-репорты</h1>
      <p class="muted">Отчёты пользователей о подозрительных и вредоносных сайтах.</p>
      <p class="muted">Ожидает модерации: <strong>{pending_count}</strong></p>
    </div>
    <div class="card">
      <h2>Фильтры</h2>
      <form method="get" action="{_p(request, 'admin/ui/crowd-reports')}" style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;">
        <label>Статус
          <select name="status" style="margin-left:4px;min-width:140px;">
            {status_filter_html}
          </select>
        </label>
        <label>Период
          <select name="period" style="margin-left:4px;min-width:160px;">
            {period_filter_html}
          </select>
        </label>
        <button type="submit">Применить</button>
      </form>
    </div>
    <div class="card">
      <h2>Список крауд-репортов</h2>
      <div style="max-height:650px;overflow:auto;">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>URL</th>
              <th>Тип угрозы</th>
              <th>Комментарий</th>
              <th>Device ID</th>
              <th>Дата</th>
              <th>Статус</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
      </div>
    </div>
    """
    return _layout(request, "Админ панель – крауд-репорты", body)


@router.post("/crowd-reports/{report_id}/approve")
async def crowd_report_approve_action(
    request: Request,
    report_id: int,
):
    """Одобрение отдельного крауд‑репорта через HTML‑форму."""
    if not db_manager:
        raise HTTPException(status_code=503, detail="Database unavailable")
    updated = db_manager.moderate_crowd_report(report_id, approve=True)
    msg = "Репорт одобрен, URL добавлен в угрозы" if updated else "Репорт не найден"
    prefix = request.scope.get("root_path", "")
    # Сохраняем исходные query‑параметры (status, period)
    qs = request.url.query
    base = prefix + ("/admin/ui/crowd-reports" if not prefix.endswith("/") else "admin/ui/crowd-reports")
    url = f"{base}?{qs}" if qs else base
    redirect = RedirectResponse(url=url, status_code=303)
    redirect.set_cookie("flash", quote(msg), max_age=10)
    return redirect


@router.post("/crowd-reports/{report_id}/reject")
async def crowd_report_reject_action(
    request: Request,
    report_id: int,
):
    """Отклонение отдельного крауд‑репорта через HTML‑форму."""
    if not db_manager:
        raise HTTPException(status_code=503, detail="Database unavailable")
    updated = db_manager.moderate_crowd_report(report_id, approve=False)
    msg = "Репорт отклонён" if updated else "Репорт не найден"
    prefix = request.scope.get("root_path", "")
    qs = request.url.query
    base = prefix + ("/admin/ui/crowd-reports" if not prefix.endswith("/") else "admin/ui/crowd-reports")
    url = f"{base}?{qs}" if qs else base
    redirect = RedirectResponse(url=url, status_code=303)
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
      <p class="muted">Последние события API из таблицы logs · <a href="{_p(request, 'admin/ui/export/logs')}">Экспорт в CSV</a></p>
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
        cache_stats = db_manager.get_cache_stats()
        top_domains = db_manager.get_top_cached_domains(20)
    except Exception as e:
        logging.getLogger(__name__).error(f"Get cache entries error: {e}")
        whitelist_entries = []
        blacklist_entries = []
        cache_stats = {}
        top_domains = []
    total_hits = (cache_stats.get("whitelist_hits") or 0) + (cache_stats.get("blacklist_hits") or 0)
    total_entries = (cache_stats.get("whitelist_entries") or 0) + (cache_stats.get("blacklist_entries") or 0)
    hit_ratio = f"{(total_hits / (total_entries or 1)):.1f}" if total_entries else "0"
    cache_bytes = cache_stats.get("bytes_estimated", 0)
    cache_size_str = f"{(cache_bytes / (1024*1024)):.2f} МБ" if cache_bytes else "—"
    top_domain_rows = "".join([
        f"<tr><td>{html.escape(d['domain'][:80])}</td><td>{d['hits']}</td></tr>" for d in top_domains
    ])
    
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
          <div><strong>Хитов кэша:</strong> {total_hits}</div>
          <div><strong>Hit ratio (эффективность):</strong> {hit_ratio}</div>
          <div><strong>Размер (оценка):</strong> {cache_size_str}</div>
        </div>
      </div>
      <div class="card col">
        <h2>Топ закэшированных доменов</h2>
        <div style="max-height:180px;overflow:auto">
          <table><thead><tr><th>Домен</th><th>Хитов</th></tr></thead><tbody>{top_domain_rows or '<tr><td colspan=2 class="muted">Нет данных</td></tr>'}</tbody></table>
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
            <li>Откройте расширение AVQON</li>
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


