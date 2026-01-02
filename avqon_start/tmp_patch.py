from pathlib import Path

path = Path('sidepanel.html')
data = path.read_text(encoding='utf-8')

old_block = """          <section id="view-home">
            <div class="shield-card">
            <div class="shield-head">
              <div>
                <h2 id="status">Готово</h2>
                <p class="muted" id="toggle-subtitle">Сканирование ссылок и загрузок</p>
              </div>
              <span class="badge ready">ON</span>
            </div>
            <div class="connection" id="connection-status">
                <span class="status-dot checking" id="status-dot"></span>
                <span id="connection-text">Проверка подключения...</span>
              </div>
            </div>

"""

new_block = """          <section id="view-home">
            <div class="shield-card">
              <div class="connection-block">
                <p class="eyebrow" style="letter-spacing:0.1em;">Подключение</p>
                <div class="connection" id="connection-status">
                  <span class="status-dot checking" id="status-dot"></span>
                  <span id="connection-text">Проверка подключения...</span>
                </div>
              </div>
              <div class="verdict-block">
                <p class="eyebrow" style="letter-spacing:0.1em;">Вердикт</p>
                <div class="verdict-row">
                  <h2 id="status">Готово</h2>
                  <div class="shield-icon">
                    <svg viewBox="0 0 24 24">
                      <path fill="#2563EB" d="M12 2l8 4v6c0 5.25-3.4 10.09-8 11C7.4 22.09 4 17.25 4 12В6л8-4zm0 2.18L6 6.67v5.33c0 4.17 2.6 8.13 6 8.97 3.4-.84 6-4.8 6-8.97В6.67л-6-2.49zm1 4.82v6h-2v-6h2zm0-2v2h-2В7h2z"/>
                    </svg>
                  </div>
                </div>
                <p class="muted" id="toggle-subtitle">Сканирование ссылок и загрузок</p>
              </div>
            </div>

"""

if old_block not in data:
  raise SystemExit('Shield card block not found')

data = data.replace(old_block, new_block, 1)

override_css = """    <style>
      .shield-card {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }

      .connection-block {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }

      .verdict-block {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .verdict-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }

      .verdict-row h2 {
        margin: 0;
        font-size: 22px;
      }

      .result-section {
        border-top: 1px solid rgba(255,255,255,0.08);
        padding-top: 12px;
        font-size: 13px;
        color: var(--muted);
        word-break: break-word;
      }

      .kv {
        grid-template-columns: minmax(0, 110px) minmax(0, 1fr);
      }

      .kv .k,
      .kv .v {
        word-break: break-word;
        overflow-wrap: anywhere;
      }
    </style>
  </head>
"""

marker = '  </head>\n'
if marker not in data:
  raise SystemExit('Head marker not found')

data = data.replace(marker, override_css, 1)
path.write_text(data, encoding='utf-8')

