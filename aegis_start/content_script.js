// content_script.js
// Enhanced content script with hover analysis and visual indicators

let tooltip = null;
let hoverTimeout = null;
let currentHoveredLink = null;
let currentHoveredLinkNormalized = null;
let lastMouseX = 0;
let lastMouseY = 0;
let hoverTheme = 'classic'; // 'classic' | 'dot' | 'linkcolor'
let hoverListenersReady = false;
const DEFAULTS_CS = { antivirusEnabled: true, hoverScan: true };
let lastHoverResult = null;
// Кэш результатов hover анализа
const hoverResultCache = new Map();
const hoverPalette = {
  safe: '#10B981',
  suspicious: '#F59E0B',
  malicious: '#EF4444',
  unknown: '#94A3B8',
  info: '#2563EB'
};

function isClassicHover() {
  return hoverTheme === 'classic';
}

function ensureTooltipForTheme() {
  if (isClassicHover()) {
    if (!tooltip) {
      createHoverTooltip();
    }
    if (tooltip) {
      tooltip.style.display = 'block';
    }
  } else if (tooltip) {
    hideTooltip(tooltip);
    tooltip.style.display = 'none';
  }
}

function injectHoverStyles() {
  if (document.getElementById('aegis-hover-styles')) return;
  const style = document.createElement('style');
  style.id = 'aegis-hover-styles';
  style.textContent = `
    .aegis-hover-tooltip {
      position: fixed;
      background: #0f172a;
      color: #E2E8F0;
      padding: 12px 14px;
      border-radius: 10px;
      font-size: 13px;
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      border: 1px solid rgba(15,23,42,0.45);
      box-shadow: 0 14px 32px rgba(15,23,42,0.45);
      z-index: 10000;
      pointer-events: none;
      opacity: 0;
      transition: opacity 0.2s ease;
      max-width: 260px;
      line-height: 1.4;
    }
    .aegis-hover-tooltip[data-variant="safe"] { border-color: rgba(16,185,129,0.4); box-shadow: 0 14px 32px rgba(16,185,129,0.2); }
    .aegis-hover-tooltip[data-variant="malicious"] { border-color: rgba(239,68,68,0.5); box-shadow: 0 14px 32px rgba(239,68,68,0.25); }
    .aegis-hover-tooltip[data-variant="suspicious"] { border-color: rgba(245,158,11,0.45); box-shadow: 0 14px 32px rgba(245,158,11,0.25); }
    .aegis-hover-tooltip[data-variant="unknown"] { border-color: rgba(148,163,184,0.5); }
    .aegis-hover-dot {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      margin-left: 6px;
      vertical-align: middle;
      box-shadow: 0 0 0 2px rgba(255,255,255,0.4);
    }
    .aegis-hover-dot[data-variant="safe"] { background: #10B981; box-shadow: 0 0 0 2px rgba(16,185,129,0.25); }
    .aegis-hover-dot[data-variant="malicious"] { background: #EF4444; box-shadow: 0 0 0 2px rgba(239,68,68,0.25); }
    .aegis-hover-dot[data-variant="suspicious"] { background: #F59E0B; box-shadow: 0 0 0 2px rgba(245,158,11,0.25); }
    .aegis-hover-dot[data-variant="unknown"] { background: #94A3B8; box-shadow: 0 0 0 2px rgba(148,163,184,0.25); }
    .aegis-link-safe { color: #10B981 !important; }
    .aegis-link-malicious { color: #EF4444 !important; }
    .aegis-link-suspicious { color: #F59E0B !important; }
    .aegis-link-unknown { color: #94A3B8 !important; }
  `;
  document.documentElement.appendChild(style);
}

try { injectHoverStyles(); } catch (_) {}

// КРИТИЧНО: Сохраняем ссылки на обработчики для их удаления
let hoverMouseOverHandler = null;
let hoverMouseOutHandler = null;
let hoverMouseMoveHandler = null;
let hoverClickHandler = null;
let lastHoverCheck = Date.now();
let hoverCheckCount = 0;

// Безопасное экранирование строк для вставки в innerHTML
function escapeHtml(value) {
  const str = String(value == null ? '' : value);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeUrlForCompare(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    parsed.hash = '';
    return parsed.toString();
  } catch (_) {
    return url;
  }
}

function formatFileSize(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value <= 0) return '';
  if (value < 1024) return `${value} Б`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} КБ`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} МБ`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(1)} ГБ`;
}

function determineVerdict(result) {
  if (!result) {
    console.log('[Aegis Content] determineVerdict: no result, returning unknown');
    return 'unknown';
  }
  
  console.log('[Aegis Content] determineVerdict input:', {
    safe: result.safe,
    threat_type: result.threat_type,
    result: result.result,
    verdict: result.verdict,
    source: result.source
  });
  
  // КРИТИЧНО: Приоритет проверки - сначала safe, потом threat_type
  if (result.safe === false) {
    console.log('[Aegis Content] determineVerdict: safe === false, returning malicious');
    return 'malicious';
  }
  if (result.safe === true) {
    console.log('[Aegis Content] determineVerdict: safe === true, returning safe');
    return 'safe';
  }
  // Если есть threat_type, значит есть угроза
  if (result.threat_type) {
    console.log('[Aegis Content] determineVerdict: threat_type present, returning malicious');
    return 'malicious';
  }
  
  const verdictCandidate = (result.result || result.verdict || '').toString().toLowerCase();
  let verdict = verdictCandidate || 'unknown';

  if (result.source === 'error') {
    const msg = String(result.details || '').toLowerCase();
    if (msg.includes('failed to fetch') || msg.includes('network') || msg.includes('timeout') || msg.includes('превышено время ожидания')) {
      verdict = 'suspicious';
    }
  }

  if (!verdict || verdict === 'null' || verdict === 'undefined') {
    verdict = 'unknown';
  }
  
  console.log('[Aegis Content] determineVerdict final:', verdict);
  return verdict;
}

// Логирование жизненного цикла контент-скрипта
try {
  console.debug('[Aegis] Hover content script LOADED');
  window.addEventListener('beforeunload', () => {
    try { console.debug('[Aegis] Hover content script UNLOADING'); } catch(_) {}
  });
} catch(_) {}

// КРИТИЧНО: Долгоживущее соединение для поддержания активности Service Worker
// Chrome останавливает Service Worker через 5 минут неактивности
// Долгоживущее соединение предотвращает остановку
let keepAlivePort = null;
let lastKeepAliveAck = Date.now();

function setupKeepAlive() {
  try {
    // Закрываем старое соединение, если есть
    if (keepAlivePort) {
      try {
        keepAlivePort.disconnect();
      } catch (e) {
        // Игнорируем ошибки закрытия
      }
      keepAlivePort = null;
    }
    
    // Создаем новое соединение
    keepAlivePort = chrome.runtime.connect({ name: "keepAlive" });
    
    // Обработчик отключения - переподключаемся
    keepAlivePort.onDisconnect.addListener(() => {
      keepAlivePort = null;
      try { console.warn('[Aegis] keepAlive port DISCONNECTED. Reconnecting...'); } catch(_) {}
      // Переподключаемся через 1 секунду
      setTimeout(setupKeepAlive, 1000);
    });
    
    // Обработчик сообщений от background
    keepAlivePort.onMessage.addListener((msg) => {
      if (msg.type === 'keepAlive_connected') {
        // Соединение установлено успешно
        lastKeepAliveAck = Date.now();
      }
      if (msg.type === 'hover_pong') {
        lastKeepAliveAck = Date.now();
      }
    });
  } catch (e) {
    // При ошибке переподключаемся через 2 секунды
    setTimeout(setupKeepAlive, 2000);
  }
}

// Устанавливаем keep-alive соединение при загрузке скрипта
setupKeepAlive();

// Периодический health-check для hover механизма
let hoverHealthIntervalId = null;
function startHoverHealthCheck() {
  if (hoverHealthIntervalId) {
    clearInterval(hoverHealthIntervalId);
    hoverHealthIntervalId = null;
  }
  hoverHealthIntervalId = setInterval(async () => {
    const timeSinceLastCheck = Date.now() - lastHoverCheck;
    
    // КРИТИЧНО: Если listeners не работают - переинициализируем
    if (!hoverListenersReady || timeSinceLastCheck > 120000) { // 2 минуты без активности
      try { 
        console.warn(`[Aegis] Hover listeners inactive (${Math.round(timeSinceLastCheck/1000)}s). Re-initializing...`); 
      } catch(_) {}
      cleanupHoverListeners();
      setupHoverListeners();
    }
    
    // Если порт неактивен — пытаемся восстановить
    if (!keepAlivePort) {
      try { console.warn('[Aegis] keepAlive port missing. Re-initializing...'); } catch(_) {}
      setupKeepAlive();
      return;
    }
    // Отправляем ping в background и ждем ответ (через onMessage ack)
    try {
      chrome.runtime.sendMessage({ type: 'hover_ping', ts: Date.now() }, (resp) => {
        if (resp && resp.ok) {
          lastKeepAliveAck = Date.now();
        } else {
          try { console.warn('[Aegis] No ping response from background'); } catch(_) {}
        }
      });
    } catch (e) {
      try { console.warn('[Aegis] Ping error:', e); } catch(_) {}
    }
    // Если долго нет ack — переинициализируем порт
    const sinceAck = Date.now() - lastKeepAliveAck;
    if (sinceAck > 30000) { // 30 секунд без ack
      try { console.warn('[Aegis] No hover ACK >30s. Re-initializing keepAlive...'); } catch(_) {}
      try {
        if (keepAlivePort) {
          try { keepAlivePort.disconnect(); } catch(_) {}
        }
      } catch(_) {}
      keepAlivePort = null;
      setupKeepAlive();
    }
  }, 10000); // проверка каждые 10 секунд
}
startHoverHealthCheck();

// === HOVER THEME SUPPORT ===
// Load theme from storage
try {
  chrome.storage.sync.get({ hoverTheme: 'classic' }, (cfg) => {
    if (cfg && cfg.hoverTheme) hoverTheme = cfg.hoverTheme;
    ensureTooltipForTheme();
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'sync' && changes.hoverTheme) {
      hoverTheme = changes.hoverTheme.newValue || 'classic';
      ensureTooltipForTheme();
    }
  });
} catch(_) {}

// Utility: apply visual indicator based on theme
function applyHoverTheme(linkEl, verdict) {
  if (!linkEl) return;
  // Cleanup previous artifacts
  cleanupHoverTheme(linkEl);
  if (hoverTheme === 'dot') {
    // Add small indicator next to link (temporary)
    const indicator = document.createElement('span');
    indicator.className = 'aegis-hover-dot';
    indicator.setAttribute('data-variant', verdict || 'unknown');
    indicator.setAttribute('data-aegis-hover-artifact', '1');
    linkEl.insertAdjacentElement('afterend', indicator);
  } else if (hoverTheme === 'linkcolor') {
    // Temporarily color the link
    linkEl.setAttribute('data-aegis-prev-color', linkEl.style.color || '');
    linkEl.classList.remove('aegis-link-safe','aegis-link-malicious','aegis-link-suspicious','aegis-link-unknown');
    const cls = verdict === 'malicious' ? 'aegis-link-malicious'
      : verdict === 'suspicious' ? 'aegis-link-suspicious'
      : verdict === 'clean' || verdict === 'safe' ? 'aegis-link-safe'
      : 'aegis-link-unknown';
    linkEl.classList.add(cls);
    linkEl.setAttribute('data-aegis-hover-artifact', '1');
  }
}

function cleanupHoverTheme(linkEl) {
  if (!linkEl) return;
  // Remove dot indicator next to link
  const nextEl = linkEl.nextElementSibling;
  if (nextEl && nextEl.getAttribute && nextEl.getAttribute('data-aegis-hover-artifact') === '1') {
    try { nextEl.remove(); } catch(_) {}
  }
  // Также удалим любые последующие маркеры-артефакты (на случай изменения темы на лету)
  try {
    let sibling = linkEl.nextElementSibling;
    let guard = 0;
    while (sibling && guard < 3) {
      if (sibling.getAttribute && sibling.getAttribute('data-aegis-hover-artifact') === '1') {
        const toRemove = sibling;
        sibling = sibling.nextElementSibling;
        toRemove.remove();
        continue;
      }
      sibling = sibling.nextElementSibling;
      guard++;
    }
  } catch(_) {}
  // Restore link color if changed
  if (linkEl.getAttribute && linkEl.getAttribute('data-aegis-hover-artifact') === '1') {
    const prev = linkEl.getAttribute('data-aegis-prev-color') || '';
    if (prev) {
      linkEl.style.color = prev;
    }
    linkEl.classList.remove('aegis-link-safe','aegis-link-malicious','aegis-link-suspicious','aegis-link-unknown');
    linkEl.removeAttribute('data-aegis-prev-color');
    linkEl.removeAttribute('data-aegis-hover-artifact');
  }
}

// Create hover analysis tooltip
function createHoverTooltip() {
  if (tooltip) return tooltip;
  
  tooltip = document.createElement('div');
  tooltip.id = 'safebrowse-tooltip';
  tooltip.className = 'aegis-hover-tooltip';
  document.body.appendChild(tooltip);
  return tooltip;
}

// Update tooltip position and content
function updateTooltip(tooltip, x, y, content, type = 'info') {
  tooltip.innerHTML = content;
  
  tooltip.setAttribute('data-variant', type);
  const borderColor = hoverPalette[type] || hoverPalette.info;
  tooltip.style.borderColor = borderColor;
  
  // Only update position if coordinates are provided
  if (typeof x === 'number' && typeof y === 'number') {
    tooltip.style.left = x + 10 + 'px';
    tooltip.style.top = y - 30 + 'px';
  }
  tooltip.style.opacity = '1';
}

// Hide tooltip
function hideTooltip(tooltip) {
  tooltip.style.opacity = '0';
}

// Format analysis result for display - упрощенный: только Безопасно/Опасно
function formatAnalysisResult(result, url) {
  if (!result) return '<span style="color: #93a0c0;">Неизвестно</span>';
  
  const verdict = determineVerdict(result);
  
  // Упрощенный вывод: только статус
  const verdicts = {
    safe: { text: 'Безопасно', color: hoverPalette.safe },
    clean: { text: 'Безопасно', color: hoverPalette.safe },
    suspicious: { text: 'Опасно', color: hoverPalette.suspicious },
    malicious: { text: 'Опасно', color: hoverPalette.malicious },
    unknown: { text: 'Неизвестно', color: hoverPalette.unknown }
  };
  
  const info = verdicts[verdict] || verdicts.unknown;
  
  return `
    <div style="text-align: center; line-height: 1.2;">
      <div style="color: ${info.color}; font-weight: bold; font-size: 14px;">
        ${info.text}
      </div>
    </div>
  `;
}

// Initialize tooltip when DOM is ready
function initTooltip() {
  if (!isClassicHover()) return;
  if (document.body) {
    createHoverTooltip();
  } else {
    setTimeout(initTooltip, 100);
  }
}

// КРИТИЧНО: Полная очистка всех listeners перед переинициализацией
function cleanupHoverListeners() {
  try {
    if (hoverMouseOverHandler) {
      document.removeEventListener('mouseover', hoverMouseOverHandler);
      hoverMouseOverHandler = null;
    }
    if (hoverMouseOutHandler) {
      document.removeEventListener('mouseout', hoverMouseOutHandler);
      hoverMouseOutHandler = null;
    }
    if (hoverMouseMoveHandler) {
      document.removeEventListener('mousemove', hoverMouseMoveHandler);
      hoverMouseMoveHandler = null;
    }
    if (hoverClickHandler) {
      document.removeEventListener('click', hoverClickHandler, true);
      hoverClickHandler = null;
    }
    hoverListenersReady = false;
    try { console.debug('[Aegis] Hover listeners CLEANED UP'); } catch(_) {}
  } catch (e) {
    try { console.error('[Aegis] Error cleaning up listeners:', e); } catch(_) {}
  }
}

function setupHoverListeners() {
  // КРИТИЧНО: Всегда очищаем старые listeners перед добавлением новых
  cleanupHoverListeners();
  
  hoverListenersReady = true;
  hoverCheckCount++;
  lastHoverCheck = Date.now();
  try { console.debug(`[Aegis] Setting up hover listeners (check #${hoverCheckCount})`); } catch(_) {}
  
  // Enhanced link hover detection
  hoverMouseOverHandler = (e) => {
    const link = e.target.closest('a');
    if (!link || !link.href) return;
    if (!/^https?:/i.test(link.href)) return;
    
    // Check if hover analysis is enabled (не требуем ключ)
    chrome.storage.sync.get(['hoverScan','antivirusEnabled','account','apiKey'], (result) => {
      // Требуем: включена защита, включен hover, и есть аккаунт+apiKey
      // По умолчанию считаем включенными, если ключи отсутствуют
      const antivirusEnabled = result.antivirusEnabled !== false;
      const hoverScan = result.hoverScan !== false;
      const hasAccount = !!result.account;
      const hasApiKey = !!result.apiKey;
      // КРИТИЧНО: Если нет аккаунта - просто не показываем ничего, без промежуточных подсказок
      if (!antivirusEnabled || !hoverScan || !hasAccount || !hasApiKey) {
        // Скрываем тултип, если он был показан
        if (tooltip) {
          hideTooltip(tooltip);
        }
        return;
      }
      
      currentHoveredLink = link;
      currentHoveredLinkNormalized = normalizeUrlForCompare(link.href);
      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
      
      // Clear existing timeout
      if (hoverTimeout) {
        clearTimeout(hoverTimeout);
      }
      
      // Используем кэш, чтобы сразу отображать результат
      const cachedResult = hoverResultCache.get(currentHoveredLinkNormalized);
      if (cachedResult && cachedResult.timestamp && (Date.now() - cachedResult.timestamp < 300000)) { // 5 минут кэш
        // Есть кэшированный результат - показываем сразу
        lastHoverResult = cachedResult.data;
        const verdict = determineVerdict(lastHoverResult);
        const content = formatAnalysisResult(lastHoverResult, link.href);
        cleanupHoverTheme(link);
        // Применяем только выбранную тему
        if (hoverTheme === 'classic') {
          ensureTooltipForTheme();
          if (tooltip) updateTooltip(tooltip, lastMouseX, lastMouseY, content, verdict);
        } else {
          if (tooltip) hideTooltip(tooltip);
          applyHoverTheme(link, verdict);
        }
      } else {
        // Нет кэша - запрашиваем результат
        lastHoverResult = null;
        // Не показываем промежуточные статусы — только итоговый результат
        if (tooltip) {
          hideTooltip(tooltip);
        }
        
        // Send hover message to background with mouse coords
        hoverTimeout = setTimeout(() => {
          lastHoverCheck = Date.now(); // Обновляем время последней активности
          // КРИТИЧНО: sendMessage для hover_url не требует ответа, background отправляет результат через onMessage
          // Поэтому не передаем callback, чтобы избежать ошибки "message port closed"
          try {
            chrome.runtime.sendMessage({
              type: 'hover_url', 
              url: link.href,
              mouseX: lastMouseX,
              mouseY: lastMouseY
            }).catch(err => {
              // Игнорируем ошибки отправки - результат придет через onMessage
              console.debug('[Aegis] Hover message send error (ignored):', err);
            });
            
            // Таймаут для ошибки - не показываем tooltip, только визуальные индикаторы
            const timeoutId = setTimeout(() => {
              if (currentHoveredLink === link) {
                // Для классической темы показываем ошибку, для других - ничего
                if (hoverTheme === 'classic' && tooltip && tooltip.style.opacity === '1') {
                  const errorContent = formatAnalysisResult({ source: 'error', details: 'Превышено время ожидания' }, link.href);
                  updateTooltip(tooltip, lastMouseX, lastMouseY, errorContent, 'unknown');
                }
              }
            }, 5000);
            
            // Сохраняем timeout ID для очистки при получении результата
            if (currentHoveredLink === link) {
              link.dataset.aegisHoverTimeout = timeoutId;
            }
          } catch (err) {
            // Игнорируем ошибки отправки
            console.debug('[Aegis] Hover message send exception (ignored):', err);
          }
        }, 200); // Slightly faster debounce
      }
    });
  };
  document.addEventListener('mouseover', hoverMouseOverHandler);
  
  // Handle mouse leave
  hoverMouseOutHandler = (e) => {
    const link = e.target.closest && e.target.closest('a');
    if (!link || !link.href) return;
    
    // If moving within the same link, do nothing
    if (e.relatedTarget && link.contains(e.relatedTarget)) {
      return;
    }
    
    if (hoverTimeout) {
      clearTimeout(hoverTimeout);
      hoverTimeout = null;
    }
    
    // Cleanup theme artifacts on mouse out
    cleanupHoverTheme(link);
  
    if (tooltip) {
      hideTooltip(tooltip);
    }
    try { link.style.outline = ''; } catch(_) {}
    currentHoveredLink = null;
    currentHoveredLinkNormalized = null;
    lastHoverResult = null;
  };
  document.addEventListener('mouseout', hoverMouseOutHandler);
  
  // Handle mouse move to update tooltip position
  hoverMouseMoveHandler = (e) => {
    lastMouseX = e.clientX;
    lastMouseY = e.clientY;
    if (tooltip && tooltip.style.opacity === '1') {
      tooltip.style.left = lastMouseX + 10 + 'px';
      tooltip.style.top = lastMouseY - 30 + 'px';
    }
  };
  document.addEventListener('mousemove', hoverMouseMoveHandler);
  
  // Click handler for URL checking
  hoverClickHandler = (e) => {
  const a = e.target.closest && e.target.closest('a');
  if (!a || !a.href) return;
    if (!/^https?:/i.test(a.href)) return;
  chrome.runtime.sendMessage({type: 'check_url', url: a.href});
  };
  document.addEventListener('click', hoverClickHandler, true);
  
  try { console.debug('[Aegis] Hover listeners SET UP successfully'); } catch(_) {}
}

// Инициализация слушателей при загрузке
setupHoverListeners();

// КРИТИЧНО: Обработка перезагрузки content script на SPA-сайтах
// При навигации в SPA content script может перезагружаться, но DOM остается
// Нужно переинициализировать listeners при обнаружении перезагрузки
let lastInitTime = Date.now();
window.addEventListener('pageshow', (e) => {
  // Если страница восстановлена из кэша (bfcache) - переинициализируем
  if (e.persisted) {
    try { console.debug('[Aegis] Page restored from cache. Re-initializing hover...'); } catch(_) {}
    cleanupHoverListeners();
    setupHoverListeners();
  }
});

// КРИТИЧНО: Переинициализация при возврате на вкладку (visibilitychange)
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    // Вкладка стала видимой - проверяем работоспособность
    const timeSinceLastCheck = Date.now() - lastHoverCheck;
    if (timeSinceLastCheck > 60000 || !hoverListenersReady) { // 1 минута или listeners не готовы
      try { console.debug('[Aegis] Tab visible. Checking hover listeners...'); } catch(_) {}
      cleanupHoverListeners();
      setupHoverListeners();
    }
  }
});

// Listen for analysis results from background
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'hover_result') {
    console.log('[Aegis Content] hover_result received:', {
      url: msg.url,
      safe: msg.res?.safe,
      threat_type: msg.res?.threat_type,
      source: msg.res?.source,
      details: msg.res?.details
    });
    
    const incomingUrl = normalizeUrlForCompare(msg.url);
    if (!currentHoveredLink) {
      console.log('[Aegis Content] No current hovered link, ignoring result');
      return;
    }
    if (currentHoveredLinkNormalized && incomingUrl && currentHoveredLinkNormalized !== incomingUrl) {
      console.log('[Aegis Content] URL mismatch, ignoring result. Current:', currentHoveredLinkNormalized, 'Incoming:', incomingUrl);
      return;
    }
    if (!currentHoveredLinkNormalized) {
      currentHoveredLinkNormalized = incomingUrl;
    }
    // Очищаем таймаут ошибки, если он был установлен
    if (currentHoveredLink && currentHoveredLink.dataset.aegisHoverTimeout) {
      clearTimeout(parseInt(currentHoveredLink.dataset.aegisHoverTimeout, 10));
      delete currentHoveredLink.dataset.aegisHoverTimeout;
    }
    
    lastHoverResult = msg.res ? { ...msg.res } : null;
    const verdict = determineVerdict(lastHoverResult);
    console.log('[Aegis Content] Determined verdict:', verdict, 'from result:', lastHoverResult);
    
    // Сохраняем результат в кэш
    if (currentHoveredLinkNormalized && lastHoverResult) {
      hoverResultCache.set(currentHoveredLinkNormalized, {
        data: lastHoverResult,
        timestamp: Date.now()
      });
    }
    
    const content = formatAnalysisResult(lastHoverResult, msg.url);
    // Перед применением темы гарантированно очищаем возможные артефакты (если тема сменялась во время наведения)
    cleanupHoverTheme(currentHoveredLink);
    // Update content and styling; if coords passed, snap to them for accuracy
    const x = typeof msg.mouseX === 'number' ? msg.mouseX : lastMouseX;
    const y = typeof msg.mouseY === 'number' ? msg.mouseY : lastMouseY;
    // Применяем только выбранную тему - работает только одна тема
    if (hoverTheme === 'classic') {
      ensureTooltipForTheme();
      if (tooltip) {
        updateTooltip(tooltip, x, y, content, verdict);
      }
    } else {
      if (tooltip) {
        hideTooltip(tooltip);
      }
      // Применяем визуальные индикаторы для других тем
      applyHoverTheme(currentHoveredLink, verdict);
    }
  }
  if (msg.type === 'file_analysis_updated') {
    if (!currentHoveredLink || !msg.data) {
      return;
    }
    const incomingUrl = normalizeUrlForCompare(msg.url);
    if (!incomingUrl || !currentHoveredLinkNormalized || incomingUrl !== currentHoveredLinkNormalized) {
      return;
    }
    const updatedInfo = { ...msg.data };
    delete updatedInfo.timestamp;
    if (lastHoverResult) {
      lastHoverResult = { ...lastHoverResult, fileAnalysis: { ...updatedInfo } };
    } else {
      lastHoverResult = { fileAnalysis: { ...updatedInfo } };
    }
    // Применяем только выбранную тему
    if (hoverTheme === 'classic' && tooltip && tooltip.style.opacity === '1') {
      const content = formatAnalysisResult(lastHoverResult, currentHoveredLink.href);
      const verdict = determineVerdict(lastHoverResult);
      cleanupHoverTheme(currentHoveredLink);
      updateTooltip(tooltip, lastMouseX, lastMouseY, content, verdict);
    } else if (hoverTheme !== 'classic') {
      const verdict = determineVerdict(lastHoverResult);
      cleanupHoverTheme(currentHoveredLink);
      applyHoverTheme(currentHoveredLink, verdict);
    }
  }
  if (msg.type === 'reinit_hover') {
    try { console.debug('[Aegis] Reinitializing hover after reconnect'); } catch(_) {}
    setupKeepAlive();
    startHoverHealthCheck();
    if (isClassicHover() && !tooltip) createHoverTooltip();
    // КРИТИЧНО: Полная переинициализация с очисткой старых listeners
    cleanupHoverListeners();
    setupHoverListeners();
  }
  
  // КРИТИЧНО: Диагностика - проверка работоспособности hover
  if (msg.type === 'hover_diagnostic') {
    const timeSinceLastCheck = Date.now() - lastHoverCheck;
    return Promise.resolve({
      listenersReady: hoverListenersReady,
      checkCount: hoverCheckCount,
      timeSinceLastCheck: timeSinceLastCheck,
      hasTooltip: !!tooltip,
      hasKeepAlivePort: !!keepAlivePort,
      currentLink: currentHoveredLink ? currentHoveredLink.href : null
    });
  }
});

// Visual indicator for dangerous links
function addVisualIndicator(link, verdict) {
  if (link.dataset.safebrowseIndicator) return; // Already processed
  
  const indicator = document.createElement('span');
  indicator.style.cssText = `
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-left: 4px;
    vertical-align: middle;
  `;
  
  if (verdict === 'malicious') {
    indicator.style.background = '#ff5c5c';
    indicator.title = 'Опасная ссылка';
  } else if (verdict === 'suspicious') {
    indicator.style.background = '#f1c40f';
    indicator.title = 'Подозрительная ссылка';
  } else {
    indicator.style.background = '#2ecc71';
    indicator.title = 'Безопасная ссылка';
  }
  
  link.appendChild(indicator);
  link.dataset.safebrowseIndicator = 'true';
}

// Initialize tooltip when script loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initTooltip);
} else {
  initTooltip();
}
