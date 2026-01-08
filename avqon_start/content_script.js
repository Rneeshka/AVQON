// content_script.js
// Enhanced content script with hover analysis and visual indicators

// КРИТИЧНО: Флаг инвалидации контекста расширения
let extensionContextInvalidated = false;

// КРИТИЧНО: Функция-обертка для безопасных вызовов chrome.storage
function safeStorageGet(keys, callback) {
  if (extensionContextInvalidated) {
    if (callback) callback({});
    return;
  }
  try {
    if (!chrome || !chrome.storage || !chrome.storage.sync) {
      extensionContextInvalidated = true;
      if (callback) callback({});
      return;
    }
    chrome.storage.sync.get(keys, (result) => {
      if (chrome.runtime.lastError) {
        const error = chrome.runtime.lastError.message || '';
        if (error.includes('Extension context invalidated') || 
            error.includes('message port closed') ||
            error.includes('Receiving end does not exist')) {
          extensionContextInvalidated = true;
          if (callback) callback({});
          return;
        }
      }
      if (callback) callback(result || {});
    });
  } catch (e) {
    extensionContextInvalidated = true;
    if (callback) callback({});
  }
}

// КРИТИЧНО: Функция-обертка для безопасных вызовов chrome.runtime.sendMessage
// Circuit breaker pattern - не пытается отправлять если контекст инвалидирован
function safeSendMessage(message, callback) {
  // КРИТИЧНО: Circuit breaker - если контекст инвалидирован, пробуем восстановить
  if (extensionContextInvalidated) {
    // Пробуем проверить доступность перед отказом
    if (isExtensionAvailable()) {
      // Контекст восстановлен!
      extensionContextInvalidated = false;
      hideContextInvalidatedMessage();
      console.debug('[Aegis] Extension context recovered, resuming operation');
    } else {
      // Контекст все еще инвалидирован
      if (callback) callback(null);
      return false;
    }
  }
  
  // КРИТИЧНО: Проверяем доступность ПЕРЕД попыткой отправки
  if (!isExtensionAvailable()) {
    // КРИТИЧНО: Устанавливаем инвалидацию только при реальной ошибке контекста
    // Не устанавливаем при временных ошибках
    if (callback) callback(null);
    return false;
  }
  
  try {
    if (!chrome || !chrome.runtime || !chrome.runtime.sendMessage) {
      // КРИТИЧНО: Не устанавливаем инвалидацию - это может быть временная проблема
      if (callback) callback(null);
      return false;
    }
    
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        const error = chrome.runtime.lastError.message || '';
        // КРИТИЧНО: Обнаружение инвалидации контекста - только для реальных ошибок
        if (error.includes('Extension context invalidated')) {
          // Это реальная инвалидация контекста
          extensionContextInvalidated = true;
          showContextInvalidatedMessage();
          if (callback) callback(null);
          return;
        }
        // КРИТИЧНО: Другие ошибки могут быть временными - не устанавливаем инвалидацию
        // Например: "Could not establish connection" может быть временной проблемой
        if (callback) callback(null);
        return;
      }
      // КРИТИЧНО: Успешная отправка - сбрасываем инвалидацию и скрываем сообщение
      if (response) {
        extensionContextInvalidated = false;
        hideContextInvalidatedMessage();
      }
      if (callback) callback(response);
    });
    return true; // Сообщение отправлено
  } catch (e) {
    // КРИТИЧНО: Проверяем тип ошибки - только реальная инвалидация устанавливает флаг
    const errorMsg = String(e?.message || e || '');
    if (errorMsg.includes('Extension context invalidated') || 
        errorMsg.includes('Extension context has been invalidated')) {
      extensionContextInvalidated = true;
      showContextInvalidatedMessage();
    }
    // Для других ошибок не устанавливаем инвалидацию
    if (callback) callback(null);
    return false;
  }
}

// КРИТИЧНО: Проверка доступности расширения с детальной диагностикой
// НЕ устанавливает extensionContextInvalidated - только проверяет доступность
function isExtensionAvailable() {
  // КРИТИЧНО: Если флаг установлен, все равно проверяем - может быть восстановлен
  // if (extensionContextInvalidated) return false; // УБРАНО - проверяем всегда
  
  try {
    // Проверяем наличие chrome объекта
    if (!chrome || typeof chrome !== 'object') {
      return false; // НЕ устанавливаем инвалидацию - может быть временная проблема
    }
    
    // Проверяем наличие chrome.runtime
    if (!chrome.runtime || typeof chrome.runtime !== 'object') {
      return false; // НЕ устанавливаем инвалидацию
    }
    
    // КРИТИЧНО: Проверяем наличие chrome.runtime.id (критично для Manifest V3)
    // Если id недоступен, контекст инвалидирован
    try {
      const runtimeId = chrome.runtime.id;
      if (!runtimeId || typeof runtimeId !== 'string') {
        return false; // НЕ устанавливаем инвалидацию - может быть временная проблема
      }
      // КРИТИЧНО: Если все проверки пройдены - контекст валиден, сбрасываем флаг
      if (extensionContextInvalidated) {
        extensionContextInvalidated = false;
        hideContextInvalidatedMessage();
        console.debug('[Aegis] Extension context validated, resetting invalidated flag');
      }
      return true;
    } catch (e) {
      // Если не можем получить id - проверяем тип ошибки
      const errorMsg = String(e?.message || e || '');
      if (errorMsg.includes('Extension context invalidated') || 
          errorMsg.includes('Extension context has been invalidated')) {
        // Это реальная инвалидация
        extensionContextInvalidated = true;
        return false;
      }
      // Другие ошибки - не устанавливаем инвалидацию
      return false;
    }
  } catch (e) {
    // Проверяем тип ошибки
    const errorMsg = String(e?.message || e || '');
    if (errorMsg.includes('Extension context invalidated') || 
        errorMsg.includes('Extension context has been invalidated')) {
      extensionContextInvalidated = true;
      return false;
    }
    // Другие ошибки - не устанавливаем инвалидацию
    return false;
  }
}

// КРИТИЧНО: Визуальная обратная связь для пользователя при инвалидации контекста
let contextInvalidatedMessage = null;
let contextInvalidatedMessageShown = false;
let contextInvalidatedMessageTimeout = null;

function showContextInvalidatedMessage() {
  // КРИТИЧНО: Не показываем сообщение если уже показано или если контекст восстановлен
  if (contextInvalidatedMessageShown) {
    return;
  }
  
  // КРИТИЧНО: Проверяем что контекст действительно инвалидирован
  if (!extensionContextInvalidated) {
    return;
  }
  
  try {
    // Создаем простое уведомление в углу страницы
    const message = document.createElement('div');
    message.id = 'aegis-context-invalidated-message';
    message.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: rgba(239, 68, 68, 0.95);
      color: white;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-family: system-ui, -apple-system, sans-serif;
      z-index: 999999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      max-width: 300px;
      line-height: 1.4;
    `;
    message.textContent = 'Расширение обновляется. Hover временно недоступен.';
    
    document.body.appendChild(message);
    contextInvalidatedMessage = message;
    contextInvalidatedMessageShown = true;
    
    // Автоматически скрываем через 10 секунд (увеличено с 5)
    if (contextInvalidatedMessageTimeout) {
      clearTimeout(contextInvalidatedMessageTimeout);
    }
    contextInvalidatedMessageTimeout = setTimeout(() => {
      hideContextInvalidatedMessage();
    }, 10000);
  } catch (e) {
    // Игнорируем ошибки создания сообщения
  }
}

function hideContextInvalidatedMessage() {
  if (contextInvalidatedMessage && document.body.contains(contextInvalidatedMessage)) {
    try {
      contextInvalidatedMessage.remove();
      contextInvalidatedMessage = null;
      contextInvalidatedMessageShown = false;
      if (contextInvalidatedMessageTimeout) {
        clearTimeout(contextInvalidatedMessageTimeout);
        contextInvalidatedMessageTimeout = null;
      }
    } catch (e) {
      // Игнорируем ошибки удаления
    }
  } else {
    contextInvalidatedMessageShown = false;
    if (contextInvalidatedMessageTimeout) {
      clearTimeout(contextInvalidatedMessageTimeout);
      contextInvalidatedMessageTimeout = null;
    }
  }
}

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
  // КРИТИЧНО: Если есть threat_type, значит есть угроза (небезопасно)
  if (result.threat_type && result.threat_type.trim()) {
    console.log('[Aegis Content] determineVerdict: threat_type present:', result.threat_type, 'returning malicious');
    return 'malicious';
  }
  
  // КРИТИЧНО: Если source === 'error', это ошибка анализа
  if (result.source === 'error') {
    const msg = String(result.details || '').toLowerCase();
    // Сетевые ошибки - подозрительно
    if (msg.includes('failed to fetch') || msg.includes('network') || msg.includes('timeout') || msg.includes('превышено время ожидания')) {
      console.log('[Aegis Content] determineVerdict: network error, returning suspicious');
      return 'suspicious';
    }
    // Другие ошибки - неизвестно
    console.log('[Aegis Content] determineVerdict: error source, returning unknown');
    return 'unknown';
  }
  
  // КРИТИЧНО: Если safe === null и нет threat_type - неизвестно
  // НЕ возвращаем 'safe' по умолчанию!
  console.log('[Aegis Content] determineVerdict: safe is null and no threat_type, returning unknown');
  return 'unknown';
}

// Логирование жизненного цикла контент-скрипта
try {
  console.debug('[Aegis] Hover content script LOADED');
  window.addEventListener('beforeunload', () => {
    try { console.debug('[Aegis] Hover content script UNLOADING'); } catch(_) {}
  });
} catch(_) {}

// КРИТИЧНО: Manifest V3 - keep-alive порты больше не используются
// Service Worker управляется через chrome.alarms в background.js

// КРИТИЧНО: Механизм автоматического восстановления после инвалидации контекста
let recoveryAttempts = 0;
const MAX_RECOVERY_ATTEMPTS = 3;
let lastRecoveryAttempt = 0;
const RECOVERY_COOLDOWN = 30000; // 30 секунд между попытками восстановления

function attemptRecovery() {
  const now = Date.now();
  if (now - lastRecoveryAttempt < RECOVERY_COOLDOWN) {
    return; // Слишком рано для новой попытки
  }
  if (recoveryAttempts >= MAX_RECOVERY_ATTEMPTS) {
    // Превышен лимит попыток - скрываем сообщение об ошибке
    hideContextInvalidatedMessage();
    return;
  }
  
  lastRecoveryAttempt = now;
  recoveryAttempts++;
  
  try {
    // КРИТИЧНО: Проверяем доступность расширения через isExtensionAvailable
    if (isExtensionAvailable()) {
      // Пробуем простой вызов для проверки связи
      const messageSent = safeSendMessage({ type: 'hover_ping', ts: Date.now() }, (resp) => {
        if (resp && resp.ok) {
          // Восстановление успешно!
          extensionContextInvalidated = false;
          recoveryAttempts = 0;
          consecutivePingFailures = 0;
          lastSuccessfulPing = Date.now();
          
          try { 
            console.debug('[Aegis] Extension context recovered! Re-initializing hover...'); 
          } catch(_) {}
          
          // Скрываем сообщение об ошибке
          hideContextInvalidatedMessage();
          
          // Переинициализируем hover
          cleanupHoverListeners();
          initializeHover();
        }
      });
      
      // Если сообщение не отправилось, контекст все еще инвалидирован
      if (!messageSent) {
        // Продолжаем попытки восстановления
        return;
      }
    } else {
      // Расширение все еще недоступно
      return;
    }
  } catch (e) {
    // Игнорируем ошибки при попытке восстановления
  }
}

// КРИТИЧНО: Умный health-check БЕЗ автоматической переинициализации
// Переинициализация только при явных проблемах, не по таймеру
let hoverHealthIntervalId = null;
let lastSuccessfulPing = Date.now();
let consecutivePingFailures = 0;
const MAX_PING_FAILURES = 3;

function startHoverHealthCheck() {
  if (hoverHealthIntervalId) {
    clearInterval(hoverHealthIntervalId);
    hoverHealthIntervalId = null;
  }
  
  // КРИТИЧНО: Health check только проверяет состояние, НЕ переинициализирует автоматически
  hoverHealthIntervalId = setInterval(async () => {
    // Если контекст инвалидирован - только пытаемся восстановить
    if (extensionContextInvalidated) {
      attemptRecovery();
      return;
    }
    
    // КРИТИЧНО: Проверяем доступность расширения, но не устанавливаем инвалидацию агрессивно
    // isExtensionAvailable() сама установит инвалидацию только при реальной ошибке
    if (!isExtensionAvailable() && extensionContextInvalidated) {
      attemptRecovery();
      return;
    }
    
    // КРИТИЧНО: Простая проверка доступности background через ping
    // НЕ переинициализируем listeners автоматически
    const messageSent = safeSendMessage({ type: 'hover_ping', ts: Date.now() }, (resp) => {
      if (resp && resp.ok) {
        // Background доступен - контекст восстановлен
        lastSuccessfulPing = Date.now();
        consecutivePingFailures = 0;
        if (extensionContextInvalidated) {
          // Контекст восстановлен!
          extensionContextInvalidated = false;
          recoveryAttempts = 0;
          hideContextInvalidatedMessage();
          
          // Если listeners не готовы, переинициализируем
          if (!hoverListenersReady) {
            try { 
              console.debug('[Aegis] Context recovered, reinitializing hover listeners...'); 
            } catch(_) {}
            cleanupHoverListeners();
            setupHoverListeners();
          }
        }
      } else {
        consecutivePingFailures++;
        // КРИТИЧНО: Не устанавливаем инвалидацию при временных ошибках
        // Только после множественных неудач и только если это реальная инвалидация
        if (consecutivePingFailures >= MAX_PING_FAILURES * 2) {
          // Множественные неудачи - проверяем реальную инвалидацию
          if (!isExtensionAvailable()) {
            extensionContextInvalidated = true;
            showContextInvalidatedMessage();
          }
        }
      }
    });
    
    // КРИТИЧНО: НЕ устанавливаем инвалидацию здесь - safeSendMessage обработает это
  }, 30000); // Проверка каждые 30 секунд (реже, чтобы не спамить)
}
startHoverHealthCheck();

// === HOVER THEME SUPPORT ===
// Load theme from storage
try {
  safeStorageGet(['hoverTheme'], (cfg) => {
    if (cfg && cfg.hoverTheme) hoverTheme = cfg.hoverTheme;
    ensureTooltipForTheme();
  });
  
  // КРИТИЧНО: Безопасная подписка на изменения storage
  if (isExtensionAvailable() && chrome.storage && chrome.storage.onChanged) {
    try {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (extensionContextInvalidated) return;
        if (area === 'sync' && changes.hoverTheme) {
          hoverTheme = changes.hoverTheme.newValue || 'classic';
          ensureTooltipForTheme();
        }
      });
    } catch (e) {
      extensionContextInvalidated = true;
    }
  }
} catch(_) {
  extensionContextInvalidated = true;
}

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

// КРИТИЧНО: Диагностика состояния hover для отладки
function diagnoseHoverState() {
  const diagnostics = {
    extensionAvailable: isExtensionAvailable(),
    contextInvalidated: extensionContextInvalidated,
    listenersReady: hoverListenersReady,
    hasTooltip: !!tooltip,
    hoverTheme: hoverTheme,
    lastHoverCheck: Date.now() - lastHoverCheck,
    recoveryAttempts: recoveryAttempts,
    consecutivePingFailures: consecutivePingFailures
  };
  try {
    console.debug('[Aegis] Hover diagnostics:', diagnostics);
  } catch(_) {}
  return diagnostics;
}

function setupHoverListeners() {
  // КРИТИЧНО: Проверяем доступность расширения перед настройкой listeners
  if (extensionContextInvalidated) {
    hoverListenersReady = false;
    try {
      console.warn('[Aegis] Cannot setup hover listeners: Extension context invalidated');
    } catch(_) {}
    return; // Не настраиваем listeners при инвалидации
  }
  
  if (!isExtensionAvailable()) {
    extensionContextInvalidated = true;
    hoverListenersReady = false;
    try {
      console.warn('[Aegis] Cannot setup hover listeners: Extension not available');
    } catch(_) {}
    return; // Не настраиваем listeners если расширение недоступно
  }
  
  // КРИТИЧНО: Всегда очищаем старые listeners перед добавлением новых
  cleanupHoverListeners();
  
  hoverListenersReady = true;
  hoverCheckCount++;
  lastHoverCheck = Date.now();
  try { 
    console.debug(`[Aegis] Setting up hover listeners (check #${hoverCheckCount})`);
    diagnoseHoverState();
  } catch(_) {}
  
  // Enhanced link hover detection
  hoverMouseOverHandler = (e) => {
    const link = e.target.closest('a');
    if (!link || !link.href) return;
    if (!/^https?:/i.test(link.href)) return;
    
    // КРИТИЧНО: Проверяем доступность расширения перед использованием
    if (!isExtensionAvailable()) {
      // Расширение недоступно - скрываем tooltip и выходим
      if (tooltip) hideTooltip(tooltip);
      return;
    }
    
    // Check if hover analysis is enabled (теперь бесплатно, без аккаунта)
    safeStorageGet(['hoverScan','antivirusEnabled'], (result) => {
      // КРИТИЧНО: Проверяем доступность расширения после получения storage
      if (extensionContextInvalidated || !isExtensionAvailable()) {
        if (tooltip) hideTooltip(tooltip);
        return;
      }
      
      // Требуем только: включена защита и включен hover (без проверки аккаунта/API ключа)
      // По умолчанию считаем включенными, если ключи отсутствуют
      const antivirusEnabled = result.antivirusEnabled !== false;
      const hoverScan = result.hoverScan !== false;
      
      // КРИТИЧНО: Анализ по наведению теперь бесплатный, работает без аккаунта
      // Старая проверка закомментирована (можно вернуть если нужно):
      // const hasAccount = !!result.account;
      // const hasApiKey = !!result.apiKey;
      // if (!antivirusEnabled || !hoverScan || !hasAccount || !hasApiKey) {
      
      if (!antivirusEnabled || !hoverScan) {
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
          // Используем безопасную обертку для предотвращения ошибок при инвалидации контекста
          if (!isExtensionAvailable()) {
            return; // Расширение недоступно
          }
          // КРИТИЧНО: Проверяем доступность перед отправкой
          // НЕ блокируем отправку если контекст был инвалидирован - пробуем восстановить
          if (!isExtensionAvailable() && extensionContextInvalidated) {
            // Контекст действительно инвалидирован - показываем сообщение только если это реальная проблема
            // НЕ показываем при каждой попытке - только если контекст действительно недоступен
            return; // Не пытаемся отправлять сообщение
          }
          
          // КРИТИЧНО: Отправляем сообщение - safeSendMessage обработает все ошибки
          safeSendMessage({
            type: 'hover_url', 
            url: link.href,
            mouseX: lastMouseX,
            mouseY: lastMouseY
          }, (response) => {
            // Callback не требуется, результат придет через onMessage
            // safeSendMessage уже обработал все ошибки и восстановил контекст если возможно
          });
          
          // КРИТИЧНО: НЕ показываем сообщение об ошибке здесь - это может быть временная проблема
          // Сообщение показывается только в safeSendMessage при реальной инвалидации
          
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
    
    // КРИТИЧНО: Circuit breaker - не отправляем если контекст инвалидирован
    if (extensionContextInvalidated || !isExtensionAvailable()) {
      return; // Не пытаемся отправлять сообщение
    }
    
    // КРИТИЧНО: Безопасная отправка сообщения с проверкой доступности
    safeSendMessage({type: 'check_url', url: a.href}, () => {});
  };
  document.addEventListener('click', hoverClickHandler, true);
  
  try { console.debug('[Aegis] Hover listeners SET UP successfully'); } catch(_) {}
}

// КРИТИЧНО: Надежная одноразовая инициализация с проверкой готовности
function initializeHover() {
  // Проверяем что DOM готов
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeHover, { once: true });
    return;
  }
  
  // Проверяем доступность расширения
  if (!isExtensionAvailable()) {
    extensionContextInvalidated = true;
    try {
      console.warn('[Aegis] Cannot initialize hover: Extension not available');
    } catch(_) {}
    // Пробуем восстановить через некоторое время
    setTimeout(() => {
      if (isExtensionAvailable()) {
        extensionContextInvalidated = false;
        initializeHover();
      }
    }, 2000);
    return;
  }
  
  // Инициализируем tooltip если нужно
  initTooltip();
  
  // Настраиваем listeners
  setupHoverListeners();
  
  try {
    console.debug('[Aegis] Hover initialized successfully');
    diagnoseHoverState();
  } catch(_) {}
}

// Инициализация слушателей при загрузке
initializeHover();

// КРИТИЧНО: Обработка перезагрузки content script на SPA-сайтах
// При навигации в SPA content script может перезагружаться, но DOM остается
// Нужно переинициализировать listeners при обнаружении перезагрузки
let lastInitTime = Date.now();
window.addEventListener('pageshow', (e) => {
  // Если страница восстановлена из кэша (bfcache) - переинициализируем
  if (e.persisted) {
    try { console.debug('[Aegis] Page restored from cache. Re-initializing hover...'); } catch(_) {}
    
    // КРИТИЧНО: Проверяем доступность расширения перед переинициализацией
    if (extensionContextInvalidated) {
      attemptRecovery();
      return;
    }
    
    // КРИТИЧНО: Проверяем доступность, но не устанавливаем инвалидацию агрессивно
    if (!isExtensionAvailable() && extensionContextInvalidated) {
      attemptRecovery();
      return;
    }
    
    // КРИТИЧНО: Используем полную инициализацию вместо только setupHoverListeners
    cleanupHoverListeners();
    initializeHover();
  }
});

// КРИТИЧНО: Переинициализация при возврате на вкладку (visibilitychange)
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    // КРИТИЧНО: Проверяем доступность расширения перед переинициализацией
    if (extensionContextInvalidated) {
      // Пробуем восстановить при возврате на вкладку
      attemptRecovery();
      return;
    }
    
    // КРИТИЧНО: Проверяем доступность, но не устанавливаем инвалидацию агрессивно
    if (!isExtensionAvailable() && extensionContextInvalidated) {
      showContextInvalidatedMessage();
      attemptRecovery();
      return;
    }
    
    // Вкладка стала видимой - проверяем работоспособность
    // КРИТИЧНО: Переинициализируем ТОЛЬКО если listeners действительно не работают
    if (!hoverListenersReady) {
      try { console.debug('[Aegis] Tab visible. Listeners not ready, reinitializing...'); } catch(_) {}
      cleanupHoverListeners();
      setupHoverListeners();
    } else {
      // Listeners готовы - проверяем что контекст все еще валиден
      safeSendMessage({ type: 'hover_ping', ts: Date.now() }, (resp) => {
        if (resp && resp.ok) {
          // Все работает - контекст валиден
          hideContextInvalidatedMessage();
        }
      });
      // КРИТИЧНО: НЕ устанавливаем инвалидацию здесь - safeSendMessage обработает это
    }
  }
});

// КРИТИЧНО: Безопасный обработчик сообщений с защитой от инвалидации контекста
try {
  if (chrome && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      // КРИТИЧНО: Проверяем инвалидацию контекста перед обработкой
      if (extensionContextInvalidated) {
        return false;
      }
      
      try {
        // Проверяем наличие chrome.runtime для обработки ошибок
        if (!chrome.runtime || !chrome.runtime.id) {
          extensionContextInvalidated = true;
          return false;
        }
      } catch (e) {
        extensionContextInvalidated = true;
        return false;
      }
      
      // Обрабатываем сообщения
      return handleMessage(msg, sender, sendResponse);
    });
  }
} catch (e) {
  extensionContextInvalidated = true;
}

// КРИТИЧНО: Функция обработки сообщений с полной защитой от ошибок
function handleMessage(msg, sender, sendResponse) {
  if (!msg || typeof msg !== 'object') {
    return false;
  }
  
  // КРИТИЧНО: Проверяем доступность расширения для каждого сообщения
  if (!isExtensionAvailable()) {
    return false;
  }
  
  try {
  if (msg.type === 'hover_result') {
    // КРИТИЧНО: Получен результат - контекст работает, сбрасываем инвалидацию
    if (extensionContextInvalidated) {
      extensionContextInvalidated = false;
      hideContextInvalidatedMessage();
      console.debug('[Aegis] Received hover_result, context is valid, resetting invalidated flag');
    }
    
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
    // КРИТИЧНО: При переинициализации сбрасываем флаг инвалидации и счетчик попыток
    extensionContextInvalidated = false;
    recoveryAttempts = 0;
    consecutivePingFailures = 0;
    lastSuccessfulPing = Date.now();
    
    // КРИТИЧНО: Полная переинициализация через initializeHover
    cleanupHoverListeners();
    initializeHover();
  }
  
  // КРИТИЧНО: Диагностика - проверка работоспособности hover
  if (msg.type === 'hover_diagnostic') {
    const diagnostics = diagnoseHoverState();
    if (sendResponse) {
      sendResponse({
        ...diagnostics,
        checkCount: hoverCheckCount,
        timeSinceLastCheck: Date.now() - lastHoverCheck,
        currentLink: currentHoveredLink ? currentHoveredLink.href : null,
        lastSuccessfulPing: Date.now() - lastSuccessfulPing,
        cacheSize: hoverResultCache.size
      });
    }
    return true; // Асинхронный ответ
  }
  
  return false; // Сообщение не обработано
  } catch (e) {
    // КРИТИЧНО: При любой ошибке проверяем инвалидацию контекста
    if (e && (e.message && (e.message.includes('Extension context invalidated') || 
                            e.message.includes('message port closed') ||
                            e.message.includes('Receiving end does not exist')))) {
      extensionContextInvalidated = true;
    }
    return false;
  }
}

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
