// background.js
const DEFAULTS = { antivirusEnabled: true, linkCheck: true, hoverScan: true, notify: true };
const DEFAULT_API_BASE = 'https://api.aegis.builders';

// Кеш результатов для быстрого анализа по наведению
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 минут

// Поддержка анализа файлов
const FILE_EXTENSIONS = [
  '.exe', '.msi', '.apk', '.bat', '.cmd', '.scr', '.ps1',
  '.js', '.jar', '.vbs', '.py', '.zip', '.rar', '.7z', '.gz', '.tar',
  '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.pdf', '.rtf', '.iso', '.img' 
];
const FILE_ANALYSIS_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 часа
const MAX_FILE_ANALYSIS_SIZE = 15 * 1024 * 1024; // 15 МБ лимит быстрой проверки
const FILE_ANALYSIS_STORAGE_KEY = 'fileAnalysisCache';
const fileAnalysisCache = new Map();
const ongoingFileAnalyses = new Map(); // downloadId -> Promise
let fileAnalysisCacheLoaded = false;

// Состояние подключения к серверу
let connectionState = {
  isOnline: true,
  lastCheck: 0,
  retryCount: 0,
  maxRetries: 5
};

// КРИТИЧНО: Manifest V3 - keep-alive порты больше не используются
// Service Worker управляется через chrome.alarms (см. startConnectionMonitoring)

// Время последней загрузки состояния (чтобы не загружать слишком часто)
let lastStateLoad = 0;
const STATE_LOAD_INTERVAL = 5000; // Загружаем не чаще раза в 5 секунд
const WS_RETRY_DELAYS = [1000, 2000, 5000, 10000, 30000];
const WS_RESPONSE_TIMEOUT = 15000;
const WS_HEARTBEAT_INTERVAL = 20000;

// === Side panel integration ===
function initSidePanelIntegration() {
  if (!chrome.sidePanel || !chrome.action) return;

  const disableDefaultBehavior = () => {
    chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch((err) => {
      console.warn('[Aegis] sidePanel behavior setup failed:', err);
    });
  };

  if (chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => disableDefaultBehavior());
  }

  // Также на всякий случай при запуске
  disableDefaultBehavior();

  chrome.action.onClicked.addListener(async (tab) => {
    try {
      let targetWindowId = tab?.windowId;
      if (typeof targetWindowId === 'undefined') {
        const currentWindow = await chrome.windows.getCurrent();
        targetWindowId = currentWindow?.id;
      }
      const openOptions = {};
      if (typeof targetWindowId === 'number') {
        openOptions.windowId = targetWindowId;
      }
      await chrome.sidePanel.open(openOptions);
    } catch (error) {
      console.error('[Aegis] Failed to open side panel:', error);
    }
  });
}

initSidePanelIntegration();

// Загружаем состояние из storage при старте
function normalizeApiBaseUrl(raw) {
  let value = (raw || '').toString().trim();
  if (!value) return DEFAULT_API_BASE;

  if (!/^https?:\/\//i.test(value)) {
    value = `https://${value}`;
  }

  try {
    const url = new URL(value);
    url.pathname = url.pathname.replace(/\/proxy\/?$/, '') || '/';
    url.search = '';
    url.hash = '';
    return `${url.origin}${url.pathname}`.replace(/\/$/, '') || url.origin;
  } catch (_) {
    return DEFAULT_API_BASE;
  }
}

function generateRequestId(prefix = 'req') {
  return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`;
}

class AegisWebSocketClient {
  constructor() {
    this.ws = null;
    this.pending = new Map();
    this.retryTimer = null;
    this.connectingPromise = null;
    this.heartbeatTimer = null;
    this.lastPong = 0;
    this.retryAttempt = 0;
    this.manuallyClosed = false;
  }

  async ensureConnected() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return this.ws;
    }
    if (this.connectingPromise) {
      return this.connectingPromise;
    }
    this.connectingPromise = this._connect();
    try {
      await this.connectingPromise;
    } finally {
      this.connectingPromise = null;
    }
    return this.ws;
  }

  async _connect() {
    try {
      const apiBase = await getApiBase();
      const apiKey = await getApiKey();
      const wsUrl = this._buildUrl(apiBase, apiKey);
      
      console.log('[Aegis WS] Connecting to:', wsUrl.replace(/api_key=[^&]+/, 'api_key=***'));

      return await new Promise((resolve, reject) => {
        let settled = false;
        const connectTimeout = setTimeout(() => {
          if (!settled) {
            settled = true;
            try {
              if (socket) socket.close();
            } catch (_) {}
            reject(new Error('WebSocket connection timeout'));
          }
        }, 10000); // 10 секунд таймаут подключения

        let socket;
        try {
          socket = new WebSocket(wsUrl);
          this.ws = socket;
          this.manuallyClosed = false;

          socket.onopen = () => {
            if (!settled) {
              settled = true;
              clearTimeout(connectTimeout);
              this._handleOpen();
              resolve(socket);
            }
          };

          socket.onmessage = (event) => this._handleMessage(event);

          socket.onerror = (event) => {
            const errorMsg = event?.message || event?.error?.message || 'WebSocket connection error';
            console.error('[Aegis WS] Connection error:', errorMsg, wsUrl.replace(/api_key=[^&]+/, 'api_key=***'));
            if (!settled) {
              settled = true;
              clearTimeout(connectTimeout);
              reject(new Error(`WebSocket error: ${errorMsg}`));
            }
            this._handleError(event);
          };

          socket.onclose = (event) => {
            const closeReason = event.reason || `Code ${event.code}`;
            console.warn('[Aegis WS] Connection closed:', closeReason, `(code: ${event.code})`);
            if (!settled) {
              settled = true;
              clearTimeout(connectTimeout);
              let errorMsg = 'WebSocket connection closed';
              if (event.code === 1006) {
                errorMsg = 'WebSocket connection failed (server unreachable or connection refused)';
              } else if (event.code === 1003 || event.code === 1002) {
                // 1003 = endpoint not found (404), 1002 = protocol error
                errorMsg = 'WebSocket endpoint not found (404). Check server configuration';
              } else if (event.code === 1001) {
                errorMsg = 'WebSocket connection going away (server shutdown or restart)';
              } else if (event.code !== 1000) {
                errorMsg = `WebSocket closed: ${closeReason} (code: ${event.code})`;
              }
              // Добавляем код ошибки в сообщение для fallback логики
              const error = new Error(errorMsg);
              error.closeCode = event.code;
              error.closeReason = closeReason;
              reject(error);
            }
            this._handleClose(event);
          };
        } catch (err) {
          if (!settled) {
            settled = true;
            clearTimeout(connectTimeout);
            reject(new Error(`Failed to create WebSocket: ${err.message || err}`));
          }
        }
      });
    } catch (error) {
      console.error('[Aegis WS] Connect failed:', error);
      this._scheduleReconnect();
      throw error;
    }
  }

  _buildUrl(apiBase, apiKey) {
    try {
      // Правильно преобразуем HTTP/HTTPS в WS/WSS
      let wsUrl = apiBase;
      if (wsUrl.startsWith('https://')) {
        wsUrl = wsUrl.replace('https://', 'wss://');
      } else if (wsUrl.startsWith('http://')) {
        wsUrl = wsUrl.replace('http://', 'ws://');
      } else if (!wsUrl.startsWith('ws://') && !wsUrl.startsWith('wss://')) {
        // Если нет протокола, добавляем wss по умолчанию
        wsUrl = `wss://${wsUrl}`;
      }
      
      const url = new URL(wsUrl);
      // КРИТИЧНО: Убираем ВСЕ пути из apiBase и добавляем только /ws
      // Это нужно, потому что apiBase может содержать /proxy или другие пути
      url.pathname = '/ws';
      if (apiKey) {
        url.searchParams.set('api_key', apiKey);
      }
      const finalUrl = url.toString();
      console.log('[Aegis WS] Built URL:', finalUrl.replace(/api_key=[^&]+/, 'api_key=***'));
      return finalUrl;
    } catch (err) {
      // В случае ошибки формируем URL вручную
      console.error('[Aegis WS] Failed to build URL:', err, apiBase);
      let wsBase = apiBase;
      if (wsBase.startsWith('https://')) {
        wsBase = wsBase.replace('https://', 'wss://');
      } else if (wsBase.startsWith('http://')) {
        wsBase = wsBase.replace('http://', 'ws://');
      }
      // Извлекаем только origin (без пути)
      try {
        const urlObj = new URL(wsBase);
        wsBase = `${urlObj.protocol}//${urlObj.host}`;
      } catch (_) {
        // Если не удалось распарсить, оставляем как есть
      }
      return `${wsBase}/ws${apiKey ? `?api_key=${encodeURIComponent(apiKey)}` : ''}`;
    }
  }

  _handleOpen() {
    this.retryAttempt = 0;
    this.lastPong = Date.now();
    connectionState.isOnline = true;
    connectionState.lastCheck = Date.now();
    connectionState.retryCount = 0;
    saveConnectionState();
    broadcastConnectionStatus(true);
    this._startHeartbeat();
    processRequestQueue();
  }

  _handleClose(event) {
    this._stopHeartbeat();
    this.ws = null;
    connectionState.isOnline = false;
    connectionState.lastCheck = Date.now();
    connectionState.retryCount += 1;
    saveConnectionState();
    broadcastConnectionStatus(false);
    this._rejectAllPending(`Connection closed (${event?.code || 'unknown'})`);
    if (!this.manuallyClosed) {
      this._scheduleReconnect();
    }
  }

  _handleError(event) {
    const message = event && event.message ? event.message : 'WebSocket error';
    console.warn('[Aegis WS] Error:', message);
  }

  _handleMessage(event) {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch (err) {
      console.warn('[Aegis WS] Failed to parse message', err);
      return;
    }
    if (!data || typeof data !== 'object') {
      return;
    }

    const msgType = (data.type || '').toLowerCase();
    if (msgType === 'pong' || msgType === 'hello') {
      this.lastPong = Date.now();
      return;
    }

    if (msgType === 'analysis_result') {
      this.lastPong = Date.now();
      // КРИТИЧНО: Извлекаем результат из разных возможных форматов
      let result = data.payload ?? data.result ?? data;
      
      // КРИТИЧНО: Если result это объект, но не содержит safe напрямую - проверяем вложенные структуры
      if (result && typeof result === 'object') {
        // Если есть вложенный объект с результатом
        if (result.data && typeof result.data === 'object') {
          result = result.data;
        }
        // Если есть вложенный analysis
        if (result.analysis && typeof result.analysis === 'object') {
          result = result.analysis;
        }
      }
      
      console.log('[Aegis WS] analysis_result received, requestId:', data.requestId, 'result.safe:', result?.safe, 'result.threat_type:', result?.threat_type, 'full result keys:', result ? Object.keys(result) : 'null');
      
      // КРИТИЧНО: Нормализуем результат перед передачей
      // Это гарантирует что safe всегда явно true/false/null
      const normalized = normalizeAnalysisPayload(result, null);
      if (normalized) {
        this._resolvePending(data.requestId, normalized);
      } else {
        // Если нормализация не удалась, передаем как есть
        this._resolvePending(data.requestId, result);
      }
      return;
    }

    if (msgType === 'error') {
      const errorMessage = data.message || 'Server error';
      this._rejectPending(data.requestId, errorMessage);
      return;
    }

    if (msgType === 'notification' || msgType === 'file_analysis_update') {
      const payload = data.payload || {};
      if (payload.url && payload.analysis) {
        setFileAnalysisCache(payload.url, payload.analysis).catch(() => {});
        broadcastFileAnalysisUpdate(payload.url, payload.analysis);
      }
      return;
    }
  }

  _startHeartbeat() {
    this._stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        return;
      }
      if (Date.now() - this.lastPong > WS_RESPONSE_TIMEOUT * 3) {
        try {
          this.ws.close(4001, 'Heartbeat timeout');
        } catch (_) {}
        return;
      }
      try {
        this.ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
      } catch (err) {
        console.warn('[Aegis WS] Failed to send heartbeat', err);
      }
    }, WS_HEARTBEAT_INTERVAL);
  }

  _stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  _scheduleReconnect() {
    if (this.retryTimer || this.manuallyClosed) {
      return;
    }
    const delay = WS_RETRY_DELAYS[Math.min(this.retryAttempt, WS_RETRY_DELAYS.length - 1)];
    this.retryAttempt += 1;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.ensureConnected().catch(() => {
        this._scheduleReconnect();
      });
    }, delay);
  }

  _resolvePending(requestId, payload) {
    if (!requestId) return;
    const pending = this.pending.get(requestId);
    if (!pending) return;
    clearTimeout(pending.timeout);
    this.pending.delete(requestId);
    console.log('[Aegis WS] Resolving pending request:', requestId, 'payload.safe:', payload?.safe, 'payload.threat_type:', payload?.threat_type);
    pending.resolve(payload);
  }

  _rejectPending(requestId, errorMessage) {
    if (!requestId) return;
    const pending = this.pending.get(requestId);
    if (!pending) return;
    clearTimeout(pending.timeout);
    this.pending.delete(requestId);
    pending.reject(new Error(errorMessage || 'Request failed'));
  }

  _rejectAllPending(errorMessage) {
    const entries = Array.from(this.pending.entries());
    this.pending.clear();
    entries.forEach(([, pending]) => {
      clearTimeout(pending.timeout);
      pending.reject(new Error(errorMessage));
    });
  }

  async request(type, payload = {}, options = {}) {
    await this.ensureConnected().catch((err) => {
      throw new Error(err.message || 'WebSocket connection unavailable');
    });

    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected');
    }

    const requestId = generateRequestId(type);
    const message = {
      type,
      requestId,
      payload,
      timestamp: Date.now()
    };

    return await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (this.pending.has(requestId)) {
          this.pending.delete(requestId);
          reject(new Error('Request timeout'));
        }
      }, options.timeout || WS_RESPONSE_TIMEOUT);

      this.pending.set(requestId, { resolve, reject, timeout, createdAt: Date.now(), type });

      try {
        this.ws.send(JSON.stringify(message));
      } catch (err) {
        clearTimeout(timeout);
        this.pending.delete(requestId);
        reject(err);
      }
    });
  }

  async close(code = 1000, reason = 'client_close') {
    this.manuallyClosed = true;
    this._stopHeartbeat();
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.close(code, reason);
      } catch (_) {}
    }
    this.ws = null;
    this._rejectAllPending('Connection closed');
  }

  forceReconnect() {
    this.manuallyClosed = false;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.close(1012, 'Reconnecting');
      } catch (_) {}
    } else {
      this.ensureConnected().catch(() => {});
    }
  }
}

const wsClient = new AegisWebSocketClient();

async function loadConnectionState(force = false) {
  // Не загружаем слишком часто (кроме принудительной загрузки)
  const timeSinceLastLoad = Date.now() - lastStateLoad;
  if (!force && timeSinceLastLoad < STATE_LOAD_INTERVAL) {
    return; // Состояние уже свежее
  }
  
  try {
    const stored = await new Promise(r => chrome.storage.local.get(['connectionState'], r));
    if (stored.connectionState) {
      connectionState = { ...connectionState, ...stored.connectionState };
      // Обновляем lastCheck относительно текущего времени
      const timeDiff = Date.now() - (stored.connectionState.lastCheck || 0);
      // Если прошло больше 5 минут - считаем, что нужно проверить
      if (timeDiff > 300000) {
        connectionState.lastCheck = 0; // Принудительная проверка
      }
    }
    lastStateLoad = Date.now();
  } catch (e) {
    // Игнорируем ошибки загрузки
  }
}

// Сохраняем состояние в storage
async function saveConnectionState() {
  try {
    await new Promise(r => chrome.storage.local.set({ connectionState }, r));
  } catch (e) {
    // Игнорируем ошибки сохранения
  }
}

function normalizeUrl(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    parsed.hash = '';
    return parsed.toString();
  } catch (_) {
    return url;
  }
}

function isFileUrl(url) {
  try {
    const parsed = new URL(url);
    const pathname = parsed.pathname.toLowerCase();
    return FILE_EXTENSIONS.some((ext) => pathname.endsWith(ext));
  } catch (_) {
    return false;
  }
}

function guessFileName(url) {
  try {
    const parsed = new URL(url);
    const pathname = decodeURIComponent(parsed.pathname);
    const parts = pathname.split('/');
    const name = parts.pop() || parts.pop() || 'downloaded-file';
    return name || 'downloaded-file';
  } catch (_) {
    return 'downloaded-file';
  }
}

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  const hexCodes = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) {
    const value = bytes[i].toString(16);
    hexCodes[i] = value.padStart(2, '0');
  }
  return hexCodes.join('');
}

async function computeSHA256(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return arrayBufferToHex(hashBuffer);
}

async function loadFileAnalysisCache() {
  if (fileAnalysisCacheLoaded) return;
  try {
    const stored = await new Promise((resolve) => chrome.storage.local.get([FILE_ANALYSIS_STORAGE_KEY], resolve));
    const list = stored?.[FILE_ANALYSIS_STORAGE_KEY];
    if (Array.isArray(list)) {
      const now = Date.now();
      list.forEach((entry) => {
        if (!entry || !entry.url || !entry.data) return;
        const key = entry.url;
        const data = entry.data;
        const timestamp = entry.timestamp || data.timestamp || now;
        if (now - timestamp <= FILE_ANALYSIS_CACHE_TTL) {
          fileAnalysisCache.set(key, { ...data, timestamp });
        }
      });
    }
  } catch (e) {
    // Игнорируем ошибки загрузки кэша
  } finally {
    fileAnalysisCacheLoaded = true;
  }
}

async function persistFileAnalysisCache() {
  // КРИТИЧНО: Больше не сохраняем результаты анализа файлов в chrome.storage.local,
  // чтобы вердикты хранились только на сервере (локальная БД).
  // Кэш остается только в памяти текущего Service Worker.
  return;
}

async function setFileAnalysisCache(url, data) {
  await loadFileAnalysisCache();
  const key = normalizeUrl(url);
  const entry = { ...data, timestamp: Date.now() };
  fileAnalysisCache.set(key, entry);
  persistFileAnalysisCache().catch(() => {});
  updateHoverCacheWithFileAnalysis(url, entry);
  broadcastFileAnalysisUpdate(url, entry);
}

async function getFileAnalysisHint(url) {
  await loadFileAnalysisCache();
  const key = normalizeUrl(url);
  const entry = fileAnalysisCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > FILE_ANALYSIS_CACHE_TTL) {
    fileAnalysisCache.delete(key);
    return null;
  }
  const { timestamp, ...data } = entry;
  return { ...data };
}

function updateHoverCacheWithFileAnalysis(url, entry) {
  if (!entry) return;
  const normalizedTarget = normalizeUrl(url);
  const { timestamp, ...data } = entry;
  cache.forEach((value, cacheKey) => {
    if (!value || !value.data) return;
    if (normalizeUrl(cacheKey) === normalizedTarget) {
      value.data.fileAnalysis = { ...data };
    }
  });
}

async function enrichWithFileAnalysis(url, result) {
  if (!isFileUrl(url)) {
    return result;
  }
  const info = await getFileAnalysisHint(url);
  if (info) {
    return { ...result, fileAnalysis: { ...info } };
  }
  return {
    ...result,
    fileAnalysis: {
      status: 'pending',
      verdict: 'pending',
      message: 'Файл будет проверен автоматически при скачивании',
      safe: null
    }
  };
}

function broadcastFileAnalysisUpdate(url, entry) {
  try {
    const payload = { type: 'file_analysis_updated', url: normalizeUrl(url), data: { ...entry, timestamp: undefined } };
    chrome.tabs.query({}, (tabs) => {
      tabs?.forEach((tab) => {
        if (tab.id != null) {
          try {
            chrome.tabs.sendMessage(tab.id, payload, () => chrome.runtime.lastError && void 0);
          } catch (_) {
            // Игнорируем ошибки доставки
          }
        }
      });
    });
  } catch (_) {
    // Игнорируем ошибки广播
  }
}

async function analyzeFileHash(fileHash, meta = {}) {
  const payload = await requestWsAnalysis('analyze_file_hash', {
    hash: fileHash,
    file_name: meta.fileName,
    file_size: meta.fileSize,
    context: meta.context || 'download'
  });
  return payload;
}

async function fetchFileForAnalysis(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(url, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'follow',
      signal: controller.signal
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const contentLengthHeader = response.headers.get('content-length');
    const declaredLength = contentLengthHeader ? Number(contentLengthHeader) : 0;
    if (declaredLength && declaredLength > MAX_FILE_ANALYSIS_SIZE) {
      throw new Error('FILE_TOO_LARGE');
    }
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_FILE_ANALYSIS_SIZE) {
      throw new Error('FILE_TOO_LARGE');
    }
    return { buffer, size: buffer.byteLength };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function analyzeDownloadItem(downloadItem) {
  if (!downloadItem) return;
  const url = downloadItem.finalUrl || downloadItem.url;
  if (!url || !isFileUrl(url)) return;
  await loadFileAnalysisCache();

  const normalizedUrl = normalizeUrl(url);
  const existing = fileAnalysisCache.get(normalizedUrl);
  if (existing && Date.now() - existing.timestamp <= FILE_ANALYSIS_CACHE_TTL) {
    return;
  }

  if (ongoingFileAnalyses.has(downloadItem.id)) {
    return;
  }
  ongoingFileAnalyses.set(downloadItem.id, true);

  const fileName = downloadItem.filename || guessFileName(url);
  let wasPaused = false;

  const resumeIfNeeded = () => {
    if (!wasPaused) return;
    try {
      chrome.downloads.resume(downloadItem.id, () => void chrome.runtime.lastError);
    } catch (_) {
      // ignore
    } finally {
      wasPaused = false;
    }
  };

  try {
    try {
      chrome.downloads.pause(downloadItem.id, () => {
        if (!chrome.runtime.lastError) {
          wasPaused = true;
        }
      });
    } catch (_) {
      wasPaused = false;
    }

    const { buffer, size } = await fetchFileForAnalysis(url);
    const hashHex = await computeSHA256(buffer);
      const analysisResult = await analyzeFileHash(hashHex, { fileName, fileSize: size, context: 'download' });
    const verdict = analysisResult.safe === false
      ? 'malicious'
      : analysisResult.safe === true
        ? 'safe'
        : 'unknown';

    const stored = {
      status: 'completed',
      verdict,
      safe: analysisResult.safe,
      hash: hashHex,
      details: analysisResult.details || '',
      fileName,
      fileSize: size
    };

    await setFileAnalysisCache(url, stored);

    if (verdict === 'malicious') {
      chrome.downloads.cancel(downloadItem.id, () => void chrome.runtime.lastError);
      wasPaused = false;
      notifyFileAnalysis({
        level: 'danger',
        title: 'Файл заблокирован',
        message: `${fileName} определён как опасный`,
        details: analysisResult.details || ''
      });
    } else {
      resumeIfNeeded();
      notifyFileAnalysis({
        level: verdict === 'safe' ? 'success' : 'warning',
        title: verdict === 'safe' ? 'Файл безопасен' : 'Файл требует внимания',
        message: verdict === 'safe'
          ? `${fileName} прошёл проверку`
          : `${fileName}: результат ${verdict === 'unknown' ? 'неизвестен' : 'сомнительный'}`,
        details: analysisResult.details || ''
      });
    }
  } catch (err) {
    const errorMessage = (err && err.message) ? err.message : String(err);
    resumeIfNeeded();

    let status = 'error';
    let verdict = 'unknown';
    let details = errorMessage;

    if (errorMessage === 'FILE_TOO_LARGE') {
      status = 'skipped';
      details = `Файл превышает лимит ${Math.round(MAX_FILE_ANALYSIS_SIZE / (1024 * 1024))} МБ для мгновенной проверки`;
    } else if (errorMessage.includes('Failed to fetch')) {
      details = 'Источник не разрешает фоновую загрузку для проверки';
    }

    await setFileAnalysisCache(url, {
      status,
      verdict,
      safe: null,
      details,
      fileName,
      fileSize: downloadItem.fileSize || null
    });

    notifyFileAnalysis({
      level: status === 'skipped' ? 'info' : 'warning',
      title: status === 'skipped' ? 'Файл не проверен полностью' : 'Не удалось проверить файл',
      message: `${fileName}: ${details}`,
      details: status === 'skipped' ? 'Скачивание продолжено. Будьте внимательны при открытии файла.' : ''
    });
  } finally {
    resumeIfNeeded();
    ongoingFileAnalyses.delete(downloadItem.id);
  }
}

function notifyFileAnalysis({ level = 'info', title, message, details }) {
  getConfig().then((cfg) => {
    if (!cfg.notify) return;
    let icon = 'icons/logo.png';
    let priority = 0;
    if (level === 'danger') priority = 2;
    if (level === 'warning') priority = 1;

    const notificationOptions = {
      type: 'basic',
      iconUrl: icon,
      title: title || 'Проверка файла',
      message: message || '',
      priority
    };

    if (details) {
      notificationOptions.contextMessage = details;
    }

    try {
      chrome.notifications.create(`aegis-file-${Date.now()}-${Math.random().toString(16).slice(2)}`, notificationOptions, () => chrome.runtime.lastError && void 0);
    } catch (_) {
      // Игнорируем ошибки уведомлений
    }
  });
}

// Очередь запросов при потере связи
const requestQueue = [];
const MAX_QUEUE_SIZE = 50;

function getCached(url) {
  const normalizedUrl = normalizeUrl(url);
  const cached = cache.get(normalizedUrl);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    // КРИТИЧНО: Проверяем что кэшированные данные валидны
    if (!cached.data || typeof cached.data !== 'object') {
      console.warn('[Aegis] Cache contains invalid data, ignoring');
      cache.delete(normalizedUrl);
      return null;
    }
    
    console.log('[Aegis] Cache hit for:', normalizedUrl, 'cached safe:', cached.data?.safe, 'cached threat_type:', cached.data?.threat_type);
    // КРИТИЧНО: Если в кэше safe: true, но URL содержит опасные паттерны - игнорируем кэш
    const urlLower = normalizedUrl.toLowerCase();
    const dangerousPatterns = ['eicar', 'testfile', 'malware-test', 'virus-test', 'download-anti-malware-testfile'];
    const hasDangerousPattern = dangerousPatterns.some(pattern => urlLower.includes(pattern));
    if (hasDangerousPattern && cached.data?.safe === true) {
      console.warn('[Aegis] Ignoring cached safe result for dangerous pattern URL:', url);
      cache.delete(url);
      return null;
    }
    return cached.data;
  }
  if (cached) {
    console.log('[Aegis] Cache expired for:', url);
    cache.delete(url);
  }
  return null;
}

function setCached(url, data) {
  // КРИТИЧНО: Нормализуем URL перед кэшированием
  const normalizedUrl = normalizeUrl(url);
  
  // КРИТИЧНО: Проверяем что данные валидны перед кэшированием
  if (!data || typeof data !== 'object') {
    console.warn('[Aegis] Cannot cache invalid data:', data);
    return;
  }
  
  // КРИТИЧНО: Убеждаемся что safe нормализован (true/false/null)
  const normalizedData = {
    ...data,
    safe: data.safe === true ? true : (data.safe === false ? false : null),
    threat_type: data.threat_type || null
  };
  
  console.log('[Aegis] Setting cache for:', normalizedUrl, 'safe:', normalizedData.safe, 'threat_type:', normalizedData.threat_type);
  cache.set(normalizedUrl, { data: normalizedData, timestamp: Date.now() });
}

function getConfig() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULTS, (cfg) => resolve(cfg));
  });
}

async function getApiKey() {
  const storage = await new Promise(r => chrome.storage.sync.get(['apiKey'], r));
  return storage.apiKey || '';
}

// async function getApiBase() {
//   const storage = await new Promise(r => chrome.storage.sync.get(['apiBase'], r));
//   const normalized = normalizeApiBaseUrl(storage.apiBase);
//   if (storage.apiBase !== normalized) {
//     try {
//       chrome.storage.sync.set({ apiBase: normalized }, () => chrome.runtime?.lastError && void 0);
//     } catch (_) {
//       // ignore
//     }
//   }
//   return normalized;
// }

async function getApiBase() {
  // Используем конфиг из глобальной переменной
  // В Service Worker используем self вместо window
  return self.AEGIS_CONFIG?.API_BASE || 
         'https://api-dev.aegis.builders';
}

async function warmUpConnection() {
  try {
    const apiBase = await getApiBase();
    // Делаем простой GET запрос к /health для установки доверия
    // Это позволяет браузеру "познакомиться" с сервером
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    await fetch(`${apiBase}/health`, {
      method: 'GET',
      signal: controller.signal,
      // Важно: не добавляем credentials, чтобы не вызывать CORS preflight
      mode: 'cors',
      cache: 'no-cache'
    }).finally(() => clearTimeout(timeoutId));
    
    // Обновляем состояние подключения
    connectionState.isOnline = true;
    connectionState.lastCheck = Date.now();
    await saveConnectionState();
    
    // Уведомляем о успешном warm-up (без показа пользователю)
  } catch (e) {
    // Игнорируем ошибки warm-up - это нормально, если сервер недоступен
    // Главное - браузер теперь "знает" о сервере
    connectionState.isOnline = false;
    connectionState.lastCheck = Date.now();
    await saveConnectionState();
  }
}

// Проверка подключения к серверу
async function checkServerConnection() {
  try {
    const apiBase = await getApiBase();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    
    const res = await fetch(`${apiBase}/health`, {
      method: 'GET',
      signal: controller.signal
    }).finally(() => clearTimeout(timeoutId));
    
    const wasOffline = !connectionState.isOnline;
    connectionState.isOnline = res.ok;
    connectionState.lastCheck = Date.now();
    connectionState.retryCount = 0;
    
    // Сохраняем состояние
    await saveConnectionState();
    
    if (wasOffline && connectionState.isOnline) {
      // Восстановлено подключение - обрабатываем очередь
      processRequestQueue();
      // Уведомляем все вкладки о восстановлении
      broadcastConnectionStatus(true);
    } else if (!connectionState.isOnline) {
      broadcastConnectionStatus(false);
    }
    
    return connectionState.isOnline;
  } catch (e) {
    const wasOnline = connectionState.isOnline;
    connectionState.isOnline = false;
    connectionState.lastCheck = Date.now();
    connectionState.retryCount++;
    
    // Сохраняем состояние
    await saveConnectionState();
    
    if (wasOnline) {
      broadcastConnectionStatus(false);
    }
    
    return false;
  }
}

// Периодическая проверка подключения через chrome.alarms
// Это работает даже когда service worker неактивен
function startConnectionMonitoring() {
  // Загружаем сохраненное состояние
  loadConnectionState().then(async () => {
    // Проверяем сразу при старте
    await checkServerConnection();
    // Также делаем warm-up для гарантии доверия браузера
    // (warmUpConnection определена ниже, но это асинхронная функция, так что порядок не важен)
    warmUpConnection().catch(() => {}); // Игнорируем ошибки
  });
  
  // Удаляем старые alarms
  chrome.alarms.clearAll();
  
  // КРИТИЧНО: Keep-alive alarm каждые 4.5 минуты для предотвращения остановки Service Worker
  // Chrome останавливает Service Worker через 5 минут неактивности
  // Этот alarm пробуждает SW каждые 4.5 минуты, чтобы он не был остановлен
  chrome.alarms.create('keepAlive', {
    periodInMinutes: 4.5 // Каждые 4.5 минуты (до 5-минутного лимита)
  });
  
  // КРИТИЧНО: Проверка каждые 30 секунд через chrome.alarms
  chrome.alarms.create('connectionCheck', {
    periodInMinutes: 0.5 // Каждые 30 секунд
  });
  
  // Дополнительная проверка каждые 1 минуту (перед истечением кэша)
  chrome.alarms.create('connectionCheckLong', {
    periodInMinutes: 1 // Каждую минуту
  });
  
  // Агрессивная проверка при потере связи - каждые 5 секунд
  chrome.alarms.create('connectionCheckAggressive', {
    periodInMinutes: 0.083 // Каждые ~5 секунд
  });
}

// Обработчик alarms
chrome.alarms.onAlarm.addListener(async (alarm) => {
  // КРИТИЧНО: Keep-alive alarm для поддержания активности Service Worker
  // Простая операция для предотвращения остановки Chrome
  if (alarm.name === 'keepAlive') {
    // Обновляем timestamp в storage - это поддерживает активность SW
    chrome.storage.local.get(['keepAliveTimestamp']).then(() => {
      chrome.storage.local.set({ keepAliveTimestamp: Date.now() });
    });
    // Также проверяем подключение, чтобы поддерживать активность
    checkServerConnection().catch(() => {});
            return;
  }
  
  if (alarm.name === 'connectionCheck' || alarm.name === 'connectionCheckLong' || alarm.name === 'connectionCheckAggressive') {
    // КРИТИЧНО: Загружаем состояние при каждом срабатывании alarm (принудительно)
    // Service worker может быть перезапущен, и состояние могло быть потеряно
    await loadConnectionState(true);
    
    const timeSinceLastCheck = Date.now() - connectionState.lastCheck;
    
    // Для агрессивной проверки - только если нет подключения (каждые 5 секунд)
    if (alarm.name === 'connectionCheckAggressive') {
      if (!connectionState.isOnline) {
        await checkServerConnection();
      }
        return;
      }
    
    // Для обычной проверки - всегда проверяем (каждые 15 секунд)
    // Это гарантирует, что состояние всегда актуально
    if (alarm.name === 'connectionCheck') {
      await checkServerConnection();
      if (!connectionState.isOnline) {
        await attemptReconnectWithBackoff();
      }
      return;
    }
    
    // Для длительной проверки - всегда проверяем (каждую минуту)
    if (alarm.name === 'connectionCheckLong') {
      await checkServerConnection();
      // Также делаем warm-up для поддержания доверия браузера
      // Это особенно важно после длительного простоя
      warmUpConnection();
            return;
    }
  }
});

// Попытки переподключения с экспоненциальной задержкой (до 3 попыток)
async function attemptReconnectWithBackoff() {
  const maxAttempts = 3;
  for (let i = 0; i < maxAttempts; i++) {
    const delay = Math.min(1000 * Math.pow(2, i), 8000);
    await new Promise(r => setTimeout(r, delay));
    const ok = await checkServerConnection();
    if (ok) {
      // Соединение восстановлено — просим вкладки реинициализировать hover
      broadcastReinitHover();
      break;
    }
  }
}

// Обработка очереди запросов при восстановлении связи
async function processRequestQueue() {
  if (requestQueue.length === 0) return;
  
  // Обработка очереди запросов (без console.log для production)
  const queueCopy = [...requestQueue];
  requestQueue.length = 0;
  
  for (const request of queueCopy) {
    try {
      if (request.type === 'hover_url') {
        // Повторяем hover запрос
        const res = await scanHover(request.url);
        if (request.tabId) {
          chrome.tabs.sendMessage(request.tabId, {
            type: 'hover_result',
            url: request.url,
            res: res,
            mouseX: request.mouseX,
            mouseY: request.mouseY
          });
        }
      } else if (request.type === 'check_url') {
        // Повторяем check запрос
        const res = await scanUrl(request.url, false);
        const verdict = res.safe === false ? 'malicious' : res.safe === true ? 'clean' : 'unknown';
        const cfg = await getConfig();
        maybeNotify(cfg, verdict, request.url);
      }
    } catch (e) {
      console.error('Ошибка при обработке запроса из очереди:', e);
    }
  }
}

// Добавление запроса в очередь
function queueRequest(request) {
  if (requestQueue.length >= MAX_QUEUE_SIZE) {
    requestQueue.shift(); // Удаляем самый старый
  }
  requestQueue.push({
    ...request,
    timestamp: Date.now()
  });
}

// Отправка статуса подключения всем вкладкам
function broadcastConnectionStatus(isOnline) {
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'connection_status',
          isOnline: isOnline
        }).catch(() => {
          // Игнорируем ошибки (вкладка может быть недоступна)
        });
      }
    });
  });
}

function broadcastReinitHover() {
  try {
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        if (tab.id) {
          chrome.tabs.sendMessage(tab.id, { type: 'reinit_hover' }).catch(() => {});
        }
      });
    });
  } catch (_) {}
}

async function requestWsAnalysis(type, payload = {}, options = {}) {
  // КРИТИЧНО: Сначала проверяем, доступен ли WebSocket
  const wsAvailable = wsClient.ws && wsClient.ws.readyState === WebSocket.OPEN;
  
  // Если WebSocket не подключен, сразу используем REST
  if (!wsAvailable) {
    console.log('[Aegis] WebSocket not connected, using REST API directly');
    try {
      return await requestRestFallback(type, payload);
    } catch (restError) {
      // Пробуем подключиться к WebSocket перед fallback
      try {
        await wsClient.ensureConnected();
        if (wsClient.ws && wsClient.ws.readyState === WebSocket.OPEN) {
          return await wsClient.request(type, payload, options);
        }
      } catch (wsError) {
        console.warn('[Aegis] WebSocket connection failed, using REST:', wsError?.message);
      }
      throw restError;
    }
  }
  
  try {
    const response = await wsClient.request(type, payload, options);
    console.log('[Aegis WS] Response received (full):', JSON.stringify(response).substring(0, 500));
    
    // КРИТИЧНО: Проверяем, что response содержит правильные данные
    if (response && typeof response === 'object') {
      let result = response;
      
      // Если response содержит payload (WebSocket формат), извлекаем его
      if (response.payload && typeof response.payload === 'object') {
        console.log('[Aegis WS] Extracting payload from response, payload.safe:', response.payload.safe, 'payload.threat_type:', response.payload.threat_type);
        result = response.payload;
      }
      // Если response содержит data
      else if (response.data && typeof response.data === 'object') {
        console.log('[Aegis WS] Extracting data from response, data.safe:', response.data.safe);
        result = response.data;
      }
      // Если response уже содержит safe напрямую, используем как есть
      else if ('safe' in response) {
        console.log('[Aegis WS] Response has safe field directly:', response.safe, 'threat_type:', response.threat_type);
        result = response;
      }
      // Если response не содержит safe, но содержит другие поля - логируем
      else {
        console.warn('[Aegis WS] Response does not contain safe field!', Object.keys(response));
        // Пробуем найти результат в других полях
        if (response.result && typeof response.result === 'object') {
          result = response.result;
        }
      }
      
      // КРИТИЧНО: Нормализуем результат перед возвратом
      // Это гарантирует что safe всегда явно true/false/null
      const normalized = normalizeAnalysisPayload(result, payload.url);
      if (normalized) {
        connectionState.isOnline = true;
        connectionState.lastCheck = Date.now();
        connectionState.retryCount = 0;
        await saveConnectionState();
        console.log('[Aegis WS] Returning normalized result - safe:', normalized.safe, 'threat_type:', normalized.threat_type);
        return normalized;
      }
      
      // Если нормализация не удалась, возвращаем как есть
      connectionState.isOnline = true;
      connectionState.lastCheck = Date.now();
      connectionState.retryCount = 0;
      await saveConnectionState();
      console.log('[Aegis WS] Returning response as-is (normalization failed):', JSON.stringify(response).substring(0, 300));
      return response;
    }
    
    // Если response не объект - это ошибка
    console.error('[Aegis WS] Invalid response format:', typeof response, response);
    throw new Error('Invalid response format from WebSocket');
  } catch (error) {
    const errorMsg = error?.message || String(error) || 'WebSocket error';
    const closeCode = error?.closeCode;
    console.warn('[Aegis WS] Request failed, trying REST fallback:', errorMsg, closeCode ? `(code: ${closeCode})` : '');
    
    // КРИТИЧНО: Всегда пробуем REST fallback при любой ошибке WebSocket
    try {
      console.log('[Aegis] Falling back to REST API');
      const restResult = await requestRestFallback(type, payload);
      // Успешный fallback - возвращаем результат
      return restResult;
    } catch (restError) {
      // Если и REST не работает, выбрасываем более понятную ошибку
      console.error('[Aegis] Both WebSocket and REST failed:', restError);
      const combinedError = new Error(`Сервер недоступен: ${restError?.message || errorMsg}`);
      combinedError.originalError = error;
      combinedError.restError = restError;
      throw combinedError;
    }
  }
}

async function requestRestFallback(type, payload) {
  const apiBase = await getApiBase();
  const apiKey = await getApiKey();
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey) headers['X-API-Key'] = apiKey;
  
  let endpoint = '/check/url';
  let body = {};
  
  if (type === 'analyze_url') {
    endpoint = '/check/url';
    body = { url: payload.url };
    if (payload.context) {
      headers['X-Request-Source'] = payload.context;
    }
  } else if (type === 'analyze_file_hash') {
    endpoint = '/check/file';
    body = { file_hash: payload.hash || payload.file_hash };
  } else {
    throw new Error(`Unsupported type for REST fallback: ${type}`);
  }
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);
  
  try {
    const url = `${apiBase}${endpoint}`;
    console.log('[Aegis REST] Requesting:', url.replace(/api_key=[^&]+/, 'api_key=***'));
    
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      mode: 'cors',
      cache: 'no-cache'
    });
    
    clearTimeout(timeoutId);
    
    if (!res.ok) {
      let errorText = '';
      try {
        errorText = await res.text();
      } catch (_) {
        errorText = `HTTP ${res.status}`;
      }
      throw new Error(`HTTP ${res.status}: ${errorText}`);
    }
    
    const data = await res.json();
    console.log('[Aegis REST] Raw response:', JSON.stringify(data).substring(0, 200));
    
    // КРИТИЧНО: Убеждаемся, что данные в правильном формате
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid response format from server');
    }
    
    // КРИТИЧНО: Нормализуем ответ для совместимости с WebSocket форматом
    // НЕ ставим safe: true по умолчанию - это критическая ошибка безопасности!
    // Если safe не указан явно, проверяем threat_type - если есть, значит небезопасно
    let safeValue = null;
    
    // КРИТИЧНО: Проверяем явные значения safe
    if (data.safe === true) {
      // Явно безопасно - но проверяем что нет threat_type (противоречие)
      if (data.threat_type) {
        console.warn('[Aegis REST] Contradiction: safe=true but threat_type present:', data.threat_type);
        // Если есть threat_type, но safe=true - это ошибка, считаем небезопасно
        safeValue = false;
      } else {
        safeValue = true;
      }
    } else if (data.safe === false) {
      // Явно небезопасно
      safeValue = false;
    } else if (data.safe === null || data.safe === undefined) {
      // safe не указан - определяем по threat_type
      if (data.threat_type) {
        // Если есть threat_type, но safe не указан - значит небезопасно
        console.log('[Aegis REST] safe is null but threat_type present, setting safe=false');
        safeValue = false;
      } else {
        // Нет ни safe, ни threat_type - неизвестно
        safeValue = null;
      }
    } else {
      // Неожиданное значение - логируем и считаем неизвестно
      console.warn('[Aegis REST] Unexpected safe value:', data.safe, 'treating as null');
      safeValue = null;
    }
    
    const normalized = {
      safe: safeValue,
      threat_type: data.threat_type || null,
      details: data.details || data.message || '',
      source: data.source || 'rest_fallback',
      url: payload.url || null
    };
    
    console.log('[Aegis REST] Normalized response - safe:', normalized.safe, 'threat_type:', normalized.threat_type);
    
    connectionState.isOnline = true;
    connectionState.lastCheck = Date.now();
    connectionState.retryCount = 0;
    await saveConnectionState();
    
    console.log('[Aegis REST] Success:', normalized);
    return normalized;
  } catch (err) {
    clearTimeout(timeoutId);
    console.error('[Aegis REST] Error:', err);
    throw err;
  }
}

// КРИТИЧНО: Нормализация результатов анализа для единообразной обработки
function normalizeAnalysisPayload(payload, url) {
  if (!payload || typeof payload !== 'object') {
    console.warn('[Aegis] normalizeAnalysisPayload: invalid payload', payload);
    return null;
  }
  
  // КРИТИЧНО: Нормализуем safe - должен быть явно true, false или null
  // Не полагаемся на truthy/falsy значения
  let safeValue = null;
  if (payload.safe === true) {
    safeValue = true;
  } else if (payload.safe === false) {
    safeValue = false;
  } else if (payload.threat_type) {
    // КРИТИЧНО: Если есть threat_type, но safe не указан - значит небезопасно
    safeValue = false;
  } else {
    // Иначе неизвестно
    safeValue = null;
  }
  
  // КРИТИЧНО: Нормализуем threat_type
  const threatType = payload.threat_type || null;
  
  // КРИТИЧНО: Если safe === false, но нет threat_type - добавляем общий
  if (safeValue === false && !threatType) {
    // Это небезопасный URL, но тип угрозы не указан
    // Оставляем threat_type как null, но safe остается false
  }
  
  const result = {
    safe: safeValue,
    threat_type: threatType,
    details: payload.details || payload.message || null,
    source: payload.source || 'websocket',
    url: url || payload.url || null
  };
  
  // КРИТИЧНО: Сохраняем дополнительные поля если есть
  if (payload.confidence !== undefined) result.confidence = payload.confidence;
  if (payload.timestamp !== undefined) result.timestamp = payload.timestamp;
  if (payload.external_scans !== undefined) result.external_scans = payload.external_scans;
  
  console.log('[Aegis] normalizeAnalysisPayload result - safe:', result.safe, 'threat_type:', result.threat_type, 'source:', result.source);
  return result;
}

async function scanUrl(url, useCache = true) {
  if (useCache) {
    const cached = getCached(url);
    if (cached) {
      console.log('[Aegis] scanUrl returning cached result, safe:', cached.safe, 'threat_type:', cached.threat_type);
      return cached;
    }
  }

  try {
    console.log('[Aegis] scanUrl requesting analysis for:', url);
    const payload = await requestWsAnalysis('analyze_url', { url, context: 'link_check' });
    console.log('[Aegis] scanUrl received payload:', JSON.stringify(payload).substring(0, 300));
    const normalized = normalizeAnalysisPayload(payload, url) || { safe: null, source: 'unknown' };
    console.log('[Aegis] scanUrl normalized:', JSON.stringify(normalized).substring(0, 300), 'safe:', normalized.safe);
    const enriched = await enrichWithFileAnalysis(url, normalized);
    console.log('[Aegis] scanUrl enriched:', JSON.stringify(enriched).substring(0, 300), 'safe:', enriched.safe);
    setCached(url, enriched);
    return enriched;
  } catch (error) {
    console.error('[Aegis] scanUrl failed:', error);
    // КРИТИЧНО: Возвращаем null для safe, чтобы показать, что проверка не удалась
    const fallback = {
      safe: null, // Не можем определить безопасность
      details: error?.message || 'Ошибка анализа. Повторите попытку.',
      source: 'error',
      threat_type: null
    };
    return await enrichWithFileAnalysis(url, fallback);
  }
}

async function scanHover(url) {
  chrome.storage.local.set({ lastHoverActivity: Date.now() }).catch(() => {});

  try {
    const payload = await requestWsAnalysis('analyze_url', { url, context: 'hover' });
    const normalized = normalizeAnalysisPayload(payload, url) || { safe: null, source: 'unknown' };
    return await enrichWithFileAnalysis(url, normalized);
  } catch (error) {
    console.error('[Aegis] scanHover failed:', error);
    // КРИТИЧНО: Возвращаем null для safe, чтобы показать, что проверка не удалась
    const fallback = {
      safe: null, // Не можем определить безопасность
      details: error?.message || 'Ошибка анализа. Повторите попытку.',
      source: 'error',
      threat_type: null
    };
    return await enrichWithFileAnalysis(url, fallback);
  }
}

function maybeNotify(cfg, verdict, url) {
  if (!cfg.notify) return;
  if (verdict === 'malicious' || verdict === 'suspicious') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/logo.png',
      title: verdict === 'malicious' ? 'Опасная ссылка' : 'Подозрительная ссылка',
      message: `${url}`
    });
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'save_api_key') {
    chrome.storage.sync.set(
      { apiKey: msg.apiKey, account: msg.account || true },
      () => {
        wsClient.forceReconnect();
        sendResponse({ ok: true });
      }
    );
    return true;
  }
  if (!msg || typeof msg !== 'object') {
    return false;
  }

  if (msg.type === 'antivirus_toggle') {
    chrome.storage.sync.get(DEFAULTS, (cfg) => {
      cfg.antivirusEnabled = msg.enabled;
      chrome.storage.sync.set(cfg);
      sendResponse && sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.type === 'hover_ping') {
    sendResponse({ ok: true, ts: Date.now() });
    return true;
  }

  if (msg.type === 'hover_diagnostic') {
    sendResponse({
      connectionState: connectionState,
      cacheSize: cache.size,
      requestQueueSize: requestQueue.length,
      keepAlivePortsCount: 0, // Manifest V3 - порты не используются
      timestamp: Date.now()
    });
    return true;
  }

  if (msg.type === 'settings_updated') {
    chrome.storage.sync.set(msg.settings, () => {
      sendResponse && sendResponse({ ok: !chrome.runtime.lastError });
    });
    return true;
  }

  if (msg.type === 'check_url') {
    const url = msg.url;
    getConfig().then(async (cfg) => {
      if (!cfg.antivirusEnabled || !cfg.linkCheck) {
        sendResponse && sendResponse({ ok: false, error: 'disabled' });
        return;
      }
      const res = await scanUrl(url, false);
      const verdict = res.safe === false ? 'malicious' : res.safe === true ? 'clean' : 'unknown';
      maybeNotify(cfg, verdict, url);
      sendResponse && sendResponse({ ok: true, result: res });
    });
    return true;
  }

  if (msg.type === 'analyze_url') {
    const url = msg.url;
    (async () => {
      try {
        console.log('[Aegis] ws_analyze_url request for:', url);
        const payload = await requestWsAnalysis('analyze_url', { url, context: msg.context || 'popup' });
        console.log('[Aegis] ws_analyze_url payload received:', JSON.stringify(payload).substring(0, 300));
        const normalized = normalizeAnalysisPayload(payload, url) || { safe: null, source: 'unknown' };
        console.log('[Aegis] ws_analyze_url normalized:', JSON.stringify(normalized).substring(0, 300), 'safe:', normalized.safe);
        const enriched = await enrichWithFileAnalysis(url, normalized);
        console.log('[Aegis] ws_analyze_url enriched:', JSON.stringify(enriched).substring(0, 300), 'safe:', enriched.safe);
        sendResponse({ ok: true, data: enriched });
      } catch (error) {
        console.error('[Aegis] ws_analyze_url error:', error);
        // КРИТИЧНО: Возвращаем null для safe, чтобы показать, что проверка не удалась
        const fallback = {
          safe: null,
          details: error?.message || 'Ошибка анализа',
          source: 'error',
          threat_type: null
        };
        const enriched = await enrichWithFileAnalysis(url, fallback).catch(() => fallback);
        sendResponse({ ok: true, data: enriched }); // Всегда ok: true, чтобы показать результат
      }
    })();
    return true;
  }

  if (msg.type === 'hover_url') {
    const url = msg.url;
    const tabId = sender && sender.tab && sender.tab.id;
    
    getConfig().then(async (cfg) => {
      if (!cfg.antivirusEnabled || !cfg.hoverScan) {
        return;
      }
      const accData = await new Promise(r => chrome.storage.sync.get(['account', 'apiKey'], r));
      const hasAccount = !!accData.account;
      const hasApiKey = !!accData.apiKey;
      if (!hasAccount || !hasApiKey) {
        if (tabId != null) {
          chrome.tabs.sendMessage(tabId, {
            type: 'hover_result',
            url,
            res: {
              safe: null,
              details: 'Войдите в аккаунт, чтобы включить Hover-анализ',
              source: 'error'
            },
            mouseX: msg.mouseX,
            mouseY: msg.mouseY
          });
        }
        return;
      }
      
      try {
        // КРИТИЧНО: Проверяем кэш перед запросом
        const cached = getCached(url);
        let res = cached;
        
        // КРИТИЧНО: Если кэша нет или он истек - выполняем запрос
        if (!cached) {
          const timeSinceLastCheck = Date.now() - connectionState.lastCheck;
          if (timeSinceLastCheck > 60000) { // Если прошло больше минуты
            warmUpConnection().catch(() => {});
          }

          // КРИТИЧНО: Выполняем анализ hover
          res = await scanHover(url);
          
          console.log('[Aegis] hover_url: scanHover result - safe:', res?.safe, 'threat_type:', res?.threat_type, 'source:', res?.source);

          // После каждого запроса проверяем состояние подключения
          if (res && res.source === 'error') {
            // Если была ошибка - проверяем подключение сразу
            await checkServerConnection().catch(() => {});
          } else if (res && (typeof res.safe === 'boolean' || res.safe === null)) {
            // КРИТИЧНО: Кэшируем результат только если он валидный (safe: true/false/null)
            // НЕ кэшируем если res === null или undefined
            setCached(url, res);
            console.log('[Aegis] hover_url: cached result for:', url, 'safe:', res.safe);
          } else {
            console.warn('[Aegis] hover_url: invalid result, not caching:', res);
          }
        } else {
          // Кэш есть, но проверяем подключение периодически (каждые 30 секунд)
          // чтобы не потерять связь при длительном простое
          const timeSinceLastCheck = Date.now() - connectionState.lastCheck;
          if (timeSinceLastCheck > 30000) { // 30 секунд
            // Проверяем подключение в фоне (не блокируем ответ)
            // Это гарантирует, что состояние всегда актуально
            checkServerConnection().catch(() => {});
          }
        }
        
        if (tabId != null && res) {
          console.log('[Aegis] hover_url: sending result to tab:', tabId, 'safe:', res.safe, 'threat_type:', res.threat_type, 'source:', res.source);
          chrome.tabs.sendMessage(tabId, { 
            type: 'hover_result', 
            url, 
            res, 
            mouseX: msg.mouseX, 
            mouseY: msg.mouseY 
          }).catch(err => {
            console.error('[Aegis] Failed to send hover_result to tab:', err);
          });
        } else {
          console.log('[Aegis] hover_url: not sending result (tabId:', tabId, 'res:', res, ')');
        }
      } catch (e) {
        // При ошибке отправляем сообщение об ошибке
        if (tabId != null) {
          chrome.tabs.sendMessage(tabId, {
            type: 'hover_result',
            url: url,
            res: { safe: null, details: 'Ошибка при проверке', source: 'error' },
            mouseX: msg.mouseX,
            mouseY: msg.mouseY
          });
        }
      }
    });
  }
  
  if (msg && msg.type === 'get_connection_status') {
    // Возвращаем статус подключения
    sendResponse({ isOnline: connectionState.isOnline });
    return true;
  }
  
  return false;
});

// БЕЗОПАСНОСТЬ: Убрана автоматическая инжекция скриптов во все вкладки
// Content scripts теперь инжектируются только через manifest.json
// Инжекция через scripting API только по явному действию пользователя (activeTab)

// Запускаем мониторинг подключения при старте расширения
chrome.runtime.onStartup.addListener(() => {
  loadConnectionState().then(() => {
    startConnectionMonitoring();
    // КРИТИЧНО: Делаем warm-up запрос при старте
    // Это гарантирует, что браузер доверяет серверу
    warmUpConnection().finally(() => {
      broadcastReinitHover();
    });
  });
});

chrome.runtime.onInstalled.addListener((details) => {
  loadConnectionState().then(() => {
    startConnectionMonitoring();
    // КРИТИЧНО: Делаем warm-up запрос при установке/обновлении
    // Это особенно важно для новых пользователей
    warmUpConnection().finally(() => {
      broadcastReinitHover();
    });
    
    // Если это первая установка (не обновление)
    if (details.reason === 'install') {
      // Делаем дополнительный warm-up через 2 секунды
      // для гарантии, что браузер установил доверие
      setTimeout(() => warmUpConnection(), 2000);
    }
  });
});

if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    analyzeDownloadItem(downloadItem).catch(() => {});
  });
}


// КРИТИЧНО: Manifest V3 - keep-alive порты больше не используются
// Service Worker управляется через chrome.alarms API
// Обработчик onConnect удален, так как порты не используются

// КРИТИЧНО: Сохранение состояния перед остановкой Service Worker
// Это позволяет восстановить состояние после перезапуска
chrome.runtime.onSuspend.addListener(() => {
  // Сохраняем только состояние подключения, но НЕ сохраняем вердикты (hoverCache, анализ файлов)
  chrome.storage.local.set({
    connectionState: connectionState,
    suspendedAt: Date.now()
  }).catch(() => {});
  // persistFileAnalysisCache больше не сохраняет данные в storage (только in-memory)
  persistFileAnalysisCache().catch(() => {});
});

// КРИТИЧНО: Восстановление состояния после перезапуска Service Worker
async function restoreStateAfterRestart() {
  try {
    const stored = await new Promise(r => chrome.storage.local.get(['connectionState', 'suspendedAt'], r));
    
    // Восстанавливаем состояние подключения
    if (stored.connectionState) {
      connectionState = { ...connectionState, ...stored.connectionState };
      // Если прошло много времени с момента остановки - проверяем подключение
      if (stored.suspendedAt) {
        const timeSinceSuspend = Date.now() - stored.suspendedAt;
        if (timeSinceSuspend > 60000) { // Больше минуты
          connectionState.lastCheck = 0; // Принудительная проверка
        }
      }
    }
  } catch (e) {
    // Игнорируем ошибки восстановления
  }
}

// КРИТИЧНО: Обработчик изменений storage для автоматического обновления
// Когда popup обновляет apiKey/apiBase, hover должен использовать новые значения
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'sync') {
    if (changes.apiKey || changes.apiBase) {
      if (changes.apiBase) {
        const normalized = normalizeApiBaseUrl(changes.apiBase.newValue);
        if (normalized !== changes.apiBase.newValue) {
          try {
            chrome.storage.sync.set({ apiBase: normalized }, () => chrome.runtime?.lastError && void 0);
          } catch (_) {
            // ignore
          }
          return;
        }
      }
      try {
        console.debug('[Aegis Background] Storage updated:', { 
          apiKeyChanged: !!changes.apiKey, 
          apiBaseChanged: !!changes.apiBase 
        });
        // При изменении apiKey/apiBase делаем warm-up для обновления соединения
        warmUpConnection().catch(() => {});
        wsClient.forceReconnect();
      } catch(_) {}
    }
  }
});

// Восстанавливаем состояние и запускаем мониторинг при активации service worker
// Это срабатывает каждый раз, когда service worker активируется
restoreStateAfterRestart().then(() => {
  loadConnectionState().then(() => {
    startConnectionMonitoring();
    // КРИТИЧНО: Делаем warm-up запрос при активации service worker
    // Это гарантирует, что браузер доверяет серверу даже после перезапуска
    warmUpConnection().finally(() => {
      // Пробуем подключиться к WebSocket, но не блокируем работу при ошибке
      wsClient.ensureConnected().catch((err) => {
        console.warn('[Aegis] WebSocket initialization failed, will use REST fallback:', err?.message);
        // Помечаем, что WebSocket недоступен, чтобы сразу использовать REST
        connectionState.isOnline = false;
        saveConnectionState();
      });
      broadcastReinitHover();
    });
  });
});