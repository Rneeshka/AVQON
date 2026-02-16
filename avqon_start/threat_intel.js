// threat_intel.js
// Модуль агрегатора внешних источников угроз и эвристического анализа для AVQON.
// Выполняется внутри background Service Worker (Manifest V3).
// ВАЖНО: Все сетевые запросы должны быть лёгкими и с жёсткими таймаутами.

// ===== КОНСТАНТЫ ХРАНЕНИЯ И TTL =====
const TI_STORAGE_KEYS = {
  PHISHTANK: 'ti_phishtank_feed',
  OPENPHISH: 'ti_openphish_feed',
  CROWD_CACHE: 'ti_crowd_cache', // локальный кэш валидации крауд-отчётов
  ABUSEIPDB_CACHE: 'ti_abuseipdb_cache' // кэш проверок IP через AbuseIPDB
};

// TTL для локальных кэшей (мс)
const TI_TTLS = {
  PHISHTANK: 2 * 60 * 60 * 1000, // 2 часа
  OPENPHISH: 60 * 60 * 1000,     // 1 час
  CROWD_CACHE: 6 * 60 * 60 * 1000, // 6 часов
  ABUSEIPDB_CACHE: 24 * 60 * 60 * 1000 // 24 часа (IP репутация меняется реже)
};

// AbuseIPDB API ключ (можно настроить через chrome.storage.sync)
// По умолчанию используем бесплатный тариф (1000 запросов/день)
const ABUSEIPDB_API_KEY_STORAGE_KEY = 'abuseipdb_api_key';
const ABUSEIPDB_API_BASE = 'https://api.abuseipdb.com/api/v2';

// Имя alarm для обновления внешних фидов
const TI_ALARM_UPDATE_NAME = 'ti_update_feeds';
const TI_ALARM_UPDATE_PERIOD_MINUTES = 60;
// Синхронизация крауд‑кэша с бэкенда (GET /crowd/summary)
const TI_ALARM_CROWD_SYNC = 'ti_crowd_sync';
const TI_ALARM_CROWD_SYNC_PERIOD_MINUTES = 60;

// ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====

function ti_safeJsonParse(text, fallback = null) {
  try {
    return JSON.parse(text);
  } catch (_) {
    return fallback;
  }
}

async function ti_fetchWithTimeout(
  url,
  { method = 'GET', headers = {}, body = null, timeoutMs = 10000 } = {}
) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      headers,
      body,
      signal: controller.signal,
      cache: 'no-store',
      redirect: 'follow'
    });
    return res;
  } catch (e) {
    if (e && e.name === 'AbortError') {
      throw new Error('timeout');
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function ti_normalizeUrlForMatch(rawUrl) {
  if (!rawUrl) return '';
  try {
    const u = new URL(rawUrl);
    u.hash = '';
    // Убираем стандартный порт
    if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) {
      u.port = '';
    }
    return u.toString();
  } catch (_) {
    return String(rawUrl).trim();
  }
}

function ti_extractHostname(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch (_) {
    return '';
  }
}

// Резолвинг IP-адреса домена (асинхронно через DNS lookup)
// В браузерном контексте используем fetch к домену и извлекаем IP из заголовков или делаем DNS lookup через внешний API
async function ti_resolveDomainToIP(hostname) {
  if (!hostname) return null;
  
  // Кэш IP резолвинга в памяти (на время сессии Service Worker)
  if (!ti_resolveDomainToIP._cache) {
    ti_resolveDomainToIP._cache = new Map();
  }
  
  const cached = ti_resolveDomainToIP._cache.get(hostname);
  if (cached && Date.now() - cached.timestamp < 5 * 60 * 1000) {
    return cached.ip;
  }
  
  // Используем публичный DNS over HTTPS API (Cloudflare)
  try {
    const dnsUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`;
    const res = await ti_fetchWithTimeout(dnsUrl, {
      headers: { 'Accept': 'application/dns-json' },
      timeoutMs: 5000
    });
    
    if (res && res.ok) {
      const json = await res.json();
      if (json && json.Answer && Array.isArray(json.Answer) && json.Answer.length > 0) {
        const ip = json.Answer[0].data;
        if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
          ti_resolveDomainToIP._cache.set(hostname, { ip, timestamp: Date.now() });
          return ip;
        }
      }
    }
  } catch (e) {
    console.warn('[AVQON TI] DNS resolution failed for', hostname, e && e.message);
  }
  
  return null;
}

// Простая проверка совпадения URL в списке
function ti_isUrlInFeed(url, feed) {
  if (!url || !feed || !Array.isArray(feed.urls)) return false;
  const normalized = ti_normalizeUrlForMatch(url);
  const hostname = ti_extractHostname(url);

  // Быстрый поиск по hostname
  if (feed.hostIndex && hostname && feed.hostIndex[hostname]) {
    return true;
  }

  // Фолбэк: линейный проход по ограниченному количеству записей
  const MAX_SCAN = 5000;
  for (let i = 0; i < feed.urls.length && i < MAX_SCAN; i += 1) {
    const entry = feed.urls[i];
    if (!entry || typeof entry !== 'string') continue;
    if (normalized === entry) return true;
  }
  return false;
}

// Строит индекс по хостам для быстрого поиска
function ti_buildHostIndex(urls) {
  const index = Object.create(null);
  if (!Array.isArray(urls)) return index;
  urls.forEach((u) => {
    const host = ti_extractHostname(u);
    if (!host) return;
    index[host] = true;
  });
  return index;
}

// ===== АГРЕГАТОР УГРОЗ =====

const ThreatIntelligenceAggregator = {
  _initialized: false,
  _feeds: {
    phishtank: null,
    openphish: null
  },

  async init() {
    if (this._initialized) return;
    this._initialized = true;

    await this._loadFromStorage().catch(() => {});

    // Планировщик обновления фидов
    try {
      chrome.alarms.create(TI_ALARM_UPDATE_NAME, {
        periodInMinutes: TI_ALARM_UPDATE_PERIOD_MINUTES
      });
      chrome.alarms.create(TI_ALARM_CROWD_SYNC, {
        periodInMinutes: TI_ALARM_CROWD_SYNC_PERIOD_MINUTES
      });
    } catch (_) {
      // alarms могут быть недоступны в тестовой среде
    }

    // Стартовое обновление в фоне (без ожидания)
    this.updateFeeds().catch(() => {});
    this.syncCrowdCache().catch(() => {});
  },

  /**
   * Синхронизация крауд‑кэша: GET /crowd/summary, сохранить в chrome.storage.local
   * в формате { timestamp, items } для _loadCrowdCacheForUrl.
   */
  async syncCrowdCache() {
    let apiBase = (typeof self !== 'undefined' && self.AVQON_CONFIG && self.AVQON_CONFIG.API_BASE) ||
      'https://avqon.com';
    try {
      const stored = await new Promise((r) => chrome.storage.sync.get(['apiBase'], (x) => r(x || {})));
      if (stored.apiBase) apiBase = stored.apiBase;
    } catch (_) {}
    apiBase = (apiBase || '').toString().replace(/\/+$/, '');
    const url = `${apiBase}/crowd/summary?limit=500`;
    try {
      const res = await ti_fetchWithTimeout(url, { timeoutMs: 12000 });
      if (!res || !res.ok) return;
      const data = await res.json().catch(() => null);
      if (!data || !Array.isArray(data.items)) return;
      const payload = {
        timestamp: Date.now(),
        items: data.items
      };
      await new Promise((resolve, reject) => {
        chrome.storage.local.set({ [TI_STORAGE_KEYS.CROWD_CACHE]: payload }, () => {
          if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
          else resolve();
        });
      });
      console.log('[AVQON TI] Crowd cache synced, items:', data.items.length);
    } catch (e) {
      console.warn('[AVQON TI] Crowd cache sync failed:', e && e.message);
    }
  },

  async _loadFromStorage() {
    return new Promise((resolve) => {
      chrome.storage.local.get(
        [TI_STORAGE_KEYS.PHISHTANK, TI_STORAGE_KEYS.OPENPHISH],
        (stored) => {
          const now = Date.now();

          const phish = stored[TI_STORAGE_KEYS.PHISHTANK];
          if (phish && phish.urls && phish.timestamp && now - phish.timestamp < TI_TTLS.PHISHTANK) {
            this._feeds.phishtank = {
              urls: phish.urls,
              hostIndex: ti_buildHostIndex(phish.urls),
              timestamp: phish.timestamp
            };
          }

          const open = stored[TI_STORAGE_KEYS.OPENPHISH];
          if (open && open.urls && open.timestamp && now - open.timestamp < TI_TTLS.OPENPHISH) {
            this._feeds.openphish = {
              urls: open.urls,
              hostIndex: ti_buildHostIndex(open.urls),
              timestamp: open.timestamp
            };
          }

          resolve();
        }
      );
    });
  },

  async _saveFeed(key, urls) {
    if (!Array.isArray(urls)) return;
    const payload = {
      urls,
      timestamp: Date.now()
    };
    return new Promise((resolve) => {
      chrome.storage.local.set({ [key]: payload }, resolve);
    });
  },

  async updateFeeds() {
    // Обновление фидов выполняем независимо, ошибки из одного источника не ломают остальные
    await Promise.all([
      this._updatePhishTank().catch((e) => {
        console.warn('[AVQON TI] PhishTank update failed:', e && e.message);
      }),
      this._updateOpenPhish().catch((e) => {
        console.warn('[AVQON TI] OpenPhish update failed:', e && e.message);
      })
    ]);
  },

  async _updatePhishTank() {
    // Публичный JSON‑фид активных фишинговых URL
    // В текущей версии публичный JSON‑фид может требовать API‑ключ и возвращать 403.
    // Если фид недоступен, мы не ломаем работу расширения — просто не обновляем локальный кэш.
    const PHISHTANK_URL = 'https://data.phishtank.com/data/online-valid.json';
    let res;
    try {
      res = await ti_fetchWithTimeout(PHISHTANK_URL, { timeoutMs: 15000 });
    } catch (e) {
      throw new Error(`PhishTank fetch error: ${e && e.message}`);
    }
    if (!res || !res.ok) {
      // Если PhishTank недоступен (403/404/503 и т.п.) — логируем и выходим без обновления
      throw new Error(`PhishTank HTTP ${res && res.status}`);
    }

    const json = await res.json().catch(() => null);
    if (!Array.isArray(json)) {
      throw new Error('PhishTank invalid JSON');
    }

    // Упрощённая структура: вытаскиваем только URL
    const urls = [];
    for (let i = 0; i < json.length; i += 1) {
      const entry = json[i];
      const url = entry && (entry.url || (entry.phish_detail_url && entry.phish_detail_url));
      if (!url) continue;
      urls.push(ti_normalizeUrlForMatch(url));
      if (urls.length >= 20000) break; // жёсткий лимит на размер
    }

    this._feeds.phishtank = {
      urls,
      hostIndex: ti_buildHostIndex(urls),
      timestamp: Date.now()
    };
    await this._saveFeed(TI_STORAGE_KEYS.PHISHTANK, urls);
    console.log('[AVQON TI] PhishTank feed updated, urls:', urls.length);
  },

  async _updateOpenPhish() {
    // OpenPhish: многие фиды требуют регистрации и лицензии.
    // Здесь используем публичный TXT‑фид из репозитория на GitHub (raw.githubusercontent.com).
    // ВАЖНО: этот URL должен быть согласован с host_permissions и CSP.
    const OPENPHISH_URL = 'https://raw.githubusercontent.com/openphish/public-feed/master/feed.txt';
    let res;
    try {
      res = await ti_fetchWithTimeout(OPENPHISH_URL, { timeoutMs: 15000 });
    } catch (e) {
      throw new Error(`OpenPhish fetch error: ${e && e.message}`);
    }
    if (!res || !res.ok) {
      // Если публичный фид OpenPhish недоступен (404 и т.п.), не считаем это фатальной ошибкой
      throw new Error(`OpenPhish HTTP ${res && res.status}`);
    }

    const text = await res.text();
    const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
    const urls = [];
    for (let i = 0; i < lines.length; i += 1) {
      urls.push(ti_normalizeUrlForMatch(lines[i]));
      if (urls.length >= 20000) break;
    }

    this._feeds.openphish = {
      urls,
      hostIndex: ti_buildHostIndex(urls),
      timestamp: Date.now()
    };
    await this._saveFeed(TI_STORAGE_KEYS.OPENPHISH, urls);
    console.log('[AVQON TI] OpenPhish feed updated, urls:', urls.length);
  },

  /**
   * Основной метод проверки URL по локальным TI‑фидám и крауд‑кэшу.
   * @param {string} url
   * @returns {Promise<{blacklistHit: boolean, hits: Array, crowd: object|null, ipReputation: object|null}>}
   */
  async checkUrl(url) {
    const result = {
      blacklistHit: false,
      hits: [],
      crowd: null,
      ipReputation: null
    };

    const phish = this._feeds.phishtank;
    if (phish && ti_isUrlInFeed(url, phish)) {
      result.blacklistHit = true;
      result.hits.push({
        source: 'phishtank',
        threat_type: 'phishing'
      });
    }

    const open = this._feeds.openphish;
    if (open && ti_isUrlInFeed(url, open)) {
      result.blacklistHit = true;
      result.hits.push({
        source: 'openphish',
        threat_type: 'phishing'
      });
    }

    // Локальный кэш крауд‑отчётов (аггрегированный бэкендом)
    result.crowd = await this._loadCrowdCacheForUrl(url).catch(() => null);

    // Проверка репутации IP через AbuseIPDB (асинхронно, не блокирует основной поток)
    const hostname = ti_extractHostname(url);
    if (hostname) {
      try {
        result.ipReputation = await this._checkIPReputation(hostname).catch(() => null);
      } catch (e) {
        console.warn('[AVQON TI] IP reputation check failed:', e && e.message);
      }
    }

    return result;
  },

  /**
   * Проверка репутации IP через AbuseIPDB API.
   * Использует бесплатный тариф (1000 запросов/день).
   * @param {string} hostname
   * @returns {Promise<{ip: string, abuseConfidenceScore: number, usageType: string, isPublic: boolean, isWhitelisted: boolean}|null>}
   */
  async _checkIPReputation(hostname) {
    // СНАЧАЛА проверяем, есть ли API‑ключ. Без ключа не делаем даже DNS‑запросы.
    const apiKey = await new Promise((resolve) => {
      try {
        chrome.storage.sync.get([ABUSEIPDB_API_KEY_STORAGE_KEY], (stored) => {
          resolve(stored && stored[ABUSEIPDB_API_KEY_STORAGE_KEY] ? stored[ABUSEIPDB_API_KEY_STORAGE_KEY] : null);
        });
      } catch (_) {
        resolve(null);
      }
    });

    // Если API‑ключ не настроен, полностью отключаем интеграцию AbuseIPDB
    if (!apiKey) {
      return null;
    }

    const ip = await ti_resolveDomainToIP(hostname);
    if (!ip) return null;

    // Проверяем кэш
    const cached = await this._loadAbuseIPDBCache(ip);
    if (cached) return cached;

    try {
      const url = `${ABUSEIPDB_API_BASE}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
      const res = await ti_fetchWithTimeout(url, {
        headers: {
          'Key': apiKey,
          'Accept': 'application/json'
        },
        timeoutMs: 8000
      });

      if (!res || !res.ok) {
        if (res.status === 429) {
          console.warn('[AVQON TI] AbuseIPDB rate limit exceeded');
        }
        return null;
      }

      const json = await res.json();
      if (json && json.data) {
        const data = json.data;
        const result = {
          ip: data.ipAddress || ip,
          abuseConfidenceScore: Number(data.abuseConfidenceScore || 0),
          usageType: data.usageType || 'unknown',
          isPublic: data.isPublic === true,
          isWhitelisted: data.isWhitelisted === true,
          countryCode: data.countryCode || null,
          lastReportedAt: data.lastReportedAt || null
        };

        // Сохраняем в кэш
        await this._saveAbuseIPDBCache(ip, result);
        return result;
      }
    } catch (e) {
      console.warn('[AVQON TI] AbuseIPDB API error:', e && e.message);
    }

    return null;
  },

  async _loadAbuseIPDBCache(ip) {
    return new Promise((resolve) => {
      chrome.storage.local.get([TI_STORAGE_KEYS.ABUSEIPDB_CACHE], (stored) => {
        const cache = stored[TI_STORAGE_KEYS.ABUSEIPDB_CACHE];
        if (!cache || !cache[ip]) {
          resolve(null);
          return;
        }

        const entry = cache[ip];
        const now = Date.now();
        if (!entry.timestamp || now - entry.timestamp > TI_TTLS.ABUSEIPDB_CACHE) {
          resolve(null);
          return;
        }

        resolve(entry.data);
      });
    });
  },

  async _saveAbuseIPDBCache(ip, data) {
    return new Promise((resolve) => {
      chrome.storage.local.get([TI_STORAGE_KEYS.ABUSEIPDB_CACHE], (stored) => {
        const cache = stored[TI_STORAGE_KEYS.ABUSEIPDB_CACHE] || {};
        cache[ip] = {
          data,
          timestamp: Date.now()
        };
        chrome.storage.local.set({ [TI_STORAGE_KEYS.ABUSEIPDB_CACHE]: cache }, resolve);
      });
    });
  },

  /**
   * Загрузка агрегированного результата крауд‑отчётов для URL из локального кэша.
   * Структура ожидается в формате:
   * { url: string, score: number, reports: number, lastReportAt: number }
   */
  async _loadCrowdCacheForUrl(url) {
    const key = TI_STORAGE_KEYS.CROWD_CACHE;
    const hostname = ti_extractHostname(url);
    if (!hostname) return null;

    return new Promise((resolve) => {
      chrome.storage.local.get([key], (stored) => {
        const payload = stored[key];
        if (!payload || !payload.items || !Array.isArray(payload.items)) {
          resolve(null);
          return;
        }

        const now = Date.now();
        if (!payload.timestamp || now - payload.timestamp > TI_TTLS.CROWD_CACHE) {
          resolve(null);
          return;
        }

        const items = payload.items;
        for (let i = 0; i < items.length; i += 1) {
          const item = items[i];
          if (!item || !item.hostname) continue;
          if (item.hostname === hostname) {
            resolve(item);
            return;
          }
        }
        resolve(null);
      });
    });
  },

  /**
   * Отправка крауд‑репорта на внешний бэкенд.
   * Ожидается, что базовый URL и ключи будут настроены на стороне сервера AVQON.
   * @param {{url: string, verdict?: 'suspicious'|'malicious', comment?: string|null, threat_type?: string|null}} payload
   */
  async submitCrowdReport(payload) {
    if (!payload || typeof payload.url !== 'string') {
      throw new Error('Invalid payload: url is required');
    }

    // Нормализуем URL и убеждаемся, что он валиден
    let normalizedUrl = payload.url.trim();
    if (!normalizedUrl) {
      throw new Error('Invalid payload: url is empty');
    }
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://' + normalizedUrl;
    }

    try {
      const urlObj = new URL(normalizedUrl);
      const domain = urlObj.hostname;
      console.log('[AVQON] Extracted domain for crowd report:', domain);
    } catch (e) {
      throw new Error(`Invalid URL format: ${payload.url}`);
    }

    // Гарантируем корректный вердикт для бэкенда
    let verdict = (payload.verdict || 'suspicious').toLowerCase();
    if (verdict !== 'suspicious' && verdict !== 'malicious') {
      verdict = 'suspicious';
    }

    const comment =
      typeof payload.comment === 'string' && payload.comment.trim().length > 0
        ? payload.comment.trim()
        : null;

    const threatTypeRaw = typeof payload.threat_type === 'string' ? payload.threat_type : '';
    const threat_type = threatTypeRaw.trim() || null;

    // По умолчанию шлём репорт в основной API_BASE на /crowd/report
    // Сам API_BASE берётся из глобальной конфигурации AVQON, если она доступна.
    const base =
      (typeof self !== 'undefined' && self.AVQON_CONFIG && self.AVQON_CONFIG.API_BASE) ||
      'https://avqon.com';

    const target = `${base.replace(/\/+$/, '')}/crowd/report`;

    const deviceId = await new Promise((resolve) => {
      try {
        chrome.storage.local.get(['device_id'], (st) => {
          if (st && st.device_id) {
            resolve(st.device_id);
          } else {
            const id = `dev_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`;
            chrome.storage.local.set({ device_id: id }, () => resolve(id));
          }
        });
      } catch (_) {
        resolve(`dev_${Date.now().toString(36)}`);
      }
    });

    const body = {
      url: normalizedUrl,
      verdict,
      comment,
      device_id: deviceId,
      reported_at: new Date().toISOString(),
      threat_type
    };

    // Логируем фактическое тело запроса для диагностики
    try {
      console.log('[AVQON] Sending crowd report for normalized URL:', normalizedUrl);
      console.log('[AVQON] Final crowd report URL field:', body.url);
      console.log('[AVQON] Sending crowd report body:', body);
    } catch (_) {
      // ignore logging errors
    }

    try {
      console.log('[AVQON] Full request URL:', target);
      console.log('[AVQON] Full request headers:', {
        'Content-Type': 'application/json'
      });
    } catch (_) {
      // ignore logging errors
    }

    const res = await ti_fetchWithTimeout(target, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body),
      timeoutMs: 8000
    }).catch((e) => {
      throw new Error(`Crowd report network error: ${e && e.message}`);
    });

    if (!res.ok) {
      const text = await res.text();
      console.error('[AVQON] Crowd report error response:', text);
      throw new Error(`Crowd report HTTP ${res.status}: ${text || 'unknown error'}`);
    }

    return true;
  },

  handleAlarm(alarmName) {
    if (alarmName === TI_ALARM_UPDATE_NAME) {
      this.updateFeeds().catch(() => {});
    } else if (alarmName === TI_ALARM_CROWD_SYNC) {
      this.syncCrowdCache().catch(() => {});
    }
  }
};

// ===== ЭВРИСТИЧЕСКИЙ ДВИЖОК =====

const HeuristicEngine = {
  /**
   * Оценивает риск для URL на основе локальных признаков и TI‑сигналов.
   * @param {string} url
   * @param {string} context - 'link_check' | 'hover' | 'popup' | 'context_menu' и т.д.
   * @param {object} tiSummary - результат ThreatIntelligenceAggregator.checkUrl
   * @param {{ sensitivityMode?: 'conservative'|'balanced'|'aggressive' }} [options] - режим чувствительности из настроек
   * @returns {{riskScore: number, riskLevel: 'SAFE'|'LOW_RISK'|'HIGH_RISK'|'CRITICAL', factors: Array}}
   */
  evaluateUrl(url, context, tiSummary, options) {
    let riskScore = 0;
    const factors = [];

    const normUrl = ti_normalizeUrlForMatch(url);
    const hostname = ti_extractHostname(url);

    // Сигналы из TI: попадание в фишинговые фиды значительно повышает риск
    if (tiSummary && tiSummary.blacklistHit && Array.isArray(tiSummary.hits)) {
      tiSummary.hits.forEach((hit) => {
        if (hit && hit.source === 'phishtank') {
          riskScore += 60;
          factors.push('PhishTank: URL в активном фишинговом списке');
        } else if (hit && hit.source === 'openphish') {
          riskScore += 60;
          factors.push('OpenPhish: URL в активном фишинговом списке');
        }
      });
    }

    // Крауд‑кэш: несколько независимых жалоб от пользователей
    if (tiSummary && tiSummary.crowd) {
      const c = tiSummary.crowd;
      const reports = Number(c.reports || 0);
      const score = Number(c.score || 0);
      if (reports >= 3 && score >= 0.7) {
        riskScore += 40;
        factors.push(`Краудсорсинг: ${reports} подтверждённых репортов по домену`);
      } else if (reports >= 1) {
        riskScore += 15;
        factors.push(`Краудсорсинг: есть пользовательские репорты (${reports})`);
      }
    }

    // Репутация IP через AbuseIPDB
    if (tiSummary && tiSummary.ipReputation) {
      const ipRep = tiSummary.ipReputation;
      const abuseScore = Number(ipRep.abuseConfidenceScore || 0);
      
      if (abuseScore >= 80) {
        riskScore += 50;
        factors.push(`IP репутация: очень высокий уровень злоупотреблений (${abuseScore}%)`);
      } else if (abuseScore >= 50) {
        riskScore += 30;
        factors.push(`IP репутация: высокий уровень злоупотреблений (${abuseScore}%)`);
      } else if (abuseScore >= 25) {
        riskScore += 15;
        factors.push(`IP репутация: умеренный уровень злоупотреблений (${abuseScore}%)`);
      }
      
      // Дополнительные сигналы из AbuseIPDB
      if (ipRep.usageType === 'hosting' || ipRep.usageType === 'datacenter') {
        riskScore += 10;
        factors.push('IP размещён на хостинге/датацентре (часто используется для массовых атак)');
      }
      
      if (ipRep.isWhitelisted === true) {
        riskScore -= 10; // Белый список снижает риск
        factors.push('IP находится в белом списке AbuseIPDB');
      }
    }

    // Анализ домена: свежие/подозрительные домены (без WHOIS, только эвристика по виду)
    if (hostname) {
      const labels = hostname.split('.');
      const sld = labels.length >= 2 ? labels[labels.length - 2] : hostname;

      if (sld.length >= 15) {
        riskScore += 10;
        factors.push('Очень длинное доменное имя, возможно случайно сгенерированное');
      }

      const digitCount = (sld.match(/\d/g) || []).length;
      if (digitCount >= 4) {
        riskScore += 10;
        factors.push('Много цифр в доменном имени');
      }

      const subdomainDepth = labels.length;
      if (subdomainDepth >= 4) {
        riskScore += 10;
        factors.push('Глубокая иерархия поддоменов');
      }

      const freeHostPatterns = [
        '000webhostapp.com',
        'herokuapp.com',
        'github.io',
        'pages.dev',
        'netlify.app',
        'firebaseapp.com'
      ];
      if (freeHostPatterns.some((p) => hostname.endsWith(p))) {
        riskScore += 20;
        factors.push('Домен размещён на популярном бесплатном/массовом хостинге');
      }

      const phishingKeywords = [
        'login',
        'signin',
        'verify',
        'secure',
        'account',
        'update',
        'support',
        'billing',
        'invoice',
        'bank',
        'paypal',
        'crypto'
      ];
      if (phishingKeywords.some((k) => hostname.includes(k))) {
        riskScore += 15;
        factors.push('Фишинговые ключевые слова в домене');
      }
    }

    // Анализ пути URL
    try {
      const u = new URL(normUrl);
      const pathLower = (u.pathname || '').toLowerCase();

      if (pathLower.includes('login') || pathLower.includes('signin')) {
        riskScore += 15;
        factors.push('Страница авторизации (login/signin) — целевой фишинг обычно здесь');
      }

      if (pathLower.includes('verify') || pathLower.includes('update')) {
        riskScore += 10;
        factors.push('Путь содержит verify/update — частый паттерн фишинга');
      }

      if (u.protocol === 'http:') {
        riskScore += 25;
        factors.push('Соединение без HTTPS');
      }

      // Анализ портов (нестандартные порты могут быть подозрительными)
      const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
      if (port !== 80 && port !== 443 && port < 1024) {
        riskScore += 10;
        factors.push(`Используется нестандартный системный порт (${port})`);
      }
    } catch (_) {
      // игнорируем ошибки парсинга URL
    }

    // Эвристика по длине и структуре URL
    if (normUrl.length > 200) {
      riskScore += 10;
      factors.push('Очень длинный URL (возможна попытка обфускации)');
    }

    // Проверка на подозрительные паттерны в URL
    const suspiciousPatterns = [
      /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly/i, // URL shorteners (могут скрывать фишинг)
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // Прямой IP вместо домена
      /[a-z0-9]{32,}/i // Длинные хеши (возможная обфускация)
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(normUrl)) {
        riskScore += 15;
        factors.push('Подозрительный паттерн в URL (возможна обфускация)');
        break; // Не накапливаем баллы за несколько паттернов
      }
    }

    // Бонусный вес, если анализ идёт по активному действию пользователя
    if (context === 'popup' || context === 'context_menu') {
      riskScore += 5;
    }

    const sensitivityMode = (options && options.sensitivityMode) || 'balanced';
    const riskLevel = this._classifyRisk(riskScore, sensitivityMode);
    return { riskScore, riskLevel, factors };
  },

  /**
   * Пороги по режиму: conservative — реже блокируем; aggressive — чаще.
   */
  _classifyRisk(score, sensitivityMode) {
    const mode = sensitivityMode || 'balanced';
    let highRiskThreshold = 51;
    let criticalThreshold = 81;
    if (mode === 'conservative') {
      highRiskThreshold = 71;
      criticalThreshold = 91;
    } else if (mode === 'aggressive') {
      highRiskThreshold = 41;
      criticalThreshold = 61;
    }
    if (score >= criticalThreshold) return 'CRITICAL';
    if (score >= highRiskThreshold) return 'HIGH_RISK';
    if (score >= 21) return 'LOW_RISK';
    return 'SAFE';
  }
};

// ===== РЕГИСТРАЦИЯ В ГЛОБАЛЬНОМ КОНТЕКСТЕ SERVICE WORKER =====

try {
  if (typeof self !== 'undefined') {
    self.ThreatIntelligenceAggregator = ThreatIntelligenceAggregator;
    self.HeuristicEngine = HeuristicEngine;
  }
} catch (_) {
  // ignore
}

// Инициализация при запуске / установке
try {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => {
      ThreatIntelligenceAggregator.init().catch(() => {});
    });
  }
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onStartup) {
    chrome.runtime.onStartup.addListener(() => {
      ThreatIntelligenceAggregator.init().catch(() => {});
    });
  }
  if (typeof chrome !== 'undefined' && chrome.alarms && chrome.alarms.onAlarm) {
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (!alarm || !alarm.name) return;
      ThreatIntelligenceAggregator.handleAlarm(alarm.name);
    });
  }
} catch (_) {
  // ignore
}

