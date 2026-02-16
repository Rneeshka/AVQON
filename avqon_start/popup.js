  const DEFAULTS = {
    antivirusEnabled: true,
    linkCheck: true,
    hoverScan: true,
    notify: true,
    apiBase: window.AVQON_CONFIG?.API_BASE || 'https://avqon.com',
    hoverTheme: 'classic',
    sensitivityMode: 'balanced'  // conservative | balanced | aggressive
  };

  const views = ['home', 'settings', 'customize', 'feedback', 'about', 'why'];
  const BADGE_TEXT = {
    ready: 'READY',
    safe: 'SAFE',
    clean: 'SAFE',
    malicious: 'DANGER',
    suspicious: 'WARN',
    unknown: 'UNKNOWN',
    disabled: 'OFF'
  };

  const elements = {
    statusBadge: document.getElementById('status-badge'),
    statusDot: document.getElementById('status-dot'),
    connectionText: document.getElementById('connection-text'),
    antivirusToggle: document.getElementById('antivirus-toggle'),
    hoverToggle: document.getElementById('opt-hover-scan'),
    mainAnalysisCard: document.getElementById('main-analysis-card'),
    statusHeadline: document.getElementById('status'),
    statusSubtitle: document.getElementById('toggle-subtitle'),
    statusText: document.getElementById('status-text'),
    analysisBadge: document.getElementById('analysis-badge'),
    resultEl: document.getElementById('result'),
    warningCard: document.getElementById('warning-card'),
    warningText: document.getElementById('warning-text')
  };

  const state = {
    settings: { ...DEFAULTS },
    connectionTimer: null,
    hoverTheme: 'classic',
    isServerConnected: null, // null = checking, true = connected, false = disconnected
    isScanning: false,
    scanResult: null, // null = no result, { safe: true/false/null, ... } = scan result
    sessionValidationTimer: null // Таймер для проверки валидности сессии
  };

  /**
   * Helpers
   */
  function sendRuntimeMessage(message) {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(response);
        });
      } catch (error) {
        reject(error);
      }
    });
  }

  function loadSettings() {
    return new Promise((resolve) => chrome.storage.sync.get(DEFAULTS, resolve));
  }

  function saveSettings(nextSettings) {
    return new Promise((resolve) => chrome.storage.sync.set(nextSettings, resolve));
  }

  function normalizeApiBase(value) {
    let base = (value || '').toString().trim();
    if (!base) return DEFAULTS.apiBase;
    
    // МИГРАЦИЯ: Автоматически обновляем старые URL на новые
    const oldUrl = base.toLowerCase();
    if (oldUrl.includes('api.aegis.builders') || oldUrl.includes('aegis.builders')) {
      console.log('[AVQON] Migrating old API URL:', base);
      base = window.AVQON_CONFIG?.API_BASE || DEFAULTS.apiBase;
      // Сохраняем обновленный URL
      chrome.storage.sync.set({ apiBase: base }, () => {
        console.log('[AVQON] Migrated API URL to:', base);
      });
    }
    
    if (!/^https?:\/\//i.test(base)) base = `https://${base}`;
    try {
      const url = new URL(base);
      url.pathname = url.pathname.replace(/\/proxy\/?$/, '') || '/';
      url.search = '';
      url.hash = '';
      return `${url.origin}${url.pathname}`.replace(/\/$/, '') || url.origin;
    } catch (_) {
      return DEFAULTS.apiBase;
    }
  }

  /**
   * UI state updates
   */
  /**
   * Обновляет badge в header (верхний правый угол)
   * КРИТИЧНО: Этот badge показывает общий статус системы, не статус сканирования
   */
  function setBadgeState(stateName) {
    const badge = elements.statusBadge;
    const text = BADGE_TEXT[stateName] || stateName?.toUpperCase() || 'READY';
    if (badge) {
      badge.className = `badge ${stateName || 'ready'}`;
      badge.textContent = text;
    }
    // КРИТИЧНО: analysisBadge управляется через setScanState(), не здесь
  }

  /**
   * Обновляет ТОЛЬКО статус подключения к серверу (верхняя карточка)
   * НЕ должен влиять на статус сканирования
   */
  function setConnectionState(isOnline, message) {
    // Сохраняем состояние подключения
    state.isServerConnected = isOnline;
    
    const dot = elements.statusDot;
    if (dot) {
      dot.classList.remove('online', 'offline', 'checking');
      if (isOnline === null || isOnline === undefined) {
        // Проверка подключения в процессе
        dot.classList.add('checking');
      } else {
        dot.classList.add(isOnline ? 'online' : 'offline');
      }
    }
    
    // КРИТИЧНО: Обновляем ТОЛЬКО connection text и status headline (верхняя карточка)
    if (elements.connectionText) {
      if (isOnline === null || isOnline === undefined) {
        elements.connectionText.textContent = 'Подключение к серверу...';
      } else {
        elements.connectionText.textContent = message || (isOnline ? 'Подключено' : 'Нет подключения');
      }
    }
    
    // КРИТИЧНО: Верхняя карточка показывает только статус подключения
    if (elements.statusHeadline) {
      if (isOnline === true) {
        elements.statusHeadline.textContent = 'Готово';
      } else if (isOnline === false) {
        elements.statusHeadline.textContent = 'Не готово';
      } else {
        elements.statusHeadline.textContent = 'Проверка подключения...';
      }
    }
  }

  /**
   * Обновляет ТОЛЬКО статус сканирования (средняя карточка)
   * НЕ влияет на статус подключения
   */
  function setScanState(isScanning, scanResult) {
    state.isScanning = isScanning;
    state.scanResult = scanResult;
    
    // КРИТИЧНО: Обновляем ТОЛЬКО statusText и analysisBadge (средняя карточка)
    if (isScanning) {
      // Сканирование в процессе
      if (elements.statusText) {
        elements.statusText.textContent = 'Проверяем...';
      }
      if (elements.analysisBadge) {
        elements.analysisBadge.className = 'badge scanning';
        elements.analysisBadge.textContent = 'SCANNING';
      }
    } else if (scanResult) {
      // Есть результат сканирования
      const verdict = resolveVerdict(scanResult);
      const map = {
        malicious: 'Опасно',
        suspicious: 'Подозрительно',
        safe: 'Безопасно',
        clean: 'Безопасно',
        unknown: 'Неизвестно'
      };
      
      if (elements.statusText) {
        elements.statusText.textContent = map[verdict] || 'Готово';
      }
      
      if (elements.analysisBadge) {
        const badgeState = verdict === 'malicious' ? 'malicious' : verdict || 'ready';
        elements.analysisBadge.className = `badge ${badgeState}`;
        elements.analysisBadge.textContent = BADGE_TEXT[badgeState] || 'READY';
      }
    } else {
      // Нет результата
      if (elements.statusText) {
        elements.statusText.textContent = 'Готово';
      }
      if (elements.analysisBadge) {
        elements.analysisBadge.className = 'badge ready';
        elements.analysisBadge.textContent = 'READY';
      }
    }
  }

  function showToast(message, type = 'info') {
    // Удаляем эмодзи и лишние символы для строгого стиля
    const raw = String(message || '');
    const withoutEmojis = raw.replace(
      /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27FF}]/gu,
      ''
    );
    const cleaned = withoutEmojis.trim();

    const existingContainer = document.getElementById('avqon-toast-container');
    const container = existingContainer || document.createElement('div');
    if (!existingContainer) {
      container.id = 'avqon-toast-container';
      container.style.cssText = `
        position: fixed;
        top: 16px;
        right: 16px;
        z-index: 10000;
        display: flex;
        flex-direction: column;
        gap: 8px;
        pointer-events: none;
      `;
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');

    // Цвет тонкой левой полосы в зависимости от типа
    let leftBorderColor = 'rgba(59,130,246,0.7)'; // info по умолчанию
    if (type === 'success') {
      leftBorderColor = 'rgba(16,185,129,0.7)'; // #10b981
    } else if (type === 'warning') {
      leftBorderColor = 'rgba(245,158,11,0.7)'; // #f59e0b
    } else if (type === 'error') {
      leftBorderColor = 'rgba(239,68,68,0.7)'; // #ef4444
    }

    toast.style.cssText = `
      min-width: 280px;
      max-width: 320px;
      padding: 12px 16px;
      border-radius: 8px;
      border: 1px solid rgba(255,255,255,0.08);
      border-left: 3px solid ${leftBorderColor};
      background: var(--surface, #0f172a);
      color: #e2e8f0;
      font-size: 13px;
      line-height: 1.5;
      font-weight: 400;
      box-shadow: 0 8px 20px rgba(0,0,0,0.3);
      transform: translateX(100%);
      opacity: 0;
      transition: transform 0.25s ease, opacity 0.25s ease;
      position: relative;
      pointer-events: auto;
      overflow: hidden;
    `;

    // Текст
    const textEl = document.createElement('div');
    textEl.textContent = cleaned || 'Сообщение';
    toast.appendChild(textEl);

    // Кнопка закрытия (показывается только при hover)
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.textContent = '✕';
    closeBtn.style.cssText = `
      position: absolute;
      top: 6px;
      right: 8px;
      padding: 0;
      margin: 0;
      border: none;
      background: transparent;
      color: #94a3b8;
      font-size: 11px;
      line-height: 1;
      cursor: pointer;
      opacity: 0;
      transition: opacity 0.15s ease;
    `;
    toast.appendChild(closeBtn);

    toast.addEventListener('mouseenter', () => {
      closeBtn.style.opacity = '1';
    });
    toast.addEventListener('mouseleave', () => {
      closeBtn.style.opacity = '0';
    });

    const removeToast = () => {
      toast.style.transform = 'translateX(100%)';
      toast.style.opacity = '0';
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
        if (container.childElementCount === 0 && container.parentNode) {
          container.parentNode.removeChild(container);
        }
      }, 250);
    };

    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      removeToast();
    });

    container.appendChild(toast);

    // Плавное появление
    requestAnimationFrame(() => {
      toast.style.transform = 'translateX(0)';
      toast.style.opacity = '1';
    });

    // Авто‑закрытие через 3.5 секунды
    setTimeout(removeToast, 3500);
  }

  // Для обратной совместимости
  function showInternalNotification(message, type = 'info') {
    showToast(message, type);
  }

  function toggleWarning(show, text) {
    if (!elements.warningCard) return;
    elements.warningCard.classList.toggle('hidden', !show);
    if (show && elements.warningText) {
      // КРИТИЧНО: Форматируем текст деталей - убираем упоминания VirusTotal, переводим на русский
      let formattedText = text || 'Обнаружены угрозы';
      
      // Убираем упоминания VirusTotal и технические детали
      formattedText = formattedText.replace(/VirusTotal[^.]*/gi, '');
      formattedText = formattedText.replace(/Local database:[^.]*/gi, '');
      formattedText = formattedText.replace(/undetected_ratio[^.]*/gi, '');
      formattedText = formattedText.replace(/young[^.]*/gi, '');
      formattedText = formattedText.replace(/uncertain[^.]*/gi, '');
      formattedText = formattedText.replace(/treated as unsafe/gi, '');
      formattedText = formattedText.replace(/\([^)]*\)/g, ''); // Убираем все в скобках
      
      // Переводим на русский
      formattedText = formattedText.replace(/Detected by external scan/gi, 'Обнаружено внешними системами безопасности');
      formattedText = formattedText.replace(/Detected by/gi, 'Обнаружено');
      formattedText = formattedText.replace(/malware/gi, 'вредоносное ПО');
      formattedText = formattedText.replace(/phishing/gi, 'фишинг');
      formattedText = formattedText.replace(/suspicious/gi, 'подозрительный');
      formattedText = formattedText.replace(/scam/gi, 'мошенничество');
      formattedText = formattedText.replace(/fraud/gi, 'мошенничество');
      
      // Очищаем от лишних пробелов и точек
      formattedText = formattedText.replace(/\s+/g, ' ').trim();
      formattedText = formattedText.replace(/^[.,\s]+|[.,\s]+$/g, '');
      
      // Если текст пустой после очистки, используем стандартный
      if (!formattedText || formattedText.length < 5) {
        formattedText = 'Обнаружены угрозы безопасности';
      }
      
      elements.warningText.textContent = formattedText;
    }
  }

  function applyAnalysisVerdict(verdict) {
    const card = elements.mainAnalysisCard;
    if (!card) return;
    const classes = ['analysis-safe', 'analysis-clean', 'analysis-malicious', 'analysis-suspicious', 'analysis-unknown'];
    card.classList.remove(...classes);
    if (verdict) {
      card.classList.add(`analysis-${verdict}`);
    }
  }

  function switchView(view) {
    views.forEach((name) => {
      const section = document.getElementById(`view-${name}`);
      const tab = document.getElementById(`tab-${name}`);
      const isActive = name === view;
      if (section) {
        if (isActive) {
          section.style.display = '';
          section.classList.add('active');
        } else {
          section.style.display = 'none';
          section.classList.remove('active');
        }
      }
      if (tab) {
        tab.classList.toggle('primary', isActive);
      }
    });
  }

  /**
   * Rendering logic
   */
  // КРИТИЧНО: Храним последний вердикт, чтобы не менять безопасный на опасный
  let lastVerdict = null;
  let lastUrl = null;
  let lastSafeResult = null;

  function renderResult(url, response) {
    if (!elements.resultEl) return;
    const res = response || {};
    const verdict = resolveVerdict(res);

    // КРИТИЧНО: Не меняем вердикт с безопасного на опасный для того же URL
    // Это предотвращает ситуацию, когда сайт сначала показывается как безопасный,
    // а потом меняется на опасный из-за устаревших данных в БД
    if (url === lastUrl) {
      if (lastVerdict === 'safe' && verdict === 'malicious') {
        console.warn('[Aegis Popup] Ignoring malicious verdict change from safe for same URL:', url);
        // Используем последний безопасный результат
        if (lastSafeResult) {
          renderResultInternal(url, lastSafeResult);
        }
        return;
      }
      // Если новый результат безопасный, сохраняем его
      if (verdict === 'safe' || verdict === 'clean') {
        lastSafeResult = res;
      }
    }
    
    // Обновляем последний вердикт и URL
    lastVerdict = verdict;
    lastUrl = url;
    
    renderResultInternal(url, res);
  }

  function renderResultInternal(url, response) {
    if (!elements.resultEl) return;
    const res = response || {};
    const verdict = resolveVerdict(res);

    // КРИТИЧНО: Обновляем только состояние сканирования (средняя карточка)
    setScanState(false, res); // Сканирование завершено
    
    applyAnalysisVerdict(verdict);
    
    // КРИТИЧНО: НЕ обновляем statusHeadline (верхняя карточка) - она только для подключения
    // statusHeadline управляется только через setConnectionState()

    // Функция для извлечения домена из URL
    function extractDomain(url) {
      try {
        const urlObj = new URL(url);
        return urlObj.hostname;
      } catch (_) {
        return url ? url.substring(0, 50) : '';
      }
    }
    
    // Упрощенный вердикт: только URL и статус в одну строку
    const verdictLabels = {
      malicious: 'Опасно',
      suspicious: 'Подозрительно',
      safe: 'Безопасно',
      clean: 'Безопасно',
      unknown: 'Неизвестно'
    };
    
    const verdictText = verdictLabels[verdict] || 'Неизвестно';
    const domain = url ? extractDomain(url) : '';
    
    // Убеждаемся, что resultEl имеет правильный класс
    if (elements.resultEl && !elements.resultEl.classList.contains('result-section')) {
      elements.resultEl.classList.add('result-section');
    }
    
    // Расширенный вывод с деталями анализа
    elements.resultEl.innerHTML = '';
    if (domain) {
      // Основная строка: URL - Вердикт
      const resultLine = document.createElement('div');
      resultLine.style.cssText = 'display: flex; align-items: center; gap: 8px; font-size: 12px; margin-bottom: 10px;';
      
      const urlSpan = document.createElement('span');
      urlSpan.style.cssText = 'color: var(--muted); flex-shrink: 0;';
      urlSpan.textContent = domain;
      
      const separator = document.createElement('span');
      separator.style.cssText = 'color: var(--muted);';
      separator.textContent = '—';
      
      const verdictSpan = document.createElement('span');
      const verdictColor = verdict === 'malicious' || verdict === 'suspicious' 
        ? 'var(--danger)' 
        : verdict === 'safe' || verdict === 'clean'
        ? 'var(--success)'
        : 'var(--muted)';
      verdictSpan.style.cssText = `color: ${verdictColor}; font-weight: 600; flex-shrink: 0;`;
      verdictSpan.textContent = verdictText;
      
      resultLine.appendChild(urlSpan);
      resultLine.appendChild(separator);
      resultLine.appendChild(verdictSpan);
      elements.resultEl.appendChild(resultLine);

      // Детали эвристического анализа (если доступны)
      const heuristics = res.meta && res.meta.heuristics;
      if (heuristics && typeof heuristics === 'object') {
        const riskScore = Number(heuristics.riskScore || 0);
        const riskLevel = heuristics.riskLevel || 'SAFE';
        const factors = Array.isArray(heuristics.factors) ? heuristics.factors : [];

        if (riskScore > 0 || factors.length > 0) {
          const detailsCard = document.createElement('div');
          detailsCard.style.cssText = 'margin-top: 10px; padding: 10px; background: rgba(0,0,0,0.02); border-radius: 6px; border: 1px solid var(--border);';
          
          // Risk Score и Level
          const riskRow = document.createElement('div');
          riskRow.style.cssText = 'display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; font-size: 11px;';
          
          const riskLabel = document.createElement('span');
          riskLabel.style.cssText = 'color: var(--muted); font-weight: 600;';
          riskLabel.textContent = 'Оценка риска:';
          
          const riskValue = document.createElement('span');
          let riskColor = 'var(--success)';
          if (riskLevel === 'CRITICAL') riskColor = 'var(--danger)';
          else if (riskLevel === 'HIGH_RISK') riskColor = 'var(--danger)';
          else if (riskLevel === 'LOW_RISK') riskColor = 'var(--warning)';
          riskValue.style.cssText = `color: ${riskColor}; font-weight: 700;`;
          riskValue.textContent = `${riskScore} (${riskLevel})`;
          
          riskRow.appendChild(riskLabel);
          riskRow.appendChild(riskValue);
          detailsCard.appendChild(riskRow);

          // Факторы риска
          if (factors.length > 0) {
            const factorsTitle = document.createElement('div');
            factorsTitle.style.cssText = 'font-size: 11px; font-weight: 600; color: var(--muted); margin-bottom: 6px;';
            factorsTitle.textContent = 'Факторы риска:';
            detailsCard.appendChild(factorsTitle);

            const factorsList = document.createElement('ul');
            factorsList.style.cssText = 'margin: 0; padding-left: 18px; font-size: 10px; color: var(--text); line-height: 1.5;';
            
            factors.slice(0, 5).forEach((factor) => {
              const li = document.createElement('li');
              li.textContent = factor;
              factorsList.appendChild(li);
            });
            
            if (factors.length > 5) {
              const moreLi = document.createElement('li');
              moreLi.style.cssText = 'color: var(--muted); font-style: italic;';
              moreLi.textContent = `... и ещё ${factors.length - 5} факторов`;
              factorsList.appendChild(moreLi);
            }
            
            detailsCard.appendChild(factorsList);
          }

          elements.resultEl.appendChild(detailsCard);
        }
      }

      // Информация о Threat Intelligence (если доступна)
      const ti = res.meta && res.meta.threat_intel;
      if (ti && typeof ti === 'object') {
        const tiInfo = [];
        
        if (ti.blacklistHit === true && Array.isArray(ti.hits) && ti.hits.length > 0) {
          ti.hits.forEach((hit) => {
            if (hit && hit.source) {
              tiInfo.push(`${hit.source}: обнаружен в списке угроз`);
            }
          });
        }
        
        if (ti.ipReputation && ti.ipReputation.abuseConfidenceScore) {
          const score = Number(ti.ipReputation.abuseConfidenceScore);
          if (score > 0) {
            tiInfo.push(`IP репутация: ${score}% (AbuseIPDB)`);
          }
        }
        
        if (ti.crowd && ti.crowd.reports) {
          const reports = Number(ti.crowd.reports);
          if (reports > 0) {
            tiInfo.push(`Краудсорсинг: ${reports} репортов от пользователей`);
          }
        }

        if (tiInfo.length > 0) {
          const tiCard = document.createElement('div');
          tiCard.style.cssText = 'margin-top: 8px; padding: 8px; background: rgba(37,99,235,0.05); border-radius: 6px; border: 1px solid rgba(37,99,235,0.2);';
          
          const tiTitle = document.createElement('div');
          tiTitle.style.cssText = 'font-size: 10px; font-weight: 600; color: var(--primary); margin-bottom: 4px;';
          tiTitle.textContent = 'Threat Intelligence:';
          tiCard.appendChild(tiTitle);

          const tiList = document.createElement('div');
          tiList.style.cssText = 'font-size: 10px; color: var(--text); line-height: 1.4;';
          tiList.textContent = tiInfo.join(' • ');
          tiCard.appendChild(tiList);

          elements.resultEl.appendChild(tiCard);
        }
      }
    } else {
      elements.resultEl.innerHTML = '<p class="muted">Нет данных по текущему URL.</p>';
    }

    toggleWarning(verdict === 'malicious', res.details);

    // Обновляем вкладку «Почему сайт опасен?»
    renderWhyExplanation(url, res);
  }

  function resolveVerdict(res) {
    if (!res || typeof res !== 'object') return 'unknown';
    if (res.safe === false) return 'malicious';
    if (res.safe === true) return 'safe';
    if (res.threat_type) return 'suspicious';
    return 'unknown';
  }

  /**
   * Генерация объяснения «почему сайт опасен»
   */
  function renderWhyExplanation(url, res) {
    const container = document.getElementById('why-content');
    if (!container) return;

    const data = res || {};
    const verdict = resolveVerdict(data);
    const meta = data.meta || {};
    const heur = meta.heuristics || {};
    const ti = meta.threat_intel || {};
    const domainMeta = data.domain_metadata || {};

    const parts = [];

    // 1. Общее резюме
    const verdictMap = {
      malicious: 'Сайт признан ОПАСНЫМ на основе совокупности сигналов.',
      suspicious: 'Сайт выглядит ПОДОЗРИТЕЛЬНЫМ по ряду признаков.',
      safe: 'Сайт выглядит БЕЗОПАСНЫМ на основе текущих сигналов.',
      unknown: 'Недостаточно данных для однозначного вердикта.'
    };
    parts.push(`<p>${verdictMap[verdict] || verdictMap.unknown}</p>`);

    // 2. Риск‑скор и ML
    const riskScore = typeof heur.riskScore === 'number' ? heur.riskScore : null;
    const riskLevel = heur.riskLevel || null;
    const mlScore = typeof heur.ml_score === 'number' ? heur.ml_score : null;
    const mlLabel = heur.ml_label || null;

    if (riskScore !== null || mlScore !== null) {
      let html = '<p><strong>Оценка риска:</strong><br />';
      if (riskScore !== null) {
        html += `— эвристический риск: <b>${Math.round(riskScore)}</b> баллов (${riskLevel || 'SAFE'})<br />`;
      }
      if (mlScore !== null) {
        html += `— ML‑модель: <b>${Math.round(mlScore * 100)}%</b> (${mlLabel || 'unknown'})`;
      }
      html += '</p>';
      parts.push(html);
    }

    // 3. Основные факторы риска
    if (Array.isArray(heur.factors) && heur.factors.length > 0) {
      const items = heur.factors.slice(0, 6).map((f) => `<li>${f}</li>`).join('');
      parts.push(
        `<p><strong>Факторы риска:</strong></p><ul>${items}${
          heur.factors.length > 6
            ? `<li>... и ещё ${heur.factors.length - 6} факторов</li>`
            : ''
        }</ul>`
      );
    }

    // 4. Информация о домене
    if (domainMeta && (domainMeta.domain || domainMeta.tld)) {
      const lines = [];
      if (domainMeta.domain) {
        lines.push(`Домен: <b>${domainMeta.domain}</b>`);
      }
      if (typeof domainMeta.subdomain_depth === 'number') {
        lines.push(`Глубина поддоменов: <b>${domainMeta.subdomain_depth}</b>`);
      }
      if (domainMeta.domain_age_days != null) {
        lines.push(`Возраст домена: <b>${domainMeta.domain_age_days}</b> дней`);
      } else {
        lines.push('Возраст домена: нет данных (WHOIS пока не дал информации)');
      }
      if (domainMeta.ssl_issuer || domainMeta.ssl_valid_from || domainMeta.ssl_valid_to) {
        const issuer = domainMeta.ssl_issuer ? `<b>${domainMeta.ssl_issuer}</b>` : 'неизвестен';
        let period = '';
        if (domainMeta.ssl_valid_from || domainMeta.ssl_valid_to) {
          const from = domainMeta.ssl_valid_from ? new Date(domainMeta.ssl_valid_from).toLocaleDateString() : '?';
          const to = domainMeta.ssl_valid_to ? new Date(domainMeta.ssl_valid_to).toLocaleDateString() : '?';
          period = ` (действует с ${from} по ${to})`;
        }
        lines.push(`SSL‑сертификат: ${issuer}${period}`);
      } else {
        lines.push('SSL‑сертификат: нет данных о сертификате (хост может не использовать TLS)');
      }
      parts.push(`<p><strong>Доменная информация:</strong><br />${lines.join('<br />')}</p>`);
    }

    // 5. Threat Intelligence‑источники
    const tiLines = [];
    if (ti && ti.blacklistHit && Array.isArray(ti.hits)) {
      ti.hits.forEach((hit) => {
        if (!hit || !hit.source) return;
        tiLines.push(`${hit.source}: обнаружен в списке угроз`);
      });
    }
    if (ti && ti.crowd && ti.crowd.reports) {
      tiLines.push(`Крауд‑репорты: ${ti.crowd.reports} отчётов от пользователей`);
    }
    if (ti && ti.ipReputation && typeof ti.ipReputation.abuseConfidenceScore === 'number') {
      tiLines.push(`IP‑репутация: ${ti.ipReputation.abuseConfidenceScore}% (AbuseIPDB)`);
    }
    if (tiLines.length > 0) {
      parts.push(
        `<p><strong>Threat Intelligence:</strong><br />${tiLines.join('<br />')}</p>`
      );
    }

    if (parts.length === 0) {
      container.innerHTML =
        'Подробное объяснение недоступно: пока нет данных от движка анализа. Попробуйте снова проверить URL.';
    } else {
      container.innerHTML = parts.join('');
    }
  }

  /**
   * Event handlers
   */
  function initTabs() {
    views.forEach((view) => {
      const btn = document.getElementById(`tab-${view}`);
      if (btn) {
        btn.addEventListener('click', () => {
          switchView(view);
        });
      } else {
        // Если вкладка отсутствует (например, в упрощённой разметке) – просто пропускаем
        console.warn('[AVQON] Tab button not found (skipping):', `tab-${view}`);
      }
    });
    switchView('home');
  }

  function initToggles() {
    const { antivirusToggle, hoverToggle } = elements;

    if (antivirusToggle) {
      antivirusToggle.addEventListener('change', async (event) => {
        state.settings.antivirusEnabled = !!event.target.checked;
        await saveSettings(state.settings);
        try {
          await sendRuntimeMessage({ type: 'antivirus_toggle', enabled: state.settings.antivirusEnabled });
        } catch (err) {
          console.warn('[Aegis Popup] Failed to notify background about antivirus toggle:', err);
        }
        setBadgeState(state.settings.antivirusEnabled ? 'ready' : 'disabled');
        if (elements.statusSubtitle) {
          elements.statusSubtitle.textContent = state.settings.antivirusEnabled
            ? 'Сканирование ссылок и загрузок'
            : 'Проверка отключена';
        }
      });
    }

    if (hoverToggle) {
      hoverToggle.addEventListener('change', async (event) => {
        state.settings.hoverScan = !!event.target.checked;
        await saveSettings(state.settings);
        chrome.runtime.sendMessage({ type: 'settings_updated', settings: state.settings }, () => {});
      });
    }
  }

  function initHoverThemeRadios() {
    const radios = Array.from(document.querySelectorAll('input[name="hover-theme"]'));
    if (!radios.length) return;

    radios.forEach((radio) => {
      radio.addEventListener('change', async () => {
        if (!radio.checked) return;
        state.hoverTheme = radio.value;
        await saveSettings({ hoverTheme: state.hoverTheme });
        chrome.storage.sync.set({ hoverTheme: state.hoverTheme }, () => {});
      });
    });
  }

  function initSensitivityRadios() {
    const radios = Array.from(document.querySelectorAll('input[name="sensitivity-mode"]'));
    if (!radios.length) return;
    const mode = state.settings.sensitivityMode || 'balanced';
    radios.forEach((radio) => {
      radio.checked = radio.value === mode;
      radio.closest('.radio-option')?.classList.toggle('active', radio.value === mode);
      radio.addEventListener('change', async () => {
        if (!radio.checked) return;
        document.querySelectorAll('#view-settings .radio-option').forEach((el) => el.classList.remove('active'));
        radio.closest('.radio-option')?.classList.add('active');
        state.settings.sensitivityMode = radio.value;
        await saveSettings({ sensitivityMode: radio.value });
        chrome.runtime.sendMessage({ type: 'settings_updated', settings: state.settings }, () => {});
      });
    });
  }

  function initAccountForms() {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const forgotForm = document.getElementById('forgot-form');
    const accountInfo = document.getElementById('account-info');

    const registerBtn = document.getElementById('show-register-btn');
    const loginBtn = document.getElementById('show-login-btn');
    const forgotBtn = document.getElementById('forgot-password-btn');
    const backToLoginBtn = document.getElementById('back-to-login-btn');

    function applyAccountMode(mode) {
      // КРИТИЧНО: Все формы аккаунта полностью скрыты (бесплатный режим)
      // Старый код закомментирован (можно вернуть):
      // const normalized = mode || 'login';
      // if (document.body) {
      //   document.body.setAttribute('data-account-mode', normalized);
      // }
      // if (loginForm) loginForm.style.display = normalized === 'login' ? 'block' : 'none';
      // if (registerForm) registerForm.style.display = normalized === 'register' ? 'block' : 'none';
      // if (forgotForm) forgotForm.style.display = normalized === 'forgot' ? 'block' : 'none';
      // if (accountInfo) accountInfo.style.display = normalized === 'account' ? 'block' : 'none';
      
      // Все формы аккаунта всегда скрыты
      if (loginForm) loginForm.style.display = 'none';
      if (registerForm) registerForm.style.display = 'none';
      if (forgotForm) forgotForm.style.display = 'none';
      if (accountInfo) accountInfo.style.display = 'none';
    }

    function showLogin() {
      // Не переключаемся в режим логина, если аккаунт уже привязан
      const currentMode = document.body?.getAttribute('data-account-mode');
      if (currentMode === 'account') return;
      applyAccountMode('login');
    }
    // КРИТИЧНО: Функция регистрации закомментирована (бесплатный режим)
    // Старый код закомментирован (можно вернуть):
    // function showRegister() {
    //   const currentMode = document.body?.getAttribute('data-account-mode');
    //   if (currentMode === 'account') return;
    //   applyAccountMode('register');
    // }
    function showRegister() {
      // Регистрация отключена - анализ теперь бесплатный
      console.log('[AVQON] Registration disabled - hover analysis is now free');
    }
    function showForgot() {
      const currentMode = document.body?.getAttribute('data-account-mode');
      if (currentMode === 'account') return;
      applyAccountMode('forgot');
    }

    // КРИТИЧНО: Обработчик регистрации отключен (бесплатный режим)
    // Старый код закомментирован (можно вернуть):
    // if (registerBtn) registerBtn.addEventListener('click', showRegister);
    // Регистрация не нужна - анализ бесплатный
    if (loginBtn) loginBtn.addEventListener('click', showLogin);
    if (forgotBtn) forgotBtn.addEventListener('click', showForgot);
    if (backToLoginBtn) backToLoginBtn.addEventListener('click', showLogin);

    // КРИТИЧНО: Аккаунты полностью скрыты (бесплатный режим)
    // Старый код закомментирован (можно вернуть):
    // chrome.storage?.sync?.get(['account', 'apiKey'], async (data) => {
    //   if (chrome.runtime?.lastError) {
    //     applyAccountMode('login');
    //     return;
    //   }
    //   if (data?.account) {
    //     applyAccountMode('account');
    //     await showAccountInfo(data.account);
    //     await updateHoverScanState();
    //   } else {
    //     applyAccountMode('login');
    //   }
    // });
    
    // Всегда скрываем формы аккаунта и включаем hover
    applyAccountMode();
    updateHoverScanState().catch(() => {});

    // Обработчики кнопок
    const loginSubmitBtn = document.getElementById('login-btn');
    const registerSubmitBtn = document.getElementById('register-btn');
    const forgotSubmitBtn = document.getElementById('forgot-btn');
    const resetSubmitBtn = document.getElementById('reset-btn');
    const logoutSubmitBtn = document.getElementById('logout-btn');

    if (loginSubmitBtn) {
      loginSubmitBtn.addEventListener('click', handleLogin);
    }
    // КРИТИЧНО: Обработчик регистрации отключен (бесплатный режим)
    // Старый код закомментирован (можно вернуть):
    // if (registerSubmitBtn) {
    //   registerSubmitBtn.addEventListener('click', handleRegister);
    // }
    if (forgotSubmitBtn) {
      forgotSubmitBtn.addEventListener('click', handleForgotPassword);
    }
    if (resetSubmitBtn) {
      resetSubmitBtn.addEventListener('click', handleResetPassword);
    }
    if (logoutSubmitBtn) {
      logoutSubmitBtn.addEventListener('click', handleLogout);
    }
    
    // Обработчики сохранения API ключа
    const saveApiKeyBtnPopup = document.getElementById('account-save-api-key-popup-btn');
    const saveApiKeyBtnSidepanel = document.getElementById('account-save-api-key-sidepanel-btn');
    if (saveApiKeyBtnPopup) {
      saveApiKeyBtnPopup.addEventListener('click', handleSaveApiKey);
    }
    if (saveApiKeyBtnSidepanel) {
      saveApiKeyBtnSidepanel.addEventListener('click', handleSaveApiKey);
    }
  }

  async function showAccountInfo(account) {
    const accountInfo = document.getElementById('account-info');
    const accountUsername = document.getElementById('account-username');
    const accountEmail = document.getElementById('account-email');
    const accountAvatar = document.getElementById('account-avatar');
    
    if (accountInfo) accountInfo.style.display = 'block';
    if (accountUsername) accountUsername.textContent = account?.username || '—';
    if (accountEmail) accountEmail.textContent = account?.email || '—';
    if (accountAvatar) {
      const letter = (account?.username || account?.email || '?').charAt(0).toUpperCase();
      accountAvatar.textContent = letter;
    }
    
    // Загружаем текущий API ключ
    const storage = await new Promise((resolve) => {
      chrome.storage.sync.get(['apiKey'], resolve);
    });
    const apiKeyInputPopup = document.getElementById('account-api-key-popup');
    const apiKeyInputSidepanel = document.getElementById('account-api-key-sidepanel');
    const apiKeyFieldPopup = apiKeyInputPopup?.closest('.form-field');
    const apiKeyFieldSidepanel = apiKeyInputSidepanel?.closest('.form-field');
    
    // Если ключ уже есть, скрываем поле ввода
    if (storage.apiKey && storage.apiKey.trim().length > 0) {
      if (apiKeyFieldPopup) apiKeyFieldPopup.style.display = 'none';
      if (apiKeyFieldSidepanel) apiKeyFieldSidepanel.style.display = 'none';
    } else {
      // Если ключа нет, показываем поле и очищаем его
      if (apiKeyFieldPopup) apiKeyFieldPopup.style.display = 'block';
      if (apiKeyFieldSidepanel) apiKeyFieldSidepanel.style.display = 'block';
      if (apiKeyInputPopup) apiKeyInputPopup.value = '';
      if (apiKeyInputSidepanel) apiKeyInputSidepanel.value = '';
    }
    
    // Обновляем состояние hover scan после показа аккаунта
    await updateHoverScanState();
  }
  
  /**
   * Обновляет состояние ползунка "анализ по наведению" в зависимости от наличия аккаунта и API ключа
   */
  async function updateHoverScanState() {
    // КРИТИЧНО: Анализ по наведению теперь бесплатный, всегда доступен
    // Старая проверка закомментирована (можно вернуть если нужно):
    // const storage = await new Promise((resolve) => {
    //   chrome.storage.sync.get(['account', 'apiKey'], resolve);
    // });
    // const hasAccount = !!storage.account;
    // const hasApiKey = !!storage.apiKey && storage.apiKey.trim().length > 0;
    // 
    // const hoverToggle = elements.hoverToggle;
    // if (!hoverToggle) return;
    // 
    // // Включаем hover только если есть аккаунт И ключ
    // if (hasAccount && hasApiKey) {
    //   hoverToggle.disabled = false;
    //   const parent = hoverToggle.closest('.toggle-group') || hoverToggle.parentElement;
    //   if (parent) parent.style.opacity = '1';
    // } else {
    //   // Блокируем и выключаем, если нет аккаунта или ключа
    //   hoverToggle.checked = false;
    //   hoverToggle.disabled = true;
    //   const parent = hoverToggle.closest('.toggle-group') || hoverToggle.parentElement;
    //   if (parent) parent.style.opacity = '0.5';
    //   
    //   // Сохраняем выключенное состояние
    //   state.settings.hoverScan = false;
    //   await saveSettings(state.settings);
    // }
    
    // Теперь hover всегда доступен
    const hoverToggle = elements.hoverToggle;
    if (hoverToggle) {
      hoverToggle.disabled = false;
      const parent = hoverToggle.closest('.toggle-group') || hoverToggle.parentElement;
      if (parent) parent.style.opacity = '1';
    }
  }
  
  /**
   * Обработчик сохранения API ключа из формы аккаунта
   */
  async function handleSaveApiKey() {
    const apiKeyInputPopup = document.getElementById('account-api-key-popup');
    const apiKeyInputSidepanel = document.getElementById('account-api-key-sidepanel');
    const apiKey = (apiKeyInputPopup?.value || apiKeyInputSidepanel?.value || '').trim();
    
    if (!apiKey) {
      showInternalNotification('⚠️ Введите API ключ', 'error');
      return;
    }
    
    try {
      // Получаем токен сессии для авторизации
      const storage = await new Promise((resolve) => {
        chrome.storage.sync.get(['session_token', 'account'], resolve);
      });
      
      if (!storage.session_token || !storage.account) {
        showInternalNotification('❌ Необходимо войти в аккаунт', 'error');
        return;
      }
      
      // Привязываем ключ к аккаунту через API
      const apiBase = normalizeApiBase(state.settings.apiBase);
      const response = await fetch(`${apiBase}/auth/bind-api-key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${storage.session_token}`
        },
        body: JSON.stringify({ api_key: apiKey })
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Ошибка привязки ключа' }));
        throw new Error(errorData.detail || 'Ошибка привязки ключа к аккаунту');
      }
      
      // Сохраняем ключ локально
      await chrome.storage.sync.set({ apiKey });
      
      // Скрываем поле ввода ключа
      const apiKeyFieldPopup = apiKeyInputPopup?.closest('.form-field');
      const apiKeyFieldSidepanel = apiKeyInputSidepanel?.closest('.form-field');
      if (apiKeyFieldPopup) apiKeyFieldPopup.style.display = 'none';
      if (apiKeyFieldSidepanel) apiKeyFieldSidepanel.style.display = 'none';
      
      showInternalNotification('✅ API ключ привязан к аккаунту! Анализ по наведению теперь доступен.', 'success');
      
      // Обновляем состояние hover scan
      await updateHoverScanState();
      
      // Уведомляем background script об изменении настроек
      chrome.runtime.sendMessage({ 
        type: 'settings_updated', 
        settings: { ...state.settings, apiKey } 
      }, () => {});
    } catch (error) {
      console.error('[Aegis] Error saving API key:', error);
      showInternalNotification('❌ ' + (error.message || 'Ошибка сохранения ключа'), 'error');
    }
  }

  /**
   * Получает или создает уникальный идентификатор устройства
   */
  async function getDeviceId() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['device_id'], (result) => {
        if (result.device_id) {
          resolve(result.device_id);
        } else {
          // Генерируем новый device_id
          const deviceId = 'device_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
          chrome.storage.local.set({ device_id: deviceId }, () => {
            resolve(deviceId);
          });
        }
      });
    });
  }

  async function handleLogin() {
    const usernameEl = document.getElementById('login-username');
    const passwordEl = document.getElementById('login-password');
    const loginBtn = document.getElementById('login-btn');
    
    if (!usernameEl || !passwordEl) return;
    
    const username = usernameEl.value.trim();
    const password = passwordEl.value.trim();
    
    if (!username || !password) {
      showInternalNotification('⚠️ Заполните логин и пароль', 'warning');
      return;
    }
    
    try {
      if (loginBtn) {
        loginBtn.disabled = true;
        loginBtn.textContent = 'Вход...';
      }
      
      const apiBase = normalizeApiBase(state.settings.apiBase);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      
      // Получаем device_id
      const deviceId = await getDeviceId();
      
      const res = await fetch(`${apiBase}/auth/login`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Device-ID': deviceId
        },
        body: JSON.stringify({ username, password }),
        signal: controller.signal
      });
      
      clearTimeout(timeout);
      
      if (!res.ok) {
        const error = await res.json().catch(() => ({ detail: 'Ошибка входа' }));
        throw new Error(error?.detail || 'Не удалось войти');
      }
      
      const data = await res.json();
      const account = data.account;
      
      // Сохраняем account и access_token (используем как session_token для совместимости)
      await new Promise((resolve) => {
        chrome.storage.sync.set({ 
          account: account,
          session_token: data.access_token || data.session_token 
        }, () => {
          if (chrome.runtime?.lastError) {
            console.error('[Aegis] Failed to save account:', chrome.runtime.lastError);
          }
          resolve();
        });
      });
      
      // Сохраняем API ключ если есть
      if (data.api_keys && data.api_keys.length > 0) {
        const apiKey = String(data.api_keys[0].api_key || '').trim();
        if (apiKey) {
          await new Promise((resolve) => {
            chrome.storage.sync.set({ apiKey }, () => {
              if (chrome.runtime?.lastError) {
                console.error('[Aegis] Failed to save API key:', chrome.runtime.lastError);
              }
              resolve();
            });
          });
        }
      }
      
      await showAccountInfo(account);
      const loginForm = document.getElementById('login-form');
      const registerForm = document.getElementById('register-form');
      const forgotForm = document.getElementById('forgot-form');
      const accountInfo = document.getElementById('account-info');
      
      if (loginForm) loginForm.style.display = 'none';
      if (registerForm) registerForm.style.display = 'none';
      if (forgotForm) forgotForm.style.display = 'none';
      if (accountInfo) accountInfo.style.display = 'block';
      if (document.body) document.body.setAttribute('data-account-mode', 'account');
      
      // Показываем уведомление внутри расширения, а не через alert
      showInternalNotification('✅ Успешный вход!', 'success');
      
      // Обновляем состояние hover scan после входа
      await updateHoverScanState();
      
      // Запускаем проверку валидности сессии
      startSessionValidation();
    } catch (error) {
      console.error('[Aegis] Login error:', error);
      showInternalNotification('❌ ' + (error.message || 'Ошибка входа'), 'error');
    } finally {
      if (loginBtn) {
        loginBtn.disabled = false;
        loginBtn.textContent = 'Войти';
      }
    }
  }
  
  /**
   * Проверяет валидность текущей сессии
   */
  async function checkSessionValidity() {
    try {
      const storage = await new Promise((resolve) => {
        chrome.storage.sync.get(['session_token', 'account'], resolve);
      });
      
      if (!storage.session_token || !storage.account) {
        return true; // Нет сессии - не нужно проверять
      }
      
      const apiBase = normalizeApiBase(state.settings.apiBase);
      const res = await fetch(`${apiBase}/auth/validate-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_token: storage.session_token })
      });
      
      if (!res.ok) {
        // Проверяем статус ответа
        const errorData = await res.json().catch(() => ({}));
        
        // Если это ошибка сервера (500) - не выходим, это временная проблема
        if (res.status >= 500) {
          console.warn('[Aegis] Server error during session validation, keeping session');
          return true; // Не выходим при ошибке сервера
        }
        
        // Только при 401/400 считаем сессию невалидной
        if (res.status === 401 || res.status === 400) {
          const data = await res.json().catch(() => ({}));
          // Проверяем, действительно ли сессия невалидна
          if (data.valid === false || data.status === 'invalid') {
        console.warn('[Aegis] Session invalid, logging out');
            await handleLogout();
            showInternalNotification('⚠️ Вы вышли из аккаунта (вход выполнен на другом устройстве)', 'warning');
            return false;
          }
        }
        
        return true; // При других ошибках не выходим
      }
      
      const data = await res.json().catch(() => ({}));
      
      // Проверяем ответ сервера
      if (data.valid === false || data.status === 'invalid') {
        console.warn('[Aegis] Session invalid from response, logging out');
        await handleLogout();
        showInternalNotification('⚠️ Вы вышли из аккаунта (вход выполнен на другом устройстве)', 'warning');
        return false;
      }
      
      return true;
    } catch (error) {
      console.error('[Aegis] Session validation error:', error);
      return true; // При ошибке не выходим
    }
  }
  
  /**
   * Запускает периодическую проверку валидности сессии
   */
  function startSessionValidation() {
    // Проверяем каждые 30 секунд
    if (state.sessionValidationTimer) {
      clearInterval(state.sessionValidationTimer);
    }
    state.sessionValidationTimer = setInterval(checkSessionValidity, 30000);
  }
  
  /**
   * Останавливает проверку валидности сессии
   */
  function stopSessionValidation() {
    if (state.sessionValidationTimer) {
      clearInterval(state.sessionValidationTimer);
      state.sessionValidationTimer = null;
    }
  }

  async function handleRegister() {
    const usernameEl = document.getElementById('register-username');
    const emailEl = document.getElementById('register-email');
    const passwordEl = document.getElementById('register-password');
    const apiKeyEl = document.getElementById('register-api-key');
    const registerBtn = document.getElementById('register-btn');
    
    if (!usernameEl || !emailEl || !passwordEl) return;
    
    const username = usernameEl.value.trim();
    const email = emailEl.value.trim();
    const password = passwordEl.value.trim();
    const apiKey = apiKeyEl ? apiKeyEl.value.trim() : '';
    
    if (!username || !email || !password) {
      showInternalNotification('⚠️ Заполните все обязательные поля', 'warning');
      return;
    }
    
    if (password.length < 6) {
      showInternalNotification('⚠️ Пароль должен содержать минимум 6 символов', 'warning');
      return;
    }
    
    try {
      if (registerBtn) {
        registerBtn.disabled = true;
        registerBtn.textContent = 'Регистрация...';
      }
      
      const apiBase = normalizeApiBase(state.settings.apiBase);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      
      const body = { username, email, password };
      if (apiKey) body.api_key = apiKey;
      
      const res = await fetch(`${apiBase}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      
      clearTimeout(timeout);
      
      if (!res.ok) {
        const error = await res.json().catch(() => ({ detail: 'Ошибка регистрации' }));
        throw new Error(error?.detail || 'Ошибка регистрации');
      }
      
      const data = await res.json();
      
      // Сохраняем API ключ если он был указан или пришел с сервера
      const finalApiKey = apiKey || (data.api_keys && data.api_keys.length > 0 ? data.api_keys[0].api_key : null);
      if (finalApiKey) {
        const normalizedApiKey = String(finalApiKey).trim();
        if (normalizedApiKey) {
          await new Promise((resolve) => {
            chrome.storage.sync.set({ apiKey: normalizedApiKey }, () => {
              if (chrome.runtime?.lastError) {
                console.error('[Aegis] Failed to save API key:', chrome.runtime.lastError);
              }
              resolve();
            });
          });
        }
      }
      
      showInternalNotification('✅ Аккаунт создан. Выполните вход.', 'success');
      
      // Переключаемся на форму входа
      const loginForm = document.getElementById('login-form');
      const registerForm = document.getElementById('register-form');
      if (loginForm) loginForm.style.display = 'block';
      if (registerForm) registerForm.style.display = 'none';
      if (document.body) document.body.setAttribute('data-account-mode', 'login');
      
    } catch (error) {
      console.error('[Aegis] Register error:', error);
      showInternalNotification('❌ ' + (error.message || 'Ошибка регистрации'), 'error');
    } finally {
      if (registerBtn) {
        registerBtn.disabled = false;
        registerBtn.textContent = 'Зарегистрироваться';
      }
    }
  }

  async function handleForgotPassword() {
    const emailEl = document.getElementById('forgot-email');
    const forgotBtn = document.getElementById('forgot-btn');
    
    if (!emailEl) return;
    
    const email = emailEl.value.trim();
    if (!email) {
      showInternalNotification('⚠️ Введите email', 'warning');
      return;
    }
    
    try {
      if (forgotBtn) {
        forgotBtn.disabled = true;
        forgotBtn.textContent = 'Отправляем...';
      }
      
      const apiBase = normalizeApiBase(state.settings.apiBase);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      
      const res = await fetch(`${apiBase}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
        signal: controller.signal
      });
      
      clearTimeout(timeout);
      
      if (!res.ok) {
        const error = await res.json().catch(() => ({ detail: 'Ошибка отправки' }));
        throw new Error(error?.detail || 'Ошибка отправки');
      }
      
      const resetCodeSection = document.getElementById('reset-code-section');
      if (resetCodeSection) resetCodeSection.style.display = 'block';
      
      showInternalNotification('✅ Письмо отправлено. Проверьте почту.', 'success');
    } catch (error) {
      console.error('[Aegis] Forgot password error:', error);
      showInternalNotification('❌ ' + (error.message || 'Ошибка отправки'), 'error');
    } finally {
      if (forgotBtn) {
        forgotBtn.disabled = false;
        forgotBtn.textContent = 'Отправить код';
      }
    }
  }

  async function handleResetPassword() {
    const emailEl = document.getElementById('forgot-email');
    const codeEl = document.getElementById('reset-code');
    const newPasswordEl = document.getElementById('new-password');
    const resetBtn = document.getElementById('reset-btn');
    
    if (!emailEl || !codeEl || !newPasswordEl) return;
    
    const email = emailEl.value.trim();
    const code = codeEl.value.trim();
    const newPassword = newPasswordEl.value.trim();
    
    if (!email || !code || !newPassword) {
      showInternalNotification('⚠️ Заполните все поля', 'warning');
      return;
    }
    
    try {
      if (resetBtn) {
        resetBtn.disabled = true;
        resetBtn.textContent = 'Сбрасываем...';
      }
      
      const apiBase = normalizeApiBase(state.settings.apiBase);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      
      const res = await fetch(`${apiBase}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
	email: email.trim(),
  	token: code.trim(),
  	new_password: newPassword.trim()
	}),
        signal: controller.signal
      });
      
      clearTimeout(timeout);
      
      if (!res.ok) {
        const error = await res.json().catch(() => ({ detail: 'Ошибка сброса' }));
        throw new Error(error?.detail || 'Ошибка сброса');
      }
      
      showInternalNotification('✅ Пароль изменен. Войдите снова.', 'success');
      
      // Переключаемся на форму входа
      const loginForm = document.getElementById('login-form');
      const forgotForm = document.getElementById('forgot-form');
      if (loginForm) loginForm.style.display = 'block';
      if (forgotForm) forgotForm.style.display = 'none';
      if (document.body) document.body.setAttribute('data-account-mode', 'login');
      
    } catch (error) {
      console.error('[Aegis] Reset password error:', error);
      showInternalNotification('❌ ' + (error.message || 'Ошибка сброса'), 'error');
    } finally {
      if (resetBtn) {
        resetBtn.disabled = false;
        resetBtn.textContent = 'Сбросить пароль';
      }
    }
  }

  async function handleLogout() {
    // Останавливаем проверку сессии
    stopSessionValidation();
    
    // Удаляем данные из хранилища
    chrome.storage.sync.remove(['account', 'apiKey', 'session_token'], async () => {
      const loginForm = document.getElementById('login-form');
      const accountInfo = document.getElementById('account-info');
      if (loginForm) loginForm.style.display = 'block';
      if (accountInfo) accountInfo.style.display = 'none';
      if (document.body) document.body.setAttribute('data-account-mode', 'login');
      
      // Обновляем состояние hover scan после выхода
      await updateHoverScanState();
    });
  }

  /**
   * Connection & scanning logic
   */
  /**
   * Проверяет статус подключения к серверу
   * КРИТИЧНО: Обновляет ТОЛЬКО верхнюю карточку (connection status)
   */
  async function checkConnectionStatus() {
    // Устанавливаем состояние "проверка" перед проверкой
    setConnectionState(null, null);
    
    try {
      const response = await sendRuntimeMessage({ type: 'get_connection_status' });
      if (response && typeof response.isOnline === 'boolean') {
        setConnectionState(response.isOnline, response.isOnline ? 'Подключено' : 'Нет подключения');
        return response.isOnline;
      }
    } catch (error) {
      console.warn('[Aegis Popup] Unable to get connection status from background:', error);
    }

    // Fallback to HTTP check
    try {
      const apiBase = normalizeApiBase(state.settings.apiBase);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(`${apiBase}/health`, { method: 'GET', signal: controller.signal });
      clearTimeout(timeout);
      setConnectionState(res.ok, res.ok ? 'Подключено' : `Ошибка сервера (${res.status})`);
      return res.ok;
    } catch (err) {
      setConnectionState(false, 'Нет подключения');
      return false;
    }
  }

  async function scanActiveTab() {
    if (!state.settings.antivirusEnabled) {
      // КРИТИЧНО: Обновляем состояние сканирования
      setScanState(false, { details: 'Защита отключена', safe: null });
      renderResult(null, { details: 'Защита отключена', safe: null });
      return;
    }

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs && tabs[0];
      if (!tab || !tab.url || tab.url.startsWith('chrome')) {
        // КРИТИЧНО: Обновляем состояние сканирования
        setScanState(false, { details: 'Нет доступного URL для проверки', safe: null });
        renderResult(null, { details: 'Нет доступного URL для проверки', safe: null });
        return;
      }

      // КРИТИЧНО: Обновляем только состояние сканирования (средняя карточка)
      setScanState(true, null); // Начало сканирования

      const response = await sendRuntimeMessage({
        type: 'analyze_url',
        url: tab.url,
        context: 'popup'
      });

      if (!response) {
        throw new Error('Нет ответа от сервера');
      }

      // КРИТИЧНО: Проверяем что результат не всегда safe: true
      const result = response.data || response.result || {};
      console.log('[Aegis Popup] Analysis result:', result);
      
      // Если safe === null или undefined, это unknown, не safe
      if (result.safe === null || result.safe === undefined) {
        console.warn('[Aegis Popup] Result has null/undefined safe, treating as unknown');
      }
      
      renderResult(tab.url, result);
    } catch (error) {
      console.error('[Aegis Popup] scanActiveTab failed:', error);
      // КРИТИЧНО: Обновляем состояние сканирования с ошибкой
      setScanState(false, { safe: null, details: error?.message || 'Ошибка проверки' });
      renderResult(null, { safe: null, details: error?.message || 'Ошибка проверки' });
      toggleWarning(false);
    }
  }

  /**
   * Гарантирует наличие карточки еженедельного отчёта на главной
   */
  function ensureWeeklyReportCard() {
    let card = document.getElementById('weekly-report-card');
    const homeSection = document.getElementById('view-home');
    if (!homeSection) return;

    if (!card) {
      const warningCard = document.getElementById('warning-card');
      const insertPoint = warningCard && warningCard.parentElement === homeSection
        ? warningCard.nextSibling
        : homeSection.lastChild;

      card = document.createElement('div');
      card.id = 'weekly-report-card';

      if (insertPoint) {
        homeSection.insertBefore(card, insertPoint);
      } else {
        homeSection.appendChild(card);
      }
    }

    card.className = 'card weekly-report-card';
    card.innerHTML = `
      <div class="weekly-report-card-inner">
        <h3 class="weekly-title">Статистика за 7 дней</h3>
        <div class="weekly-hero">
          <div class="weekly-hero-number" id="weekly-unsafe-count">0</div>
          <div class="weekly-hero-text">угроз заблокировано</div>
        </div>
        <div class="weekly-bar" title="Соотношение безопасных и опасных проверок">
          <div class="progress-safe" id="weekly-bar-safe"></div>
          <div class="progress-unsafe" id="weekly-bar-unsafe"></div>
        </div>
        <div class="weekly-bar-labels">
          <span id="weekly-label-safe">Безопасно 0%</span>
          <span id="weekly-label-unsafe">Опасно 0%</span>
        </div>
        <div class="weekly-metrics">
          <div class="weekly-metric">Впервые обнаружено: <span id="weekly-unique-unsafe">—</span></div>
          <div class="weekly-metric">Всего проверок: <span id="weekly-total-checks">0</span></div>
        </div>
      </div>
    `;
  }

  /**
   * Загрузка и отображение еженедельного отчета
   */
  async function loadWeeklyReport() {
    // Сначала убеждаемся, что карточка есть в DOM
    ensureWeeklyReportCard();
    try {
      const response = await sendRuntimeMessage({ type: 'get_weekly_stats' });
      if (!response || !response.ok) {
        throw new Error('Не удалось загрузить статистику');
      }

      const stats = response.stats || {};
      const unsafeCount = stats.unsafe_count || 0;
      const totalChecks = stats.total_checks || 0;
      const safeCount = stats.safe_count || 0;

      // Обновляем главную метрику - крупная цифра (на главной) с лёгкой анимацией
      const unsafeCountEl = document.getElementById('weekly-unsafe-count');
      if (unsafeCountEl) {
        const target = Number(unsafeCount) || 0;
        const startValue = Number(unsafeCountEl.textContent) || 0;
        const duration = 600;

        if (startValue !== target) {
          const startTime = performance.now();

          function animateNumber(now) {
            const progress = Math.min((now - startTime) / duration, 1);
            const value = Math.round(startValue + (target - startValue) * progress);
            unsafeCountEl.textContent = value;
            if (progress < 1) {
              requestAnimationFrame(animateNumber);
            }
          }

          requestAnimationFrame(animateNumber);
        }

        if (target > 0) {
          unsafeCountEl.classList.add('has-data');
        } else {
          unsafeCountEl.classList.remove('has-data');
        }
      }

      const barSafe = document.getElementById('weekly-bar-safe');
      const barUnsafe = document.getElementById('weekly-bar-unsafe');
      const labelSafe = document.getElementById('weekly-label-safe');
      const labelUnsafe = document.getElementById('weekly-label-unsafe');
      const uniqueEl = document.getElementById('weekly-unique-unsafe');
      const totalEl = document.getElementById('weekly-total-checks');

      const resolvedTotal = safeCount + unsafeCount;
      if (totalChecks > 0 && resolvedTotal > 0) {
        const safePercent = (safeCount / resolvedTotal) * 100;
        const unsafePercent = (unsafeCount / resolvedTotal) * 100;
        if (barSafe) barSafe.style.width = `${safePercent}%`;
        if (barUnsafe) barUnsafe.style.width = `${unsafePercent}%`;
        if (labelSafe) labelSafe.textContent = `Безопасно ${Math.round(safePercent)}%`;
        if (labelUnsafe) labelUnsafe.textContent = `Опасно ${Math.round(unsafePercent)}%`;
        if (totalEl) totalEl.textContent = String(totalChecks);
        if (uniqueEl) {
          uniqueEl.textContent = stats.unique_unsafe_count != null ? String(stats.unique_unsafe_count) : '—';
        }
      } else {
        if (barSafe) barSafe.style.width = '0%';
        if (barUnsafe) barUnsafe.style.width = '0%';
        if (labelSafe) labelSafe.textContent = 'Безопасно 0%';
        if (labelUnsafe) labelUnsafe.textContent = 'Опасно 0%';
        if (totalEl) totalEl.textContent = String(totalChecks || '0');
        if (uniqueEl) uniqueEl.textContent = '—';
      }

      // Показываем уведомление при первом открытии после воскресенья/понедельника
      checkAndShowWeeklyNotification();
    } catch (error) {
      console.error('[AVQON] Failed to load weekly report:', error);
      // Показываем ошибку в UI
      const unsafeCountEl = document.getElementById('weekly-unsafe-count');
      if (unsafeCountEl) {
        unsafeCountEl.textContent = '—';
      }
    }
  }

  /**
   * Проверяет и показывает уведомление о готовности отчета
   */
  async function checkAndShowWeeklyNotification() {
    try {
      const storage = await new Promise((resolve) => 
        chrome.storage.local.get(['lastWeeklyReportNotification'], resolve)
      );
      
      const lastNotification = storage.lastWeeklyReportNotification || 0;
      const now = Date.now();
      const oneWeek = 7 * 24 * 60 * 60 * 1000;
      
      // Проверяем, прошла ли неделя с последнего уведомления
      if (now - lastNotification > oneWeek) {
        const today = new Date();
        const dayOfWeek = today.getDay(); // 0 = воскресенье, 1 = понедельник
        
        // Показываем уведомление в понедельник или воскресенье
        if (dayOfWeek === 0 || dayOfWeek === 1) {
          showInternalNotification('📊 Ваш еженедельный отчет готов!', 'success');
          
          // Сохраняем время последнего уведомления
          await new Promise((resolve) => 
            chrome.storage.local.set({ lastWeeklyReportNotification: now }, resolve)
          );
        }
      }
    } catch (error) {
      console.error('[AVQON] Failed to check weekly notification:', error);
    }
  }

  /**
   * Initialization
   */
  async function init() {
    console.log('[AVQON] init() start, crowd button exists in HTML?', !!document.getElementById('crowd-report-toggle-btn'));
    state.settings = await loadSettings();
    state.settings.apiBase = normalizeApiBase(state.settings.apiBase);
    state.hoverTheme = state.settings.hoverTheme || 'classic';
    state.settings.sensitivityMode = state.settings.sensitivityMode || DEFAULTS.sensitivityMode;

    initTabs();
    initToggles();
    initHoverThemeRadios();
    initSensitivityRadios();
    initAccountForms();

    if (elements.antivirusToggle) {
      elements.antivirusToggle.checked = !!state.settings.antivirusEnabled;
    }
    if (elements.hoverToggle) {
      elements.hoverToggle.checked = !!state.settings.hoverScan;
    }
    
    // Обновляем состояние hover scan при загрузке
    await updateHoverScanState();

    const radios = Array.from(document.querySelectorAll('input[name="hover-theme"]'));
    radios.forEach((radio) => {
      radio.checked = radio.value === state.hoverTheme;
      radio.closest('.radio-option')?.classList.toggle('active', radio.checked);
      radio.addEventListener('change', () => {
        document.querySelectorAll('.radio-option').forEach((el) => el.classList.remove('active'));
        radio.closest('.radio-option')?.classList.add('active');
      });
    });

    // КРИТИЧНО: Инициализируем состояния отдельно
    // 1. Проверяем подключение к серверу (верхняя карточка)
    await checkConnectionStatus();
    state.connectionTimer = setInterval(checkConnectionStatus, 30000);
    
    // 2. Инициализируем состояние сканирования (средняя карточка)
    setScanState(false, null); // Нет активного сканирования

    // 3. Проверяем, есть ли сохраненная сессия, и запускаем проверку валидности
    const storage = await new Promise((resolve) => {
      chrome.storage.sync.get(['session_token', 'account'], resolve);
    });
    if (storage.session_token && storage.account) {
      startSessionValidation();
      // Проверяем сразу при загрузке
      checkSessionValidity();
    }

    // 4. Запускаем сканирование активной вкладки
    await scanActiveTab();

    // 5. Загружаем еженедельный отчёт для главной
    await loadWeeklyReport();

    // Дополнительно обновляем результат при фокусе окна
    window.addEventListener('focus', () => {
      checkConnectionStatus();
      scanActiveTab();
      
    });
    // Обработчик для кнопки перехода на сайт AVQON
    const botLink = document.getElementById('open-telegram-bot');
    if (botLink) {
      botLink.addEventListener('click', (e) => {
        e.preventDefault();
        const websiteUrl =
          (window.AVQON_CONFIG && window.AVQON_CONFIG.WEBSITE_URL) ||
          'https://avqon.com';
        chrome.tabs.create({ url: websiteUrl });
      });
    }

    // Инициализация формы отзывов
    initReviewForm();

    // Инициализация формы крауд‑репорта
    const crowdToggleBtn = document.getElementById('crowd-report-toggle-btn');
    const crowdFormCard = document.getElementById('crowd-report-form-card');
    const crowdUrlInput = document.getElementById('crowd-report-url');
    const crowdTypeSelect = document.getElementById('crowd-report-type');
    const crowdCommentInput = document.getElementById('crowd-report-comment');
    const crowdSubmitBtn = document.getElementById('crowd-report-submit-btn');
    const crowdCancelBtn = document.getElementById('crowd-report-cancel-btn');

    console.log('[AVQON] After DOM init, crowd button exists?', !!crowdToggleBtn);

    async function openCrowdForm() {
      if (!crowdFormCard) return;
      try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tab = tabs && tabs[0];
        if (tab && tab.url && !tab.url.startsWith('chrome') && crowdUrlInput) {
          crowdUrlInput.value = tab.url;
        }
      } catch (e) {
        console.warn('[AVQON] Failed to prefill crowd-report URL:', e);
      }
      crowdFormCard.classList.remove('hidden');
    }

    function closeCrowdForm() {
      if (crowdFormCard) {
        crowdFormCard.classList.add('hidden');
      }
    }

    async function sendCrowdReportFromForm() {
      if (!crowdUrlInput || !crowdTypeSelect) return;
      const url = crowdUrlInput.value.trim();
      const threatType = crowdTypeSelect.value || 'other';
      const comment = crowdCommentInput ? crowdCommentInput.value.trim() : '';

      if (!url) {
        showInternalNotification('Укажите URL для репорта', 'warning');
        return;
      }

      // Маппинг типов угроз на вердикт для backend (suspicious/malicious)
      let verdict = 'suspicious';
      if (['phishing', 'malware', 'trojan', 'fraud'].includes(threatType)) {
        verdict = 'malicious';
      }

      try {
        try {
          console.log('[AVQON] Preparing crowd report from popup:', {
            url,
            verdict,
            threat_type: threatType,
            comment: comment || null
          });
        } catch (_) {
          // ignore
        }
        const resp = await sendRuntimeMessage({
          type: 'crowd_report_url',
          url,
          verdict,
          threat_type: threatType,
          comment: comment || null
        });
        if (resp && resp.ok) {
          showInternalNotification('Спасибо! Ваш репорт отправлен.', 'success');
          closeCrowdForm();
        } else {
          showInternalNotification('Не удалось отправить репорт. Повторите позже.', 'error');
        }
      } catch (e) {
        console.error('[AVQON] Crowd report from popup failed:', e);
        showInternalNotification('Ошибка при отправке репорта', 'error');
      }
    }

    if (crowdToggleBtn && crowdFormCard) {
      crowdToggleBtn.addEventListener('click', () => {
        if (crowdFormCard.classList.contains('hidden')) {
          openCrowdForm();
        } else {
          closeCrowdForm();
        }
      });
    }
    if (crowdSubmitBtn) {
      crowdSubmitBtn.addEventListener('click', () => {
        sendCrowdReportFromForm();
      });
    }
    if (crowdCancelBtn) {
      crowdCancelBtn.addEventListener('click', () => {
        closeCrowdForm();
      });
    }
  }

  /**
   * Инициализация формы отзывов
   */
  function initReviewForm() {
    // Для popup
    const starRatingPopup = document.getElementById('star-rating-popup');
    const ratingInputPopup = document.getElementById('rating-value-popup');
    const submitBtnPopup = document.getElementById('submit-review-btn-popup');
    const successMsgPopup = document.getElementById('review-success-popup');

    // Для sidepanel
    const starRating = document.getElementById('star-rating');
    const ratingInput = document.getElementById('rating-value');
    const submitBtn = document.getElementById('submit-review-btn');
    const successMsg = document.getElementById('review-success');

    // Функция для инициализации звезд
    function initStars(container, input) {
      if (!container || !input) return;

      const stars = container.querySelectorAll('.star');
      let currentRating = 0;

      stars.forEach((star, index) => {
        const rating = index + 1;

        star.addEventListener('click', () => {
          currentRating = rating;
          input.value = rating;
          
          stars.forEach((s, i) => {
            if (i < rating) {
              s.classList.add('filled');
              s.textContent = '⭐';
            } else {
              s.classList.remove('filled');
              s.textContent = '☆';
            }
          });
        });

        star.addEventListener('mouseenter', () => {
          stars.forEach((s, i) => {
            if (i < rating) {
              s.classList.add('active');
            } else {
              s.classList.remove('active');
            }
          });
        });

        container.addEventListener('mouseleave', () => {
          stars.forEach((s, i) => {
            if (i < currentRating) {
              s.classList.add('active');
            } else {
              s.classList.remove('active');
            }
          });
        });
      });
    }

    // Функция для отправки отзыва
    async function submitReview(ratingInput, textarea, successMsg, submitBtn) {
      if (!ratingInput || !textarea) return;

      const rating = parseInt(ratingInput.value);
      const text = textarea.value.trim();

      if (!rating || rating < 1 || rating > 5) {
        showInternalNotification('⚠️ Пожалуйста, выберите оценку', 'warning');
        return;
      }

      try {
        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.textContent = 'Отправка...';
        }

        const apiBase = normalizeApiBase(state.settings.apiBase);
        const deviceId = await getDeviceId();

        // Получаем версию расширения
        const manifest = chrome.runtime.getManifest();
        const extensionVersion = manifest.version || '1.0.8';

        console.log('[Reviews] Sending review to:', `${apiBase}/api/reviews`);
        console.log('[Reviews] Payload:', {
          rating,
          text,
          device_id: deviceId,
          extension_version: extensionVersion
        });

        const response = await fetch(`${apiBase}/api/reviews`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Device-ID': deviceId,
            'X-Extension-Version': extensionVersion
          },
          body: JSON.stringify({
            rating: rating,
            text: text || null
          })
        });

        if (!response.ok) {
          const error = await response.json().catch(() => ({ detail: 'Ошибка отправки' }));
          throw new Error(error?.detail || 'Ошибка отправки отзыва');
        }

        const data = await response.json();
        
        // Показываем сообщение об успехе
        if (successMsg) {
          successMsg.classList.remove('hidden');
          setTimeout(() => {
            successMsg.classList.add('hidden');
          }, 5000);
        }

        showInternalNotification('✅ Спасибо за ваш отзыв!', 'success');

        // Очищаем форму
        ratingInput.value = '0';
        textarea.value = '';
        
        // Сбрасываем звезды
        const stars = (ratingInput.id === 'rating-value-popup' ? starRatingPopup : starRating)?.querySelectorAll('.star');
        if (stars) {
          stars.forEach(star => {
            star.classList.remove('filled', 'active');
            star.textContent = '☆';
          });
        }
      } catch (error) {
        console.error('[AVQON] Submit review error:', error);
        showInternalNotification('❌ ' + (error.message || 'Ошибка отправки отзыва'), 'error');
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Отправить отзыв';
        }
      }
    }

    // Инициализация для popup
    if (starRatingPopup && ratingInputPopup) {
      initStars(starRatingPopup, ratingInputPopup);
      
      if (submitBtnPopup) {
        const textareaPopup = document.getElementById('review-text-popup');
        submitBtnPopup.addEventListener('click', () => {
          submitReview(ratingInputPopup, textareaPopup, successMsgPopup, submitBtnPopup);
        });
      }
    }

    // Инициализация для sidepanel
    if (starRating && ratingInput) {
      initStars(starRating, ratingInput);
      
      if (submitBtn) {
        const textarea = document.getElementById('review-text');
        submitBtn.addEventListener('click', () => {
          submitReview(ratingInput, textarea, successMsg, submitBtn);
        });
      }
    }
  }

  document.addEventListener('DOMContentLoaded', init);
  
  