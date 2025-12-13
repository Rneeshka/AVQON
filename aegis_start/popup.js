  const DEFAULTS = {
    antivirusEnabled: true,
    linkCheck: true,
    hoverScan: true,
    notify: true,
    apiBase: 'https://api.aegis.builders',
    hoverTheme: 'classic'
  };

  const views = ['home', 'settings', 'customize', 'about'];
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
    // КРИТИЧНО: Раздельные состояния для подключения и сканирования
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

  function showInternalNotification(message, type = 'info') {
    // Создаем элемент уведомления внутри расширения
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${type === 'success' ? '#10B981' : type === 'error' ? '#EF4444' : '#F59E0B'};
      color: white;
      padding: 12px 16px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 10000;
      font-size: 14px;
      font-weight: 500;
      max-width: 300px;
      animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;
    
    // Добавляем стиль для анимации
    if (!document.getElementById('notification-styles')) {
      const style = document.createElement('style');
      style.id = 'notification-styles';
      style.textContent = `
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(100%); opacity: 0; }
        }
      `;
      document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    // Удаляем через 3 секунды
    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease-out';
      setTimeout(() => {
        if (notification.parentNode) {
          notification.parentNode.removeChild(notification);
        }
      }, 300);
    }, 3000);
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
    
    // Простой вывод в одну строку: URL - Вердикт
    elements.resultEl.innerHTML = '';
    if (domain) {
      const resultLine = document.createElement('div');
      resultLine.style.cssText = 'display: flex; align-items: center; gap: 8px; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;';
      
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
    } else {
      elements.resultEl.innerHTML = '<p class="muted">Нет данных по текущему URL.</p>';
    }

    toggleWarning(verdict === 'malicious', res.details);
  }

  function resolveVerdict(res) {
    if (!res || typeof res !== 'object') return 'unknown';
    if (res.safe === false) return 'malicious';
    if (res.safe === true) return 'safe';
    if (res.threat_type) return 'suspicious';
    return 'unknown';
  }

  /**
   * Event handlers
   */
  function initTabs() {
    views.forEach((view) => {
      const btn = document.getElementById(`tab-${view}`);
      if (btn) {
        btn.addEventListener('click', () => switchView(view));
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
      const normalized = mode || 'login';
      if (document.body) {
        document.body.setAttribute('data-account-mode', normalized);
      }
      if (loginForm) loginForm.style.display = normalized === 'login' ? 'block' : 'none';
      if (registerForm) registerForm.style.display = normalized === 'register' ? 'block' : 'none';
      if (forgotForm) forgotForm.style.display = normalized === 'forgot' ? 'block' : 'none';
      if (accountInfo) accountInfo.style.display = normalized === 'account' ? 'block' : 'none';
    }

    function showLogin() {
      // Не переключаемся в режим логина, если аккаунт уже привязан
      const currentMode = document.body?.getAttribute('data-account-mode');
      if (currentMode === 'account') return;
      applyAccountMode('login');
    }
    function showRegister() {
      const currentMode = document.body?.getAttribute('data-account-mode');
      if (currentMode === 'account') return;
      applyAccountMode('register');
    }
    function showForgot() {
      const currentMode = document.body?.getAttribute('data-account-mode');
      if (currentMode === 'account') return;
      applyAccountMode('forgot');
    }

    if (registerBtn) registerBtn.addEventListener('click', showRegister);
    if (loginBtn) loginBtn.addEventListener('click', showLogin);
    if (forgotBtn) forgotBtn.addEventListener('click', showForgot);
    if (backToLoginBtn) backToLoginBtn.addEventListener('click', showLogin);

    chrome.storage?.sync?.get(['account', 'apiKey'], (data) => {
      if (chrome.runtime?.lastError) {
        applyAccountMode('login');
        return;
      }
      if (data?.account) {
        applyAccountMode('account');
        showAccountInfo(data.account);
      } else {
        applyAccountMode('login');
      }
    });

    // Обработчики кнопок
    const loginSubmitBtn = document.getElementById('login-btn');
    const registerSubmitBtn = document.getElementById('register-btn');
    const forgotSubmitBtn = document.getElementById('forgot-btn');
    const resetSubmitBtn = document.getElementById('reset-btn');
    const logoutSubmitBtn = document.getElementById('logout-btn');

    if (loginSubmitBtn) {
      loginSubmitBtn.addEventListener('click', handleLogin);
    }
    if (registerSubmitBtn) {
      registerSubmitBtn.addEventListener('click', handleRegister);
    }
    if (forgotSubmitBtn) {
      forgotSubmitBtn.addEventListener('click', handleForgotPassword);
    }
    if (resetSubmitBtn) {
      resetSubmitBtn.addEventListener('click', handleResetPassword);
    }
    if (logoutSubmitBtn) {
      logoutSubmitBtn.addEventListener('click', handleLogout);
    }
  }

  function showAccountInfo(account) {
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
      
      // Сохраняем account и session_token
      await new Promise((resolve) => {
        chrome.storage.sync.set({ 
          account: account,
          session_token: data.session_token 
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
      
      showAccountInfo(account);
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
    chrome.storage.sync.remove(['account', 'apiKey', 'session_token'], () => {
      const loginForm = document.getElementById('login-form');
      const accountInfo = document.getElementById('account-info');
      if (loginForm) loginForm.style.display = 'block';
      if (accountInfo) accountInfo.style.display = 'none';
      if (document.body) document.body.setAttribute('data-account-mode', 'login');
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
   * Initialization
   */
  async function init() {
    state.settings = await loadSettings();
    state.settings.apiBase = normalizeApiBase(state.settings.apiBase);
    state.hoverTheme = state.settings.hoverTheme || 'classic';

    initTabs();
    initToggles();
    initHoverThemeRadios();
    initAccountForms();

    if (elements.antivirusToggle) {
      elements.antivirusToggle.checked = !!state.settings.antivirusEnabled;
    }
    if (elements.hoverToggle) {
      elements.hoverToggle.checked = !!state.settings.hoverScan;
    }

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

    // Дополнительно обновляем результат при фокусе окна
    window.addEventListener('focus', () => {
      checkConnectionStatus();
      scanActiveTab();
    });
  }

  document.addEventListener('DOMContentLoaded', init);
  
