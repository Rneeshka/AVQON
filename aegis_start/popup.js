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
    hoverTheme: 'classic'
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
  function setBadgeState(stateName) {
    const badge = elements.statusBadge;
    const analysisBadge = elements.analysisBadge;
    const text = BADGE_TEXT[stateName] || stateName?.toUpperCase() || 'READY';
    if (badge) {
      badge.className = `badge ${stateName || 'ready'}`;
      badge.textContent = text;
    }
    if (analysisBadge) {
      analysisBadge.className = `badge ${stateName || 'ready'}`;
      analysisBadge.textContent = text;
    }
  }

  function setConnectionState(isOnline, message) {
    const dot = elements.statusDot;
    if (dot) {
      dot.classList.remove('online', 'offline', 'checking');
      dot.classList.add(isOnline ? 'online' : 'offline');
    }
    if (elements.connectionText) {
      elements.connectionText.textContent = message || (isOnline ? 'Подключено' : 'Нет подключения');
    }
  }

  function toggleWarning(show, text) {
    if (!elements.warningCard) return;
    elements.warningCard.classList.toggle('hidden', !show);
    if (show && elements.warningText) {
      elements.warningText.textContent = text || 'Обнаружены угрозы';
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
  function renderResult(url, response) {
    if (!elements.resultEl) return;
    const res = response || {};
    const verdict = resolveVerdict(res);

    applyAnalysisVerdict(verdict);
    setBadgeState(verdict === 'malicious' ? 'malicious' : verdict || 'ready');

    if (elements.statusHeadline) {
      const map = {
        malicious: 'Опасно',
        suspicious: 'Подозрительно',
        safe: 'Безопасно',
        clean: 'Безопасно',
        unknown: 'Неизвестно'
      };
      elements.statusHeadline.textContent = map[verdict] || 'Готово';
    }
    if (elements.statusText) {
      elements.statusText.textContent = elements.statusHeadline ? elements.statusHeadline.textContent : 'Готово';
    }

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

  async function handleLogin() {
    const usernameEl = document.getElementById('login-username');
    const passwordEl = document.getElementById('login-password');
    const loginBtn = document.getElementById('login-btn');
    
    if (!usernameEl || !passwordEl) return;
    
    const username = usernameEl.value.trim();
    const password = passwordEl.value.trim();
    
    if (!username || !password) {
      alert('Заполните логин и пароль');
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
      
      const res = await fetch(`${apiBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
      
      await new Promise((resolve) => {
        chrome.storage.sync.set({ account }, () => {
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
      
      alert('✅ Успешный вход!');
    } catch (error) {
      console.error('[Aegis] Login error:', error);
      alert(error.message || 'Ошибка входа');
    } finally {
      if (loginBtn) {
        loginBtn.disabled = false;
        loginBtn.textContent = 'Войти';
      }
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
      alert('Заполните все обязательные поля');
      return;
    }
    
    if (password.length < 6) {
      alert('Пароль должен содержать минимум 6 символов');
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
      
      alert('✅ Аккаунт создан. Выполните вход.');
      
      // Переключаемся на форму входа
      const loginForm = document.getElementById('login-form');
      const registerForm = document.getElementById('register-form');
      if (loginForm) loginForm.style.display = 'block';
      if (registerForm) registerForm.style.display = 'none';
      if (document.body) document.body.setAttribute('data-account-mode', 'login');
      
    } catch (error) {
      console.error('[Aegis] Register error:', error);
      alert(error.message || 'Ошибка регистрации');
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
      alert('Введите email');
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
      
      alert('✅ Письмо отправлено. Проверьте почту.');
    } catch (error) {
      console.error('[Aegis] Forgot password error:', error);
      alert(error.message || 'Ошибка отправки');
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
      alert('Заполните все поля');
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
        body: JSON.stringify({ email, code, new_password: newPassword }),
        signal: controller.signal
      });
      
      clearTimeout(timeout);
      
      if (!res.ok) {
        const error = await res.json().catch(() => ({ detail: 'Ошибка сброса' }));
        throw new Error(error?.detail || 'Ошибка сброса');
      }
      
      alert('✅ Пароль изменен. Войдите снова.');
      
      // Переключаемся на форму входа
      const loginForm = document.getElementById('login-form');
      const forgotForm = document.getElementById('forgot-form');
      if (loginForm) loginForm.style.display = 'block';
      if (forgotForm) forgotForm.style.display = 'none';
      if (document.body) document.body.setAttribute('data-account-mode', 'login');
      
    } catch (error) {
      console.error('[Aegis] Reset password error:', error);
      alert(error.message || 'Ошибка сброса');
    } finally {
      if (resetBtn) {
        resetBtn.disabled = false;
        resetBtn.textContent = 'Сбросить пароль';
      }
    }
  }

  function handleLogout() {
    chrome.storage.sync.remove(['account', 'apiKey'], () => {
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
  async function checkConnectionStatus() {
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
      renderResult(null, { details: 'Защита отключена', safe: null });
      return;
    }

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs && tabs[0];
      if (!tab || !tab.url || tab.url.startsWith('chrome')) {
        renderResult(null, { details: 'Нет доступного URL для проверки', safe: null });
        return;
      }

      setBadgeState('suspicious');
      if (elements.statusHeadline) elements.statusHeadline.textContent = 'Проверяем...';
      if (elements.statusText) elements.statusText.textContent = 'Проверяем...';

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
      setBadgeState('unknown');
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

    await checkConnectionStatus();
    state.connectionTimer = setInterval(checkConnectionStatus, 30000);

    await scanActiveTab();

    // Дополнительно обновляем результат при фокусе окна
    window.addEventListener('focus', () => {
      checkConnectionStatus();
      scanActiveTab();
    });
  }

  document.addEventListener('DOMContentLoaded', init);
  