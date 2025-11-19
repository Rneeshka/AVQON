// popup.js – UI logic for popup and side panel
(() => {
  if (typeof chrome === 'undefined' || !chrome.runtime) {
    console.warn('[Aegis Popup] chrome.runtime is not available. Script aborted.');
    return;
  }
(() => {
  if (window.__AEGIS_POPUP_INITIALIZED__) {
    return;
  }
  window.__AEGIS_POPUP_INITIALIZED__ = true;

  const DEFAULT_API_BASE = 'https://aegis.builders';
  const STORAGE_DEFAULTS = {
    antivirusEnabled: true,
    linkCheck: true,
    hoverScan: true,
    notify: true,
    apiBase: DEFAULT_API_BASE,
    apiKey: '',
    hoverTheme: 'classic'
  };

  const state = {
    settings: { ...STORAGE_DEFAULTS },
    account: null,
    scanning: false
  };
  let layoutStylesInjected = false;

  const els = {
    status: document.getElementById('status'),
    statusSubtitle: document.getElementById('toggle-subtitle'),
    statusBadge: document.getElementById('status-badge'),
    analysisBadge: document.getElementById('analysis-badge'),
    statusText: document.getElementById('status-text'),
    result: document.getElementById('result'),
    warningCard: document.getElementById('warning-card'),
    warningText: document.getElementById('warning-text'),
    connectionText: document.getElementById('connection-text'),
    statusDot: document.getElementById('status-dot'),
    antivirusToggle: document.getElementById('antivirus-toggle'),
    hoverScanToggle: document.getElementById('opt-hover-scan'),
    accountStatus: document.getElementById('account-status'),
    accountInfo: document.getElementById('account-info'),
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    forgotForm: document.getElementById('forgot-form'),
    loginUsername: document.getElementById('login-username'),
    loginPassword: document.getElementById('login-password'),
    loginBtn: document.getElementById('login-btn'),
    registerBtn: document.getElementById('register-btn'),
    registerUsername: document.getElementById('register-username'),
    registerEmail: document.getElementById('register-email'),
    registerPassword: document.getElementById('register-password'),
    registerApiKey: document.getElementById('register-api-key'),
    showRegisterBtn: document.getElementById('show-register-btn'),
    showLoginBtn: document.getElementById('show-login-btn'),
    forgotPasswordBtn: document.getElementById('forgot-password-btn'),
    backToLoginBtn: document.getElementById('back-to-login-btn'),
    forgotBtn: document.getElementById('forgot-btn'),
    resetBtn: document.getElementById('reset-btn'),
    logoutBtn: document.getElementById('logout-btn'),
    accountUsername: document.getElementById('account-username'),
    accountEmail: document.getElementById('account-email'),
    accountAvatar: document.getElementById('account-avatar'),
    forgotEmail: document.getElementById('forgot-email'),
    resetCode: document.getElementById('reset-code'),
    newPassword: document.getElementById('new-password'),
    resetCodeSection: document.getElementById('reset-code-section'),
    sections: {
      home: document.getElementById('view-home'),
      settings: document.getElementById('view-settings'),
      customize: document.getElementById('view-customize'),
      about: document.getElementById('view-about')
    },
    tabButtons: {
      home: document.getElementById('tab-home'),
      settings: document.getElementById('tab-settings'),
      customize: document.getElementById('tab-customize'),
      about: document.getElementById('tab-about')
    }
  };

  const hoverThemeInputs = Array.from(document.querySelectorAll('input[name="hover-theme"]'));
  const logLinks = Array.from(document.querySelectorAll('#open-logs'));

  function init() {
    bindTabNavigation();
    bindSettingToggles();
    bindHoverThemeControls();
    bindAccountControls();
    bindLogLinks();
    loadSettings();
    loadAccount();
    setActiveTab('home');
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        checkConnection();
        if (!state.scanning) {
          scanActiveTab();
        }
      }
    });
  }

  function bindTabNavigation() {
    Object.entries(els.tabButtons).forEach(([name, btn]) => {
      if (!btn) return;
      btn.addEventListener('click', () => setActiveTab(name));
    });
  }

  function setActiveTab(name) {
    Object.entries(els.sections).forEach(([key, section]) => {
      if (!section) return;
      if (key === name) {
        section.style.display = '';
        section.classList.add('active');
      } else {
        section.style.display = 'none';
        section.classList.remove('active');
      }
    });
    Object.entries(els.tabButtons).forEach(([key, btn]) => {
      if (!btn) return;
      btn.classList.toggle('primary', key === name);
    });
  }

  function bindSettingToggles() {
    if (els.antivirusToggle) {
      els.antivirusToggle.addEventListener('change', (e) => {
        persistSettings({ antivirusEnabled: e.target.checked });
        chrome.runtime.sendMessage({ type: 'antivirus_toggle', enabled: e.target.checked });
        updateProtectionSubtitle();
        scanActiveTab();
      });
    }
    if (els.hoverScanToggle) {
      els.hoverScanToggle.addEventListener('change', (e) => {
        persistSettings({ hoverScan: e.target.checked });
      });
    }
  }

  function bindHoverThemeControls() {
    hoverThemeInputs.forEach((input) => {
      input.addEventListener('change', () => {
        if (!input.checked) return;
        persistSettings({ hoverTheme: input.value });
      });
    });
  }

  function bindLogLinks() {
    logLinks.forEach((link) => {
      if (!link) return;
      link.addEventListener('click', (e) => {
        e.preventDefault();
        if (chrome?.runtime?.openOptionsPage) {
          chrome.runtime.openOptionsPage();
        } else {
          chrome.tabs.create({ url: 'chrome://extensions/' });
        }
      });
    });
  }

  function bindAccountControls() {
    els.showRegisterBtn?.addEventListener('click', () => showRegisterForm());
    els.showLoginBtn?.addEventListener('click', () => showLoginForm());
    els.forgotPasswordBtn?.addEventListener('click', () => showForgotForm());
    els.backToLoginBtn?.addEventListener('click', () => showLoginForm());
    els.loginBtn?.addEventListener('click', handleLogin);
    els.registerBtn?.addEventListener('click', handleRegister);
    els.forgotBtn?.addEventListener('click', handleForgotPassword);
    els.resetBtn?.addEventListener('click', handleResetPassword);
    els.logoutBtn?.addEventListener('click', handleLogout);
  }

  function loadSettings() {
    chrome.storage?.sync?.get(STORAGE_DEFAULTS, (cfg) => {
      if (chrome.runtime?.lastError) {
        console.warn('[Aegis Popup] storage error', chrome.runtime.lastError);
        cfg = STORAGE_DEFAULTS;
      }
      state.settings = { ...STORAGE_DEFAULTS, ...cfg };
      applySettingsToUI();
      checkConnection();
      scanActiveTab();
    });
  }

  function applySettingsToUI() {
    if (els.antivirusToggle) els.antivirusToggle.checked = !!state.settings.antivirusEnabled;
    if (els.hoverScanToggle) els.hoverScanToggle.checked = !!state.settings.hoverScan;
    updateProtectionSubtitle();
    hoverThemeInputs.forEach((input) => {
      input.checked = input.value === (state.settings.hoverTheme || 'classic');
    });
  }

  function updateProtectionSubtitle() {
    if (!els.statusSubtitle) return;
    if (!state.settings.antivirusEnabled) {
      els.statusSubtitle.textContent = 'Проверки и уведомления отключены';
      setBadgeState('disabled');
    } else {
      els.statusSubtitle.textContent = 'Сканирование ссылок и загрузок';
    }
  }

  function persistSettings(patch) {
    state.settings = { ...state.settings, ...patch };
    chrome.storage?.sync?.set(state.settings, () => {
      chrome.runtime?.lastError && console.warn('[Aegis Popup] storage set error', chrome.runtime.lastError);
    });
    chrome.runtime?.sendMessage?.({
      type: 'settings_updated',
      settings: state.settings
    });
  }

  function loadAccount() {
    chrome.storage?.sync?.get(['account', 'apiKey'], (data) => {
      if (chrome.runtime?.lastError) {
        console.warn('[Aegis Popup] account load error', chrome.runtime.lastError);
        return;
      }
      state.account = data.account || null;
      const hasAccount = !!state.account;
      const hasApiKey = !!data.apiKey;
      if (hasAccount) {
        showAccountInfo(state.account);
      } else {
        showLoginForm();
      }
      updateHoverScanAvailability(hasAccount && hasApiKey);
    });
  }

  function updateHoverScanAvailability(enabled) {
    if (!els.hoverScanToggle) return;
    if (enabled) {
      els.hoverScanToggle.disabled = false;
      els.hoverScanToggle.parentElement?.classList.remove('muted');
    } else {
      els.hoverScanToggle.checked = false;
      els.hoverScanToggle.disabled = true;
      els.hoverScanToggle.parentElement?.classList.add('muted');
      persistSettings({ hoverScan: false });
    }
  }

  function setBadgeState(stateName) {
    const map = {
      ready: 'READY',
      scanning: 'SCAN',
      safe: 'SAFE',
      clean: 'SAFE',
      suspicious: 'WARN',
      malicious: 'DANGER',
      unknown: 'UNKNOWN',
      disabled: 'OFF'
    };
    if (els.statusBadge) {
      els.statusBadge.className = `badge ${stateName}`;
      els.statusBadge.textContent = map[stateName] || stateName?.toUpperCase() || 'READY';
    }
    if (els.analysisBadge) {
      els.analysisBadge.className = `badge ${stateName}`;
      els.analysisBadge.textContent = map[stateName] || stateName?.toUpperCase() || 'SAFE';
    }
  }

  async function checkConnection() {
    if (!els.connectionText || !els.statusDot) return;
    setConnectionState('checking', 'Проверка подключения...');
    const apiBase = normalizeApiBase(state.settings.apiBase || DEFAULT_API_BASE);
    try {
      await fetchWithTimeout(`${apiBase}/health`, {}, 4000);
      setConnectionState('online', 'Подключено');
    } catch (error) {
      console.warn('[Aegis Popup] connection error:', error);
      setConnectionState('offline', 'Нет подключения');
    }
  }

  function setConnectionState(stateName, text) {
    if (els.connectionText) {
      els.connectionText.textContent = text;
    }
    if (!els.statusDot) return;
    els.statusDot.classList.remove('online', 'offline', 'checking');
    els.statusDot.classList.add(stateName);
  }

  async function scanActiveTab() {
    if (!state.settings.antivirusEnabled) {
      showResultMessage('Защита выключена. Включите переключатель, чтобы проверить страницу.');
      setBadgeState('disabled');
      return;
    }
    const tab = await queryActiveTab();
    if (!tab || !tab.url) {
      showResultMessage('Откройте вкладку с URL для проверки.');
      return;
    }
    state.scanning = true;
    setStatusText('Сканируем...');
    setBadgeState('scanning');
    chrome.runtime?.sendMessage?.(
      { type: 'ws_analyze_url', url: tab.url, context: 'popup' },
      (response) => {
        state.scanning = false;
        if (chrome.runtime?.lastError) {
          console.error('[Aegis Popup] scan error:', chrome.runtime.lastError);
          showResultMessage('Не удалось выполнить проверку. Попробуйте еще раз.');
          setBadgeState('suspicious');
          return;
        }
        if (!response || !response.ok) {
          showResultMessage('Сервис проверки недоступен. Попробуйте позже.');
          setBadgeState('suspicious');
          return;
        }
        renderResult(tab.url, response.data || response.result || response);
      }
    );
  }

  function queryActiveTab() {
    return new Promise((resolve) => {
      chrome.tabs?.query?.({ active: true, lastFocusedWindow: true }, (tabs) => {
        resolve(tabs && tabs.length ? tabs[0] : null);
      });
    });
  }

  function setStatusText(text) {
    if (els.status) {
      els.status.textContent = text;
    }
    if (els.statusText) {
      els.statusText.textContent = text;
    }
  }

  function showResultMessage(text) {
    if (!els.result) return;
    els.result.innerHTML = `<p class="muted">${text}</p>`;
    if (els.warningCard) {
      els.warningCard.classList.add('hidden');
    }
  }

  function ensureLayoutStyles() {
    if (layoutStylesInjected) return;
    const style = document.createElement('style');
    style.id = 'aegis-layout-overrides';
    style.textContent = `
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
    `;
    document.head?.appendChild(style);
    layoutStylesInjected = true;
  }

  function enhanceShieldCards() {
    const cards = document.querySelectorAll('.shield-card');
    if (!cards.length) return;
    ensureLayoutStyles();
    cards.forEach((card) => {
      if (card.dataset.aegisLayout === '1') return;
      card.dataset.aegisLayout = '1';
      const connectionRow = card.querySelector('.connection');
      if (connectionRow) {
        const block = document.createElement('div');
        block.className = 'connection-block';
        const label = document.createElement('p');
        label.className = 'eyebrow';
        label.style.letterSpacing = '0.1em';
        label.textContent = 'Подключение';
        block.appendChild(label);
        block.appendChild(connectionRow);
        card.insertBefore(block, card.firstChild);
      }

      const head = card.querySelector('.shield-head');
      const statusHeading = head?.querySelector('#status') || card.querySelector('#status');
      const subtitle = head?.querySelector('#toggle-subtitle') || card.querySelector('#toggle-subtitle');
      const icon = head?.querySelector('.shield-icon');
      if (head) head.remove();

      const verdictBlock = document.createElement('div');
      verdictBlock.className = 'verdict-block';
      const verdictLabel = document.createElement('p');
      verdictLabel.className = 'eyebrow';
      verdictLabel.style.letterSpacing = '0.1em';
      verdictLabel.textContent = 'Вердикт';
      const verdictRow = document.createElement('div');
      verdictRow.className = 'verdict-row';
      if (statusHeading) verdictRow.appendChild(statusHeading);
      if (icon) verdictRow.appendChild(icon);
      verdictBlock.appendChild(verdictLabel);
      verdictBlock.appendChild(verdictRow);
      if (subtitle) verdictBlock.appendChild(subtitle);
      card.appendChild(verdictBlock);
    });
  }

  function renderResult(url, data) {
    if (!els.result) return;
    const verdict = determineVerdict(data);
    const verdictLabels = {
      clean: 'Готово',
      safe: 'Готово',
      malicious: 'Опасно',
      suspicious: 'Подозрительно',
      unknown: 'Неизвестно'
    };
    setBadgeState(verdict);
    setStatusText(verdictLabels[verdict] || 'Готово');
    if (els.warningCard) {
      els.warningCard.classList.toggle('hidden', verdict !== 'malicious');
      if (els.warningText) {
        els.warningText.textContent = data?.details || 'Обнаружены угрозы';
      }
    }
    const container = document.createElement('div');
    container.className = 'kv';
    const addRow = (title, value) => {
      if (!value) return;
      const keyEl = document.createElement('div');
      keyEl.className = 'k';
      keyEl.textContent = title;
      const valEl = document.createElement('div');
      valEl.className = 'v';
      valEl.textContent = typeof value === 'string' ? value : JSON.stringify(value);
      container.appendChild(keyEl);
      container.appendChild(valEl);
    };
    addRow('URL', tryExtractHost(url));
    if (typeof data.safe === 'boolean') {
      addRow('Безопасно', data.safe ? 'Да' : 'Нет');
    } else {
      addRow('Безопасно', 'Неизвестно');
    }
    if (data.threat_type) addRow('Тип угрозы', data.threat_type);
    if (data.source && data.source !== 'error') addRow('Источник', data.source);
    if (data.details && data.details !== 'rest_fallback') addRow('Детали', sanitizeDetails(data.details));
    if (data.confidence != null) addRow('Уверенность', `${data.confidence}%`);
    if (data.timestamp) addRow('Время', new Date(data.timestamp).toLocaleString());
    if (Array.isArray(data.external_scans) && data.external_scans.length) {
      const info = data.external_scans
        .map((scan) => `${scan.source || 'внешний'}: ${formatVerdict(scan.safe)}`)
        .join(', ');
      addRow('Внешние проверки', info);
    }
    els.result.innerHTML = '';
    els.result.appendChild(container);
  }

  function determineVerdict(data) {
    if (!data || typeof data.safe === 'undefined' || data.safe === null) return 'unknown';
    return data.safe ? 'safe' : 'malicious';
  }

  function formatVerdict(value) {
    if (value === true) return 'безопасно';
    if (value === false) return 'опасно';
    return 'неизвестно';
  }

  function sanitizeDetails(details) {
    if (Array.isArray(details)) {
      return details.join(', ');
    }
    if (typeof details === 'object') {
      try {
        return JSON.stringify(details);
      } catch (_) {
        return String(details);
      }
    }
    return String(details);
  }

  function tryExtractHost(url) {
    try {
      return new URL(url).hostname;
    } catch (_) {
      return url;
    }
  }

  function showLoginForm() {
    toggleAccountForms('login');
  }

  function showRegisterForm() {
    toggleAccountForms('register');
  }

  function showForgotForm() {
    toggleAccountForms('forgot');
  }

  function showAccountInfo(account) {
    if (!account) {
      showLoginForm();
      return;
    }
    toggleAccountForms('account');
    if (els.accountUsername) els.accountUsername.textContent = account.username || '—';
    if (els.accountEmail) els.accountEmail.textContent = account.email || '—';
    if (els.accountStatus) els.accountStatus.textContent = `Аккаунт: ${account.username || ''}`;
    if (els.accountAvatar) {
      const letter = (account.username || account.email || '?').charAt(0).toUpperCase();
      els.accountAvatar.textContent = letter;
    }
  }

  function toggleAccountForms(mode) {
    if (document.body) {
      document.body.setAttribute('data-account-mode', mode);
    }
    if (els.loginForm) els.loginForm.style.display = mode === 'login' ? 'block' : 'none';
    if (els.registerForm) els.registerForm.style.display = mode === 'register' ? 'block' : 'none';
    if (els.forgotForm) els.forgotForm.style.display = mode === 'forgot' ? 'block' : 'none';
    if (els.accountInfo) els.accountInfo.style.display = mode === 'account' ? 'block' : 'none';
    if (els.accountStatus) {
      const map = {
        login: 'Вход в аккаунт',
        register: 'Регистрация',
        forgot: 'Восстановление доступа',
        account: 'Аккаунт привязан'
      };
      els.accountStatus.textContent = map[mode] || 'Аккаунт';
    }
  }

  async function handleLogin() {
    const username = els.loginUsername?.value.trim();
    const password = els.loginPassword?.value.trim();
    if (!username || !password) {
      alert('Заполните логин и пароль');
      return;
    }
    const apiBase = normalizeApiBase(state.settings.apiBase || DEFAULT_API_BASE);
    try {
      setButtonBusy(els.loginBtn, true, 'Вход...');
      const res = await fetchWithTimeout(`${apiBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      }, 10000);
      if (!res.ok) {
        const error = await safeJson(res);
        throw new Error(error?.detail || 'Не удалось войти');
      }
      const data = await res.json();
      state.account = data.account;
      await chrome.storage?.sync?.set({ account: data.account });
      if (data.api_keys && data.api_keys.length) {
        await chrome.storage?.sync?.set({ apiKey: data.api_keys[0].api_key });
      }
      showAccountInfo(state.account);
      updateHoverScanAvailability(true);
      alert('Успешный вход');
    } catch (error) {
      alert(error.message);
    } finally {
      setButtonBusy(els.loginBtn, false, 'Войти');
    }
  }

  async function handleRegister() {
    const username = els.registerUsername?.value.trim();
    const email = els.registerEmail?.value.trim();
    const password = els.registerPassword?.value.trim();
    const apiKey = els.registerApiKey?.value.trim();
    if (!username || !email || !password || !apiKey) {
      alert('Заполните все поля для регистрации');
      return;
    }
    if (password.length < 6) {
      alert('Пароль должен содержать минимум 6 символов');
      return;
    }
    const apiBase = normalizeApiBase(state.settings.apiBase || DEFAULT_API_BASE);
    try {
      setButtonBusy(els.registerBtn, true, 'Регистрация...');
      const res = await fetchWithTimeout(`${apiBase}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, api_key: apiKey })
      }, 10000);
      if (!res.ok) {
        const error = await safeJson(res);
        throw new Error(error?.detail || 'Ошибка регистрации');
      }
      await chrome.storage?.sync?.set({ apiKey });
      alert('Аккаунт создан. Выполните вход.');
      showLoginForm();
    } catch (error) {
      alert(error.message);
    } finally {
      setButtonBusy(els.registerBtn, false, 'Зарегистрироваться');
    }
  }

  async function handleForgotPassword() {
    const email = els.forgotEmail?.value.trim();
    if (!email) {
      alert('Введите email');
      return;
    }
    const apiBase = normalizeApiBase(state.settings.apiBase || DEFAULT_API_BASE);
    try {
      setButtonBusy(els.forgotBtn, true, 'Отправляем...');
      const res = await fetchWithTimeout(`${apiBase}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      }, 10000);
      if (!res.ok) {
        const error = await safeJson(res);
        throw new Error(error?.detail || 'Ошибка отправки');
      }
      els.resetCodeSection && (els.resetCodeSection.style.display = 'block');
      alert('Письмо отправлено. Проверьте почту.');
    } catch (error) {
      alert(error.message);
    } finally {
      setButtonBusy(els.forgotBtn, false, 'Отправить код');
    }
  }

  async function handleResetPassword() {
    const email = els.forgotEmail?.value.trim();
    const code = els.resetCode?.value.trim();
    const newPassword = els.newPassword?.value.trim();
    if (!email || !code || !newPassword) {
      alert('Заполните все поля');
      return;
    }
    const apiBase = normalizeApiBase(state.settings.apiBase || DEFAULT_API_BASE);
    try {
      setButtonBusy(els.resetBtn, true, 'Сбрасываем...');
      const res = await fetchWithTimeout(`${apiBase}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code, new_password: newPassword })
      }, 10000);
      if (!res.ok) {
        const error = await safeJson(res);
        throw new Error(error?.detail || 'Ошибка сброса');
      }
      alert('Пароль изменен. Войдите снова.');
      showLoginForm();
    } catch (error) {
      alert(error.message);
    } finally {
      setButtonBusy(els.resetBtn, false, 'Сбросить пароль');
    }
  }

  function handleLogout() {
    chrome.storage?.sync?.remove(['account', 'apiKey'], () => {
      state.account = null;
      showLoginForm();
      updateHoverScanAvailability(false);
    });
  }

  function setButtonBusy(button, busy, busyText) {
    if (!button) return;
    if (busy) {
      button.dataset.originalText = button.textContent;
      button.textContent = busyText;
      button.disabled = true;
    } else {
      button.textContent = button.dataset.originalText || button.textContent;
      button.disabled = false;
    }
  }

  function normalizeApiBase(value) {
    let base = (value || '').toString().trim();
    if (!base) return DEFAULT_API_BASE;
    if (!/^https?:\/\//i.test(base)) {
      base = `https://${base}`;
    }
    try {
      const url = new URL(base);
      url.pathname = url.pathname.replace(/\/proxy\/?$/, '') || '/';
      url.search = '';
      url.hash = '';
      return `${url.origin}${url.pathname}`.replace(/\/$/, '') || url.origin;
    } catch (_) {
      return DEFAULT_API_BASE;
    }
  }

  function fetchWithTimeout(resource, options = {}, timeoutMs = 8000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(resource, { ...options, signal: controller.signal })
      .finally(() => clearTimeout(id));
  }

  async function safeJson(response) {
    try {
      return await response.json();
    } catch (_) {
      return null;
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
  const DEFAULTS = {
    antivirusEnabled: true,
    linkCheck: true,
    hoverScan: true,
    notify: true,
    apiBase: 'https://aegis.builders',
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

    chrome.storage?.sync?.get(['account'], (data) => {
      if (chrome.runtime?.lastError) {
        applyAccountMode('login');
        return;
      }
      applyAccountMode(data?.account ? 'account' : 'login');
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
        type: 'ws_analyze_url',
        url: tab.url,
        context: 'popup'
      });

      if (!response || !response.ok) {
        throw new Error(response?.error || 'Сервер недоступен');
      }

      renderResult(tab.url, response.data || response.result || {});
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
    enhanceShieldCards();

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
})();