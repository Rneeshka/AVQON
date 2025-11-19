// options.js
(function() {
  const DEFAULT_API_BASE = 'https://aegis.builders';
  const defaults = {
    antivirusEnabled: true,
    linkCheck: true,
    hoverScan: true,
    notify: true,
    apiBase: DEFAULT_API_BASE,
    apiKey: ''
  };

  const el = {
    antivirus: document.getElementById('opt-antivirus'),
    linkCheck: document.getElementById('opt-link-check'),
    hoverScan: document.getElementById('opt-hover-scan'),
    notify: document.getElementById('opt-notify'),
    apiBase: document.getElementById('opt-api-base'),
    save: document.getElementById('save-btn'),
    reset: document.getElementById('reset-btn'),
    // Account elements
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    forgotForm: document.getElementById('forgot-form'),
    accountInfo: document.getElementById('account-info'),
    accountStatus: document.getElementById('account-status'),
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
    forgotEmail: document.getElementById('forgot-email'),
    resetCode: document.getElementById('reset-code'),
    newPassword: document.getElementById('new-password'),
    resetCodeSection: document.getElementById('reset-code-section')
  };

  function normalizeApiBase(v) {
    let base = (v || '').toString().trim();
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

  // Обертка для fetch с таймаутом
  function fetchWithTimeout(resource, options = {}, timeoutMs = 10000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    const opts = { ...options, signal: controller.signal };
    return fetch(resource, opts)
      .catch(err => {
        if (err.name === 'AbortError') {
          throw new Error('Request timeout');
        } else if (err instanceof TypeError && err.message.includes('Failed to fetch')) {
          throw new Error('Network error: Failed to fetch');
        }
        throw err;
      })
      .finally(() => clearTimeout(id));
  }

  function load() {
    chrome.storage.sync.get(defaults, (cfg) => {
      el.antivirus.checked = cfg.antivirusEnabled;
      el.linkCheck.checked = cfg.linkCheck;
      el.hoverScan.checked = cfg.hoverScan;
      el.notify.checked = cfg.notify;
      const normalizedBase = normalizeApiBase(cfg.apiBase);
      el.apiBase.value = normalizedBase;
      if (cfg.apiBase !== normalizedBase) {
        chrome.storage.sync.set({ apiBase: normalizedBase }, () => chrome.runtime?.lastError && void 0);
      }
      
      // Автоматическая валидация ключа из аккаунта
      updateHoverScanState();
    });
  }
  
  async function updateHoverScanState() {
    const data = await chrome.storage.sync.get(['account', 'apiKey']);
    const hasAccount = !!data.account;
    const hasApiKey = !!data.apiKey;
    
    // Включаем hover только если есть аккаунт и ключ
    if (hasAccount && hasApiKey) {
      el.hoverScan.disabled = false;
      el.hoverScan.parentElement.style.opacity = '1';
    } else {
      el.hoverScan.checked = false;
      el.hoverScan.disabled = true;
      el.hoverScan.parentElement.style.opacity = '0.5';
    }
  }

  function save() {
    const cfg = {
      antivirusEnabled: el.antivirus.checked,
      linkCheck: el.linkCheck.checked,
      hoverScan: el.hoverScan.checked,
      notify: el.notify.checked,
      apiBase: normalizeApiBase(el.apiBase.value)
    };
    chrome.storage.sync.set(cfg, () => {
      el.save.textContent = 'Сохранено';
      setTimeout(() => (el.save.textContent = 'Сохранить'), 1200);
      
      // Notify background script of changes
      chrome.runtime.sendMessage({
        type: 'settings_updated',
        settings: cfg
      });
    });
  }

  function reset() {
    chrome.storage.sync.set(defaults, load);
  }

  // Мгновенно сохраняем переключатель hover
  el.hoverScan.addEventListener('change', () => {
    const cfg = {
      antivirusEnabled: el.antivirus.checked,
      linkCheck: el.linkCheck.checked,
      hoverScan: el.hoverScan.checked,
      notify: el.notify.checked,
      apiBase: normalizeApiBase(el.apiBase.value)
    };
    chrome.storage.sync.set(cfg, () => {
      chrome.runtime.sendMessage({ type: 'settings_updated', settings: cfg });
    });
  });

  // ===== ACCOUNT MANAGEMENT =====
  
  function showLoginForm() {
    el.loginForm.style.display = 'block';
    el.registerForm.style.display = 'none';
    el.forgotForm.style.display = 'none';
    el.accountInfo.style.display = 'none';
    el.accountStatus.textContent = 'Вход в аккаунт';
  }
  
  function showForgotForm() {
    el.loginForm.style.display = 'none';
    el.registerForm.style.display = 'none';
    el.forgotForm.style.display = 'block';
    el.accountInfo.style.display = 'none';
    el.accountStatus.textContent = 'Восстановление пароля';
  }
  
  function showRegisterForm() {
    el.loginForm.style.display = 'none';
    el.registerForm.style.display = 'block';
    el.forgotForm.style.display = 'none';
    el.accountInfo.style.display = 'none';
    el.accountStatus.textContent = 'Регистрация аккаунта';
  }
  
  function showAccountInfo(account) {
    el.loginForm.style.display = 'none';
    el.registerForm.style.display = 'none';
    el.forgotForm.style.display = 'none';
    el.accountInfo.style.display = 'block';
    el.accountUsername.textContent = account.username;
    el.accountEmail.textContent = account.email;
    el.accountStatus.textContent = `Аккаунт: ${account.username}`;
  }
  
  async function loadAccount() {
    const data = await chrome.storage.sync.get(['account', 'apiKey']);
    if (data.account) {
      showAccountInfo(data.account);
      // Обновляем состояние hover при загрузке
      updateHoverScanState();
    } else {
      showLoginForm();
    }
  }
  
  async function handleLogin() {
    const username = el.loginUsername.value.trim();
    const password = el.loginPassword.value.trim();
    const apiBase = normalizeApiBase(el.apiBase.value);
    
    if (!username || !password) {
      alert('Заполните все поля');
      return;
    }
    
    if (!apiBase) {
      alert('Укажите API Base URL');
      return;
    }
    
    try {
      el.loginBtn.textContent = 'Вход...';
      el.loginBtn.disabled = true;
      
      const response = await fetchWithTimeout(`${apiBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      }, 10000);
      
      if (!response.ok) {
        const error = await response.json();
        alert(`Ошибка входа: ${error.detail}`);
        el.loginBtn.textContent = 'Войти';
        el.loginBtn.disabled = false;
        return;
      }
      
      const data = await response.json();
      await chrome.storage.sync.set({ account: data.account });
      
      // Автоматически сохраняем API ключ если есть
      if (data.api_keys && data.api_keys.length > 0) {
        const apiKey = data.api_keys[0].api_key;
        await chrome.storage.sync.set({ apiKey });
      }
      
      showAccountInfo(data.account);
      updateHoverScanState();
      alert('✅ Успешный вход!');
      
    } catch (error) {
      alert(`Ошибка: ${error.message}`);
      el.loginBtn.textContent = 'Войти';
      el.loginBtn.disabled = false;
    }
  }
  
  async function handleRegister() {
    const username = el.registerUsername.value.trim();
    const email = el.registerEmail.value.trim();
    const password = el.registerPassword.value.trim();
    const apiKey = el.registerApiKey.value.trim();
    const apiBase = normalizeApiBase(el.apiBase.value);
    
    if (!username || !email || !password || !apiKey) {
      alert('Заполните все поля');
      return;
    }
    
    if (password.length < 6) {
      alert('Пароль должен содержать минимум 6 символов');
      return;
    }
    
    if (!apiBase) {
      alert('Укажите API Base URL');
      return;
    }
    
    try {
      el.registerBtn.textContent = 'Регистрация...';
      el.registerBtn.disabled = true;
      
      const response = await fetchWithTimeout(`${apiBase}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          email,
          password,
          api_key: apiKey
        })
      }, 10000);
      
      if (!response.ok) {
        const error = await response.json();
        alert(`Ошибка регистрации: ${error.detail}`);
        el.registerBtn.textContent = 'Зарегистрироваться';
        el.registerBtn.disabled = false;
        return;
      }
      
      const data = await response.json();
      
      // Сохраняем аккаунт
      await chrome.storage.sync.set({ account: { id: data.user_id, username, email } });
      
      // Сохраняем API ключ
      await chrome.storage.sync.set({ apiKey });
      
      // Автоматически входим
      const loginResponse = await fetchWithTimeout(`${apiBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      }, 10000);
      
      if (loginResponse.ok) {
        const loginData = await loginResponse.json();
        await chrome.storage.sync.set({ account: loginData.account });
        showAccountInfo(loginData.account);
        updateHoverScanState();
        alert('✅ Аккаунт создан и привязан!');
      }
      
    } catch (error) {
      alert(`Ошибка: ${error.message}`);
      el.registerBtn.textContent = 'Зарегистрироваться';
      el.registerBtn.disabled = false;
    }
  }
  
  async function handleForgotPassword() {
    const email = el.forgotEmail.value.trim();
    const apiBase = normalizeApiBase(el.apiBase.value);
    
    if (!email) {
      alert('Введите email');
      return;
    }
    
    if (!apiBase) {
      alert('Укажите API Base URL');
      return;
    }
    
    try {
      el.forgotBtn.textContent = 'Отправляем...';
      el.forgotBtn.disabled = true;
      
      const response = await fetchWithTimeout(`${apiBase}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      }, 10000);
      
      if (!response.ok) {
        const error = await response.json();
        alert(`Ошибка: ${error.detail}`);
        el.forgotBtn.textContent = 'Отправить код';
        el.forgotBtn.disabled = false;
        return;
      }
      
      const data = await response.json();
      
      // Показываем код для разработки
      if (data.debug_code) {
        alert(`Код восстановления: ${data.debug_code}\n\n(В продакшене код придет на email)`);
      }
      
      el.resetCodeSection.style.display = 'block';
      el.forgotBtn.textContent = 'Код отправлен';
      
    } catch (error) {
      alert(`Ошибка: ${error.message}`);
      el.forgotBtn.textContent = 'Отправить код';
      el.forgotBtn.disabled = false;
    }
  }
  
  async function handleResetPassword() {
    const email = el.forgotEmail.value.trim();
    const code = el.resetCode.value.trim();
    const newPassword = el.newPassword.value.trim();
    const apiBase = normalizeApiBase(el.apiBase.value);
    
    if (!email || !code || !newPassword) {
      alert('Заполните все поля');
      return;
    }
    
    if (newPassword.length < 6) {
      alert('Пароль должен содержать минимум 6 символов');
      return;
    }
    
    try {
      el.resetBtn.textContent = 'Сбрасываем...';
      el.resetBtn.disabled = true;
      
      const response = await fetchWithTimeout(`${apiBase}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code, new_password: newPassword })
      }, 10000);
      
      if (!response.ok) {
        const error = await response.json();
        alert(`Ошибка: ${error.detail}`);
        el.resetBtn.textContent = 'Сбросить пароль';
        el.resetBtn.disabled = false;
        return;
      }
      
      alert('✅ Пароль успешно изменен! Теперь войдите в аккаунт.');
      showLoginForm();
      
    } catch (error) {
      alert(`Ошибка: ${error.message}`);
      el.resetBtn.textContent = 'Сбросить пароль';
      el.resetBtn.disabled = false;
    }
  }

  function handleLogout() {
    chrome.storage.sync.remove(['account', 'apiKey'], () => {
      showLoginForm();
      updateHoverScanState();
    });
  }

  el.save.addEventListener('click', save);
  el.reset.addEventListener('click', (e) => { e.preventDefault(); reset(); });
  
  // Account event listeners
  el.showLoginBtn.addEventListener('click', showLoginForm);
  el.showRegisterBtn.addEventListener('click', showRegisterForm);
  el.forgotPasswordBtn.addEventListener('click', showForgotForm);
  el.backToLoginBtn.addEventListener('click', showLoginForm);
  el.loginBtn.addEventListener('click', handleLogin);
  el.registerBtn.addEventListener('click', handleRegister);
  el.forgotBtn.addEventListener('click', handleForgotPassword);
  el.resetBtn.addEventListener('click', handleResetPassword);
  el.logoutBtn.addEventListener('click', handleLogout);
  
  // Initialize
  document.addEventListener('DOMContentLoaded', load);
  document.addEventListener('DOMContentLoaded', loadAccount);
})();



