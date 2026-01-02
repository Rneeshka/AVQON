// config.js - ЕДИНЫЙ КОНФИГ ДЛЯ ВСЕГО РАСШИРЕНИЯ
// Этот файл используется всеми компонентами расширения: background.js, popup.js, options.js, sidepanel.html, popup.html

// ===== ПЕРЕКЛЮЧАТЕЛЬ СРЕДЫ =====
// МЕНЯЙ ЗДЕСЬ: 'DEV' или 'PROD'
// Для продакшена расширения всегда должно быть 'PROD'
const ENV = 'PROD'; // PROD для продакшена, DEV для разработки
// ===============================

// Конфигурация для DEV и PROD
const CONFIG = {
  DEV: {
    API_BASE: 'https://dev.avqon.com',
    WS_URL: 'wss://dev.avqon.com/ws',
    WEBSITE_URL: 'https://site-dev.avqon.com'
  },
  PROD: {
    API_BASE: 'https://prod.avqon.com',
    WS_URL: 'wss://prod.avqon.com/ws',
    WEBSITE_URL: 'https://avqon.com'
  }
};

// Экспортируем конфиг для текущего окружения
const CURRENT_CONFIG = CONFIG[ENV];

// Делаем доступным глобально (для фонового скрипта и content scripts)
if (typeof window !== 'undefined') {
  window.AVQON_CONFIG = CURRENT_CONFIG;
}

// Для Service Worker (background.js)
if (typeof self !== 'undefined') {
  self.AVQON_CONFIG = CURRENT_CONFIG;
}

// Для обратной совместимости (если где-то используется старая переменная)
if (typeof CURRENT_ENV === 'undefined') {
  // CURRENT_ENV больше не используется, используем CURRENT_CONFIG
}

// Экспорт для ES6 модулей (если используется)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CURRENT_CONFIG;
}

