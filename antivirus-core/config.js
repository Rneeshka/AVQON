// config.js - КОНФИГ ДЛЯ ВСЕГО РАСШИРЕНИЯ

// ===== ПЕРЕКЛЮЧАТЕЛЬ СРЕДЫ =====
const ENV = 'DEV';
// ===============================

// Конфигурация для DEV и PROD
const CONFIG = {
  DEV: {
    API_BASE: 'https://api-dev.aegis.builders',
    WS_URL: 'wss://api-dev.aegis.builders/ws'
  },
  PROD: {
    API_BASE: 'https://api.aegis.builders',
    WS_URL: 'wss://api.aegis.builders/ws'
  }
};

const CURRENT_CONFIG = CONFIG[ENV];

// Делаем доступным глобально (для фонового скрипта и content scripts)
if (typeof window !== 'undefined') {
  window.AEGIS_CONFIG = CURRENT_CONFIG;
}

// Для Service Worker (background.js)
if (typeof self !== 'undefined') {
  self.AEGIS_CONFIG = CURRENT_CONFIG;
}

// Экспорт для ES6 модулей (если используется)
export default CURRENT_CONFIG;