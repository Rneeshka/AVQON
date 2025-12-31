// ===== Configuration =====
<<<<<<< HEAD
// Автоматическое определение окружения по hostname
function getApiBaseUrl() {
    const hostname = window.location.hostname;
    
    // DEV окружение
    if (hostname.includes('devsite.aegis.builders') || hostname === 'www.devsite.aegis.builders') {
        return 'https://api-dev.aegis.builders';
    }
    
    // PROD окружение
    if (hostname.includes('aegis.builders') && !hostname.includes('devsite')) {
        return 'https://api.aegis.builders';
    }
    
    // Локальная разработка (localhost)
    return 'http://localhost:8000';
}

const API_BASE_URL = getApiBaseUrl();
const PAYMENT_ENDPOINT = `${API_BASE_URL}/payments/create`;
const CHECK_URL_ENDPOINT = `${API_BASE_URL}/check/url`;

console.log(`[CONFIG] Environment detected: ${window.location.hostname}`);
console.log(`[CONFIG] API Base URL: ${API_BASE_URL}`);

// ===== API Health Check =====
async function checkApiHealth() {
    try {
        const abortController = new AbortController();
        const timeoutId = setTimeout(() => abortController.abort(), 3000); // 3 секунды для проверки
        try {
            const response = await fetch(`${API_BASE_URL}/health`, {
                method: 'GET',
                signal: abortController.signal
            });
            clearTimeout(timeoutId);
            return response.ok;
        } catch (fetchError) {
            clearTimeout(timeoutId);
            return false;
        }
    } catch (error) {
        console.warn('[API] Health check failed:', error.message);
        return false;
    }
}
=======
const API_BASE_URL = 'http://localhost:8000'; // Измените на ваш URL API
const PAYMENT_ENDPOINT = `${API_BASE_URL}/payments/create`;
const CHECK_URL_ENDPOINT = `${API_BASE_URL}/check/url`;
>>>>>>> 4264469 (WIP Wed Dec 31 12:44:59 MSK 2025)

// ===== Navigation =====
document.addEventListener('DOMContentLoaded', async function() {
    // Проверяем доступность API при загрузке страницы
    if (API_BASE_URL.includes('localhost') || API_BASE_URL.includes('127.0.0.1')) {
        const isApiAvailable = await checkApiHealth();
        if (!isApiAvailable) {
            console.warn('[API] Backend server is not available. Payment functionality will not work.');
            // Можно показать предупреждение пользователю, но не блокируем загрузку страницы
        } else {
            console.log('[API] Backend server is available');
        }
    }
    // Mobile menu toggle
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');
    
    if (navToggle) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
        });
    }

    // Smooth scroll for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
                // Close mobile menu if open
                navMenu.classList.remove('active');
            }
        });
    });

    // Navbar background on scroll
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            navbar.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.1)';
        } else {
            navbar.style.boxShadow = 'none';
        }
    });

    // Close modal on outside click
    const modal = document.getElementById('paymentModal');
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closePaymentModal();
            }
        });
    }

    // Close modal on X button
    const closeBtn = document.querySelector('.modal-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', closePaymentModal);
    }

    // Close modal on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closePaymentModal();
        }
    });
});

// ===== Payment Functions =====
let currentLicenseType = null;
let currentAmount = null;

async function initiatePayment(licenseType, amount) {
    // Сохраняем параметры для использования после ввода email
    currentLicenseType = licenseType;
    currentAmount = amount;
    
    // Show modal
    const modal = document.getElementById('paymentModal');
    if (modal) {
        modal.classList.add('show');
        showPaymentForm();
<<<<<<< HEAD
    }
}

async function processPayment() {
    const emailInput = document.getElementById('userEmail');
    const email = emailInput.value.trim();
    
    // Валидация email
    if (!email || !validateEmail(email)) {
        showPaymentError('Пожалуйста, введите корректный email адрес');
        return;
    }
    
    // Скрываем форму и показываем статус загрузки
    showPaymentStatus();
    
    try {
        // Проверяем доступность API перед запросом
        console.log(`[PAYMENT] Creating payment request to: ${PAYMENT_ENDPOINT}`);
        console.log(`[PAYMENT] Request data:`, {
            amount: currentAmount,
            license_type: currentLicenseType,
            email: email
        });
        
        // Create payment request with timeout using AbortController for browser compatibility
        const abortController = new AbortController();
        const timeoutId = setTimeout(() => abortController.abort(), 30000); // 30 секунд
        
        let response;
        try {
            response = await fetch(PAYMENT_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    amount: currentAmount,
                    license_type: currentLicenseType,
                    email: email,
                    username: email.split('@')[0] // Используем часть email как username
                }),
                signal: abortController.signal
            });
        } catch (fetchError) {
            clearTimeout(timeoutId);
            if (fetchError.name === 'AbortError') {
                showPaymentError('Превышено время ожидания ответа от сервера. Попробуйте еще раз.');
                return;
            }
            throw fetchError;
        }
        
        clearTimeout(timeoutId);

        console.log(`[PAYMENT] Response status: ${response.status} ${response.statusText}`);

        if (!response.ok) {
            let errorData;
            try {
                errorData = await response.json();
            } catch (jsonError) {
                const text = await response.text();
                console.error('[PAYMENT] Failed to parse error response:', text);
                errorData = { detail: `HTTP ${response.status}: ${response.statusText}` };
            }
            
            const errorMessage = errorData.detail || errorData.message || `Ошибка ${response.status}`;
            console.error('[PAYMENT] API error:', errorMessage);
            throw new Error(errorMessage);
        }

        const paymentData = await response.json();
        console.log('[PAYMENT] Payment created:', paymentData);
        
        if (!paymentData.confirmation_url) {
            console.error('[PAYMENT] Missing confirmation_url in response:', paymentData);
            throw new Error('Не получен URL для оплаты. Обратитесь в поддержку.');
        }
        
        if (!paymentData.payment_id) {
            console.error('[PAYMENT] Missing payment_id in response:', paymentData);
            throw new Error('Не получен ID платежа. Обратитесь в поддержку.');
        }
        
        // КРИТИЧНО: Сохраняем payment_id от бэкенда (это правильный ID, который сохранен в БД)
        // ЮKassa может вернуть другой payment_id в redirect URL, поэтому используем только наш
        console.log('[PAYMENT] Saving payment_id from backend:', paymentData.payment_id);
        console.log('[PAYMENT] This is the payment_id that backend saved to database');
        
        // Сохраняем в sessionStorage (основной источник)
        sessionStorage.setItem('last_payment_id', paymentData.payment_id);
        
        // Также сохраняем в localStorage как резерв (на случай, если sessionStorage потеряется)
        localStorage.setItem('last_payment_id_backup', paymentData.payment_id);
        
        // Сохраняем email для использования на странице успешной оплаты
        sessionStorage.setItem('payment_email', email);
        
        // Show success message
        showPaymentSuccess();
        
        // Redirect to payment page immediately
        window.location.href = paymentData.confirmation_url;
        
    } catch (error) {
        console.error('[PAYMENT] Payment error:', error);
        
        let errorMessage = 'Не удалось создать платеж. Попробуйте позже.';
        
        // Детальная обработка ошибок
        if (error.name === 'AbortError' || error.name === 'TimeoutError') {
            errorMessage = 'Превышено время ожидания. Проверьте интернет-соединение и попробуйте снова.';
        } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            // Проверяем, это ли ошибка подключения к localhost
            if (API_BASE_URL.includes('localhost') || API_BASE_URL.includes('127.0.0.1')) {
                errorMessage = 'Не удалось подключиться к серверу API. Убедитесь, что backend запущен на порту 8000.\n\n' +
                              'Для запуска backend выполните:\n' +
                              'cd antivirus-core\n' +
                              'uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload\n\n' +
                              'Или обратитесь в поддержку: aegisshieldos@gmail.com';
            } else {
                errorMessage = 'Не удалось подключиться к серверу. Проверьте интернет-соединение. Если проблема сохраняется, обратитесь в поддержку: aegisshieldos@gmail.com';
            }
        } else if (error.message.includes('ERR_CONNECTION_REFUSED') || error.message.includes('Connection refused')) {
            errorMessage = 'Сервер API недоступен!\n\n' +
                          'Backend не запущен или недоступен на ' + API_BASE_URL + '\n\n' +
                          'Для запуска backend:\n' +
                          '1. Откройте терминал\n' +
                          '2. Перейдите в папку: cd antivirus-core\n' +
                          '3. Запустите: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload\n\n' +
                          'Или обратитесь в поддержку: aegisshieldos@gmail.com';
        } else if (error.message.includes('CORS') || error.message.includes('CORS policy')) {
            errorMessage = 'Ошибка доступа к серверу. Обратитесь в поддержку: aegisshieldos@gmail.com';
        } else if (error.message) {
            errorMessage = error.message;
        }
        
        showPaymentError(errorMessage);
    }
}

=======
    }
}

async function processPayment() {
    const emailInput = document.getElementById('userEmail');
    const email = emailInput.value.trim();
    
    // Валидация email
    if (!email || !validateEmail(email)) {
        showPaymentError('Пожалуйста, введите корректный email адрес');
        return;
    }
    
    // Скрываем форму и показываем статус загрузки
    showPaymentStatus();
    
    try {
        // Проверяем доступность API перед запросом
        console.log(`[PAYMENT] Creating payment request to: ${PAYMENT_ENDPOINT}`);
        console.log(`[PAYMENT] Request data:`, {
            amount: currentAmount,
            license_type: currentLicenseType,
            email: email
        });
        
        // Create payment request
        const response = await fetch(PAYMENT_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                amount: currentAmount,
                license_type: currentLicenseType,
                email: email,
                username: email.split('@')[0] // Используем часть email как username
            }),
            // Добавляем timeout через AbortController
            signal: AbortSignal.timeout(30000) // 30 секунд
        });

        console.log(`[PAYMENT] Response status: ${response.status} ${response.statusText}`);

        if (!response.ok) {
            let errorData;
            try {
                errorData = await response.json();
            } catch (jsonError) {
                const text = await response.text();
                console.error('[PAYMENT] Failed to parse error response:', text);
                errorData = { detail: `HTTP ${response.status}: ${response.statusText}` };
            }
            
            const errorMessage = errorData.detail || errorData.message || `Ошибка ${response.status}`;
            console.error('[PAYMENT] API error:', errorMessage);
            throw new Error(errorMessage);
        }

        const paymentData = await response.json();
        console.log('[PAYMENT] Payment created:', paymentData);
        
        if (!paymentData.confirmation_url) {
            console.error('[PAYMENT] Missing confirmation_url in response:', paymentData);
            throw new Error('Не получен URL для оплаты. Обратитесь в поддержку.');
        }
        
        if (!paymentData.payment_id) {
            console.error('[PAYMENT] Missing payment_id in response:', paymentData);
            throw new Error('Не получен ID платежа. Обратитесь в поддержку.');
        }
        
        // Сохраняем payment_id для проверки после возврата
        sessionStorage.setItem('last_payment_id', paymentData.payment_id);
        
        // Сохраняем email для использования на странице успешной оплаты
        sessionStorage.setItem('payment_email', email);
        
        // Show success message
        showPaymentSuccess();
        
        // Redirect to payment page immediately
        window.location.href = paymentData.confirmation_url;
        
    } catch (error) {
        console.error('[PAYMENT] Payment error:', error);
        
        let errorMessage = 'Не удалось создать платеж. Попробуйте позже.';
        
        // Детальная обработка ошибок
        if (error.name === 'AbortError' || error.name === 'TimeoutError') {
            errorMessage = 'Превышено время ожидания. Проверьте интернет-соединение и попробуйте снова.';
        } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            errorMessage = 'Не удалось подключиться к серверу. Проверьте интернет-соединение. Если проблема сохраняется, обратитесь в поддержку: aegisshieldos@gmail.com';
        } else if (error.message.includes('CORS') || error.message.includes('CORS policy')) {
            errorMessage = 'Ошибка доступа к серверу. Обратитесь в поддержку: aegisshieldos@gmail.com';
        } else if (error.message) {
            errorMessage = error.message;
        }
        
        showPaymentError(errorMessage);
    }
}

>>>>>>> 4264469 (WIP Wed Dec 31 12:44:59 MSK 2025)
function showPaymentForm() {
    const form = document.getElementById('paymentForm');
    const status = document.getElementById('paymentStatus');
    const success = document.getElementById('paymentSuccess');
    const error = document.getElementById('paymentError');
    
    if (form) form.style.display = 'block';
    if (status) status.style.display = 'none';
    if (success) success.style.display = 'none';
    if (error) error.style.display = 'none';
    
    // Очищаем поле email при открытии модального окна
    const emailInput = document.getElementById('userEmail');
    if (emailInput) emailInput.value = '';
}

function showPaymentStatus() {
    const form = document.getElementById('paymentForm');
    const status = document.getElementById('paymentStatus');
    const success = document.getElementById('paymentSuccess');
    const error = document.getElementById('paymentError');
    
    if (form) form.style.display = 'none';
    if (status) status.style.display = 'block';
    if (success) success.style.display = 'none';
    if (error) error.style.display = 'none';
}

function showPaymentSuccess() {
    document.getElementById('paymentStatus').style.display = 'none';
    document.getElementById('paymentSuccess').style.display = 'block';
    document.getElementById('paymentError').style.display = 'none';
}

function showPaymentError(message) {
    const form = document.getElementById('paymentForm');
    const status = document.getElementById('paymentStatus');
    const success = document.getElementById('paymentSuccess');
    const error = document.getElementById('paymentError');
    
    if (form) form.style.display = 'none';
    if (status) status.style.display = 'none';
    if (success) success.style.display = 'none';
    if (error) error.style.display = 'block';
    
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        errorMessage.textContent = message;
    }
}

function closePaymentModal() {
    const modal = document.getElementById('paymentModal');
    if (modal) {
        modal.classList.remove('show');
        // Возвращаем форму при закрытии
        showPaymentForm();
    }
}

// ===== Helper Functions =====
// Обработка Enter в поле email
document.addEventListener('DOMContentLoaded', function() {
    const emailInput = document.getElementById('userEmail');
    if (emailInput) {
        emailInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                processPayment();
            }
        });
    }
});

// ===== Intersection Observer for Animations =====
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver(function(entries) {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observe feature cards and pricing cards
document.addEventListener('DOMContentLoaded', function() {
    const cards = document.querySelectorAll('.feature-card, .pricing-card');
    cards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.transition = 'opacity 0.6s ease-out, transform 0.6s ease-out';
        observer.observe(card);
    });
});

// ===== Form Validation (if needed in future) =====
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// ===== Error Handling =====
window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
});

// ===== Demo Link Hover Analysis =====
let demoAnalysisCache = {}; // Кэш для результатов анализа
let cursorTooltip = null; // Элемент индикатора около курсора

// Палитра цветов как в расширении
const hoverPalette = {
    safe: '#10B981',
    suspicious: '#F59E0B',
    malicious: '#EF4444',
    unknown: '#94A3B8',
    info: '#2563EB'
};

// Создаем tooltip точно как в расширении
function createCursorTooltip() {
    if (!cursorTooltip) {
        cursorTooltip = document.createElement('div');
        cursorTooltip.id = 'cursor-tooltip';
        cursorTooltip.className = 'aegis-hover-tooltip';
        document.body.appendChild(cursorTooltip);
    }
    return cursorTooltip;
}

function showCursorTooltip(event, text, type) {
    const tooltip = createCursorTooltip();
    
    // Форматируем текст как в расширении
    tooltip.innerHTML = `
        <div style="text-align: center; line-height: 1.2;">
            <div style="color: ${hoverPalette[type] || hoverPalette.unknown}; font-weight: bold; font-size: 14px;">
                ${text}
            </div>
        </div>
    `;
    
    // Устанавливаем атрибут variant для стилей
    tooltip.setAttribute('data-variant', type);
    
    // Устанавливаем border и shadow в зависимости от типа
    if (type === 'safe') {
        tooltip.style.borderColor = 'rgba(16,185,129,0.4)';
        tooltip.style.boxShadow = '0 14px 32px rgba(16,185,129,0.2)';
    } else if (type === 'malicious' || type === 'dangerous') {
        tooltip.style.borderColor = 'rgba(239,68,68,0.5)';
        tooltip.style.boxShadow = '0 14px 32px rgba(239,68,68,0.25)';
    } else if (type === 'suspicious') {
        tooltip.style.borderColor = 'rgba(245,158,11,0.45)';
        tooltip.style.boxShadow = '0 14px 32px rgba(245,158,11,0.25)';
    } else {
        tooltip.style.borderColor = 'rgba(148,163,184,0.5)';
        tooltip.style.boxShadow = '0 14px 32px rgba(15,23,42,0.45)';
    }
    
    // Позиционируем около курсора (как в расширении: x+10, y-30)
    tooltip.style.left = (event.clientX + 10) + 'px';
    tooltip.style.top = (event.clientY - 30) + 'px';
    tooltip.style.opacity = '1';
}

function hideCursorTooltip() {
    if (cursorTooltip) {
        cursorTooltip.style.opacity = '0';
    }
}

async function analyzeUrl(url) {
    // Проверяем кэш
    if (demoAnalysisCache[url]) {
        return demoAnalysisCache[url];
    }

    // Для демо используем предопределенные результаты
    // В реальном приложении здесь был бы запрос к API
    let result = null;
    
    if (url.includes('google.com')) {
        result = { safe: true, source: 'demo' };
    } else if (url.includes('testsafebrowsing')) {
        result = { safe: false, source: 'demo' };
    }
    
    if (result) {
        demoAnalysisCache[url] = result;
        return result;
    }
    
    return null;
}

function determineVerdict(result) {
    if (!result) return 'unknown';
    
    if (result.safe === false) return 'malicious';
    if (result.safe === true) return 'safe';
    if (result.threat_type && result.threat_type.trim()) return 'malicious';
    if (result.source === 'error') {
        const msg = String(result.details || '').toLowerCase();
        if (msg.includes('failed to fetch') || msg.includes('network') || msg.includes('timeout')) {
            return 'suspicious';
        }
        return 'unknown';
    }
    
    return 'unknown';
}

function showLinkIndicator(linkElement, result, event) {
    const verdict = determineVerdict(result);
    
    // Форматируем текст как в расширении
    let text = 'Неизвестно';
    let type = 'unknown';
    
    if (verdict === 'safe' || verdict === 'clean') {
        text = 'Безопасно';
        type = 'safe';
    } else if (verdict === 'malicious' || verdict === 'dangerous') {
        text = 'Опасно';
        type = 'malicious';
    } else if (verdict === 'suspicious') {
        text = 'Опасно';
        type = 'suspicious';
    } else {
        text = 'Неизвестно';
        type = 'unknown';
    }
    
    showCursorTooltip(event, text, type);
}

function hideLinkIndicator() {
    hideCursorTooltip();
}

// Инициализация анализа по наведению для демо-ссылок
document.addEventListener('DOMContentLoaded', function() {
    const demoLinks = document.querySelectorAll('.demo-link[data-url]');
    const warningDiv = document.getElementById('demo-subscription-warning');
    
    // Скрываем предупреждение о подписке - демо доступно всем
    if (warningDiv) {
        warningDiv.style.display = 'none';
    }

    demoLinks.forEach(link => {
        const url = link.getAttribute('data-url');
        let analysisTimeout = null;
        
        link.addEventListener('mouseenter', async function(event) {
            // Небольшая задержка для реалистичности (как в расширении - 200ms)
            analysisTimeout = setTimeout(async () => {
                // Анализируем URL
                const result = await analyzeUrl(url);
                if (result) {
                    showLinkIndicator(link, result, event);
                } else {
                    showCursorTooltip(event, 'Неизвестно', 'unknown');
                }
            }, 200);
        });

        link.addEventListener('mousemove', function(event) {
            // Обновляем позицию tooltip при движении курсора (как в расширении: x+10, y-30)
            if (cursorTooltip && parseFloat(cursorTooltip.style.opacity) > 0) {
                cursorTooltip.style.left = (event.clientX + 10) + 'px';
                cursorTooltip.style.top = (event.clientY - 30) + 'px';
            }
        });

        link.addEventListener('mouseleave', function() {
            if (analysisTimeout) {
                clearTimeout(analysisTimeout);
            }
            hideLinkIndicator();
        });
    });
    
    // Скрываем tooltip при движении курсора вне ссылок
    document.addEventListener('mousemove', function(event) {
        const isOverLink = event.target.closest('.demo-link');
        if (!isOverLink && cursorTooltip) {
            hideCursorTooltip();
        }
    });
});

// Сохранение API ключа после успешной оплаты
function saveApiKey(apiKey) {
    localStorage.setItem('aegis_api_key', apiKey);
    // Скрываем предупреждение если оно было показано
    const warningDiv = document.getElementById('demo-subscription-warning');
    if (warningDiv) {
        warningDiv.style.display = 'none';
    }
}
