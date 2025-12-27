// ===== Configuration =====
const API_BASE_URL = window.AEGIS_CONFIG.API_BASE_URL;
const PAYMENT_ENDPOINT = `${API_BASE_URL}/payments/create`;

// ===== Navigation =====
document.addEventListener('DOMContentLoaded', function() {
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
async function initiatePayment(licenseType, amount) {
    // Show modal
    const modal = document.getElementById('paymentModal');
    if (modal) {
        modal.classList.add('show');
        showPaymentStatus();
    }

    // Get user info (for demo, using placeholder values)
    // In production, you would get this from user authentication
    const userInfo = {
        telegram_id: generateDemoUserId(), // Demo: random user ID
        username: 'web_user_' + Date.now(),
        amount: amount,
        license_type: licenseType
    };

    try {
        // Create payment request
        const response = await fetch(PAYMENT_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                amount: userInfo.amount,
                license_type: userInfo.license_type,
                telegram_id: userInfo.telegram_id,
                username: userInfo.username
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
            throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
        }

        const paymentData = await response.json();
        
        if (paymentData.confirmation_url) {
            // Сохраняем payment_id для проверки после возврата
            if (paymentData.payment_id) {
                sessionStorage.setItem('last_payment_id', paymentData.payment_id);
            }
            
            // Show success message
            showPaymentSuccess();
            
            // Redirect to payment page immediately
            window.location.href = paymentData.confirmation_url;
        } else {
            throw new Error('Payment confirmation URL not received');
        }
    } catch (error) {
        console.error('Payment error:', error);
        showPaymentError(error.message || 'Не удалось создать платеж. Попробуйте позже.');
    }
}

function showPaymentStatus() {
    document.getElementById('paymentStatus').style.display = 'block';
    document.getElementById('paymentSuccess').style.display = 'none';
    document.getElementById('paymentError').style.display = 'none';
}

function showPaymentSuccess() {
    document.getElementById('paymentStatus').style.display = 'none';
    document.getElementById('paymentSuccess').style.display = 'block';
    document.getElementById('paymentError').style.display = 'none';
}

function showPaymentError(message) {
    document.getElementById('paymentStatus').style.display = 'none';
    document.getElementById('paymentSuccess').style.display = 'none';
    document.getElementById('paymentError').style.display = 'block';
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        errorMessage.textContent = message;
    }
}

function closePaymentModal() {
    const modal = document.getElementById('paymentModal');
    if (modal) {
        modal.classList.remove('show');
    }
}

// ===== Helper Functions =====
function generateDemoUserId() {
    // Generate a demo user ID (in production, use actual user authentication)
    // For web users, you might want to use a different identifier
    return Math.floor(Math.random() * 1000000) + 100000;
}

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

