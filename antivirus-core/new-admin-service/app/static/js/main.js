// Основной JavaScript для админ-панели

// Удаление flash сообщений через 5 секунд
document.addEventListener('DOMContentLoaded', function() {
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(function(msg) {
        setTimeout(function() {
            msg.style.transition = 'opacity 0.5s';
            msg.style.opacity = '0';
            setTimeout(function() {
                msg.remove();
            }, 500);
        }, 5000);
    });
});

// Подтверждение опасных действий
document.addEventListener('DOMContentLoaded', function() {
    const dangerButtons = document.querySelectorAll('button[data-danger]');
    dangerButtons.forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            if (!confirm('Вы уверены? Это действие необратимо!')) {
                e.preventDefault();
            }
        });
    });
});

