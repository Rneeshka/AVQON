"""Фоновая задача для проверки сроков подписок и отправки напоминаний"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict
from aiogram import Bot
from database import Database
from config import DB_PATH, BOT_TOKEN, SUPPORT_TECH, INSTALLATION_LINK
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

logger = logging.getLogger(__name__)


class SubscriptionScheduler:
    """Класс для управления фоновыми задачами подписок"""
    
    def __init__(self, bot: Bot):
        self.bot = bot
        self.db = Database(DB_PATH)
        self.running = False
        self.task = None
    
    async def start(self):
        """Запустить фоновую задачу"""
        if self.running:
            logger.warning("SubscriptionScheduler уже запущен")
            return
        
        self.running = True
        self.task = asyncio.create_task(self._check_loop())
        logger.info("SubscriptionScheduler запущен")
    
    async def stop(self):
        """Остановить фоновую задачу"""
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("SubscriptionScheduler остановлен")
    
    async def _check_loop(self):
        """Основной цикл проверки подписок"""
        while self.running:
            try:
                await self._check_subscriptions()
                # Проверяем каждые 6 часов
                await asyncio.sleep(6 * 60 * 60)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Ошибка в цикле проверки подписок: {e}", exc_info=True)
                # При ошибке ждем 1 час перед следующей попыткой
                await asyncio.sleep(60 * 60)
    
    async def _check_subscriptions(self):
        """Проверка всех подписок и отправка напоминаний"""
        logger.info("Начинаю проверку подписок...")
        
        # Проверяем истекшие подписки
        await self._check_expired_subscriptions()
        
        # Проверяем подписки, которые скоро истекают
        await self._check_expiring_subscriptions(7)  # За 7 дней
        await self._check_expiring_subscriptions(3)  # За 3 дня
        await self._check_expiring_subscriptions(1)  # За 1 день
        
        # Проверяем автопродление
        await self._check_auto_renew()
        
        logger.info("Проверка подписок завершена")
    
    async def _check_expired_subscriptions(self):
        """Проверка истекших подписок"""
        expired = self.db.get_expired_subscriptions()
        
        for sub in expired:
            user_id = sub.get("user_id")
            expires_at_str = sub.get("expires_at")
            
            if not user_id:
                continue
            
            # Помечаем как истекшую
            self.db.expire_subscription(user_id)
            
            # Отправляем уведомление
            try:
                if expires_at_str:
                    if isinstance(expires_at_str, str):
                        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                    else:
                        expires_at = expires_at_str
                    expires_text = expires_at.strftime("%d.%m.%Y")
                else:
                    expires_text = "неизвестно"
                
                text = f"""❌ Ваша подписка истекла

Подписка закончилась {expires_text}.

Для продолжения использования продлите подписку."""
                
                keyboard = InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🔄 Продлить подписку", callback_data="renew_subscription")],
                    [InlineKeyboardButton(text="📅 Купить на месяц (150₽)", callback_data="buy_monthly")],
                    [InlineKeyboardButton(text="💬 Поддержка", url=f"https://t.me/{SUPPORT_TECH.replace('@', '')}")]
                ])
                
                await self.bot.send_message(user_id, text, reply_markup=keyboard)
                logger.info(f"Отправлено уведомление об истечении подписки пользователю {user_id}")
            except Exception as e:
                logger.error(f"Ошибка при отправке уведомления об истечении подписки пользователю {user_id}: {e}")
    
    async def _check_expiring_subscriptions(self, days: int):
        """Проверка подписок, которые истекают через указанное количество дней"""
        expiring = self.db.get_expiring_subscriptions(days)
        
        for sub in expiring:
            user_id = sub.get("user_id")
            expires_at_str = sub.get("expires_at")
            last_notified = sub.get("last_notified_days", None)
            
            # Проверяем, не отправляли ли уже уведомление для этого количества дней
            if last_notified == days:
                continue
            
            if not user_id:
                continue
            
            try:
                if expires_at_str:
                    if isinstance(expires_at_str, str):
                        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                    else:
                        expires_at = expires_at_str
                    expires_text = expires_at.strftime("%d.%m.%Y")
                else:
                    expires_text = "неизвестно"
                
                if days == 7:
                    text = f"""⚠️ Напоминание о подписке

Ваша подписка заканчивается через 7 дней ({expires_text}).

Не забудьте продлить подписку, чтобы не потерять доступ."""
                elif days == 3:
                    text = f"""⚠️ Подписка скоро истечет

Осталось 3 дня до окончания подписки ({expires_text}).

Продлите подписку сейчас, чтобы не потерять доступ."""
                elif days == 1:
                    text = f"""🚨 Последний день подписки!

Ваша подписка заканчивается завтра ({expires_text}).

Продлите подписку прямо сейчас!"""
                else:
                    text = f"Ваша подписка заканчивается через {days} дней ({expires_text})."
                
                keyboard = InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🔄 Продлить подписку", callback_data="renew_subscription")],
                    [InlineKeyboardButton(text="📊 Моя подписка", callback_data="my_subscription")],
                    [InlineKeyboardButton(text="🏠 В меню", callback_data="main_menu")]
                ])
                
                await self.bot.send_message(user_id, text, reply_markup=keyboard)
                logger.info(f"Отправлено напоминание за {days} дней пользователю {user_id}")
                
                # Сохраняем информацию о том, что уведомление отправлено
                # (можно добавить поле last_notified_days в таблицу subscriptions)
                
            except Exception as e:
                logger.error(f"Ошибка при отправке напоминания пользователю {user_id}: {e}")
    
    async def _check_auto_renew(self):
        """Проверка подписок с автопродлением"""
        auto_renew_subs = self.db.get_auto_renew_subscriptions()
        
        for sub in auto_renew_subs:
            user_id = sub.get("user_id")
            expires_at_str = sub.get("expires_at")
            
            if not user_id:
                continue
            
            try:
                if expires_at_str:
                    if isinstance(expires_at_str, str):
                        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                    else:
                        expires_at = expires_at_str
                    
                    now = datetime.now()
                    if expires_at.tzinfo:
                        now = now.replace(tzinfo=expires_at.tzinfo)
                    
                    # Если до окончания осталось 5 дней или меньше, создаем платеж для автопродления
                    days_left = (expires_at - now).days
                    
                    if 0 < days_left <= 5:
                        # Проверяем, нет ли уже pending платежа для продления
                        pending_payments = self.db.get_pending_payments_by_user(user_id)
                        has_renewal_payment = any(p.get("is_renewal", False) for p in pending_payments)
                        
                        if not has_renewal_payment:
                            # Создаем платеж для автопродления
                            logger.info(f"Создаю платеж для автопродления пользователю {user_id}")
                            # Здесь можно вызвать backend_create_payment для создания платежа
                            # Но это лучше делать через отдельную функцию
                            pass
                
            except Exception as e:
                logger.error(f"Ошибка при проверке автопродления для пользователя {user_id}: {e}")


# Глобальный экземпляр (будет инициализирован в bot.py)
scheduler: SubscriptionScheduler = None


async def start_scheduler(bot: Bot):
    """Запустить планировщик подписок"""
    global scheduler
    scheduler = SubscriptionScheduler(bot)
    await scheduler.start()


async def stop_scheduler():
    """Остановить планировщик подписок"""
    global scheduler
    if scheduler:
        await scheduler.stop()

