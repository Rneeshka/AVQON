# app/auth.py
"""
Модуль аутентификации и управления аккаунтами
"""
import hashlib
import secrets
import logging
import smtplib  # Для отправки почты
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional, Tuple
from fastapi import HTTPException, status
from .database import db_manager
import ssl

logger = logging.getLogger(__name__)

import os

# Настройки SMTP из env.env
SMTP_SERVER = os.getenv("SMTP_HOST", "smtp.mail.ru")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASS", "")

class AuthManager:
    """Менеджер аутентификации и управления аккаунтами."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Хеширует пароль с использованием SHA-256 и соли."""
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{password_hash}"
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Проверяет пароль против хеша."""
        try:
            salt, stored_hash = password_hash.split(":")
            password_hash_check = hashlib.sha256((password + salt).encode()).hexdigest()
            return password_hash_check == stored_hash
        except ValueError:
            return False
            
    # ... (методы register и login остаются без изменений, см. ниже новые методы) ...

    @staticmethod
    def register(username: str, email: str, password: str, api_key: Optional[str] = None) -> Tuple[bool, Optional[int], Optional[str]]:
        """Регистрирует нового пользователя."""
        if not username or len(username) < 3:
            return False, None, "Username должен содержать минимум 3 символа"
        if not email or "@" not in email:
            return False, None, "Неверный email"
        if not password or len(password) < 6:
            return False, None, "Пароль должен содержать минимум 6 символов"
        
        if db_manager.get_account_by_username(username):
            return False, None, "Username уже занят"
        if db_manager.get_account_by_email(email):
            return False, None, "Email уже зарегистрирован"
        
        password_hash = AuthManager.hash_password(password)
        user_id = db_manager.create_account(username, email, password_hash)
        
        if not user_id:
            return False, None, "Ошибка создания аккаунта"
        
        if api_key:
            if not db_manager.bind_api_key_to_account(api_key, user_id):
                return False, None, "API ключ не найден или уже привязан"
        
        logger.info(f"Account created: username={username}, user_id={user_id}")
        return True, user_id, None
    
    @staticmethod
    def login(username: str, password: str, device_id: str = None) -> Tuple[bool, Optional[dict], Optional[str], Optional[str]]:
        """Авторизует пользователя."""
        if not username or not password:
            return False, None, None, "Username и password обязательны"
        
        account = db_manager.get_account_by_username(username)
        if not account:
            account = db_manager.get_account_by_email(username)
        
        if not account or not account["is_active"]:
            return False, None, None, "Неверный логин или аккаунт деактивирован"
        
        if not AuthManager.verify_password(password, account["password_hash"]):
            return False, None, None, "Неверный username или пароль"
        
        if not device_id:
            device_id = secrets.token_hex(16)
        
        session_token = secrets.token_urlsafe(32)
        
        if not db_manager.set_active_session(account["id"], session_token, device_id, expires_hours=720):
            logger.error(f"Failed to set active session for user_id={account['id']}")
            return False, None, None, "Ошибка создания сессии"
        
        db_manager.update_last_login(account["id"])
        
        account_data = {
            "id": account["id"],
            "username": account["username"],
            "email": account["email"],
            "created_at": account["created_at"],
            "last_login": account["last_login"]
        }
        
        logger.info(f"User logged in: username={username}, user_id={account['id']}")
        return True, account_data, session_token, None

    # ... (get_user_from_api_key остается без изменений) ...
    @staticmethod
    def get_user_from_api_key(api_key: str) -> Optional[dict]:
        try:
            key_info = db_manager.get_api_key_info(api_key)
            if not key_info or not key_info.get("user_id"):
                return None
            account = db_manager.get_account_by_id(key_info["user_id"])
            return account
        except Exception as e:
            logger.error(f"Get user from API key error: {e}")
            return None

auth_manager = AuthManager()