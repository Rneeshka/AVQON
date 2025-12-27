# app/auth.py
"""
Модуль аутентификации и управления аккаунтами с JWT
"""
import hashlib
import secrets
import logging
import smtplib  # Для отправки почты
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from fastapi import HTTPException, status
from .database import db_manager
from .jwt_auth import JWTAuth
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
    def register(username: str, email: str, password: str) -> Tuple[bool, Optional[int], Optional[str], Optional[Dict[str, str]]]:
        """
        Регистрирует нового пользователя и возвращает JWT токены.
        
        Returns:
            Tuple[bool, Optional[int], Optional[str], Optional[Dict[str, str]]]:
            (success, user_id, error_message, tokens_dict)
        """
        if not username or len(username) < 3:
            return False, None, "Username должен содержать минимум 3 символа", None
        if not email or "@" not in email:
            return False, None, "Неверный email", None
        if not password or len(password) < 6:
            return False, None, "Пароль должен содержать минимум 6 символов", None
        
        if not db_manager:
            return False, None, "Database unavailable", None
        
        if db_manager.get_account_by_username(username):
            return False, None, "Username уже занят", None
        if db_manager.get_account_by_email(email):
            return False, None, "Email уже зарегистрирован", None
        
        password_hash = AuthManager.hash_password(password)
        if not db_manager:
            return False, None, "Database unavailable", None
        
        user_id = db_manager.create_account(username, email, password_hash)
        
        if not user_id:
            return False, None, "Ошибка создания аккаунта", None
        
        # Создаём JWT токены
        token_data = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "access_level": "basic"  # По умолчанию базовый уровень
        }
        
        access_token = JWTAuth.create_access_token(token_data)
        refresh_token = JWTAuth.create_refresh_token(token_data)
        
        tokens = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
        
        logger.info(f"Account created with JWT: username={username}, user_id={user_id}")
        return True, user_id, None, tokens
    
    @staticmethod
    def login(username: str, password: str, device_id: str = None) -> Tuple[bool, Optional[dict], Optional[Dict[str, str]], Optional[str]]:
        """
        Авторизует пользователя и возвращает JWT токены.
        
        Returns:
            Tuple[bool, Optional[dict], Optional[Dict[str, str]], Optional[str]]:
            (success, account_data, tokens_dict, error_message)
        """
        if not username or not password:
            return False, None, None, "Username и password обязательны"
        
        if not db_manager:
            return False, None, "Database unavailable", None
        
        account = db_manager.get_account_by_username(username)
        if not account:
            account = db_manager.get_account_by_email(username)
        
        if not account or not account["is_active"]:
            return False, None, None, "Неверный логин или аккаунт деактивирован"
        
        if not AuthManager.verify_password(password, account["password_hash"]):
            return False, None, None, "Неверный username или пароль"
        
        if db_manager:
            db_manager.update_last_login(account["id"])
        
        account_data = {
            "id": account["id"],
            "username": account["username"],
            "email": account["email"],
            "created_at": account["created_at"],
            "last_login": account["last_login"]
        }
        
        # Создаём JWT токены (stateless - без сохранения в БД)
        token_data = {
            "user_id": account["id"],
            "username": account["username"],
            "email": account["email"],
            "access_level": "basic"  # Можно расширить для premium пользователей
        }
        
        access_token = JWTAuth.create_access_token(token_data)
        refresh_token = JWTAuth.create_refresh_token(token_data)
        
        tokens = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
        
        logger.info(f"User logged in with JWT: username={username}, user_id={account['id']}")
        return True, account_data, tokens, None

    @staticmethod
    def refresh_access_token(refresh_token: str) -> Optional[Dict[str, str]]:
        """
        Обновляет access token используя refresh token.
        
        Returns:
            Dict с новыми токенами или None если refresh token невалиден
        """
        payload = JWTAuth.verify_token(refresh_token, token_type="refresh")
        if not payload:
            return None
        
        user_id = payload.get("user_id") or payload.get("sub")
        if not user_id:
            return None
        
        # Получаем аккаунт из БД для актуальных данных
        if not db_manager:
            return None
        
        account = db_manager.get_account_by_id(user_id)
        if not account or not account["is_active"]:
            return None
        
        # Создаём новые токены
        token_data = {
            "user_id": account["id"],
            "username": account["username"],
            "email": account["email"],
            "access_level": "basic"
        }
        
        access_token = JWTAuth.create_access_token(token_data)
        refresh_token_new = JWTAuth.create_refresh_token(token_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token_new,
            "token_type": "bearer"
        }

    @staticmethod
    def _send_email(to_email: str, subject: str, body: str) -> bool:
        try:
            msg = MIMEMultipart()
            msg["From"] = SMTP_USER
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
            server.quit()

            return True
        
        except Exception as e:
            logger.error(f"SMTP ERROR: {e}", exc_info=True)
            return False

auth_manager = AuthManager()
