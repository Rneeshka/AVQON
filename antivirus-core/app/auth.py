# app/auth.py
"""
Модуль аутентификации и управления аккаунтами
"""
import hashlib
import secrets
import logging
from typing import Optional, Tuple
from fastapi import HTTPException, status
from .database import db_manager

logger = logging.getLogger(__name__)

class AuthManager:
    """Менеджер аутентификации и управления аккаунтами."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Хеширует пароль с использованием SHA-256 и соли.
        
        Args:
            password (str): Исходный пароль
            
        Returns:
            str: Хешированный пароль с солью (формат: salt:hash)
        """
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{password_hash}"
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Проверяет пароль против хеша.
        
        Args:
            password (str): Исходный пароль для проверки
            password_hash (str): Хешированный пароль (формат: salt:hash)
            
        Returns:
            bool: True если пароль верный, иначе False
        """
        try:
            salt, stored_hash = password_hash.split(":")
            password_hash_check = hashlib.sha256((password + salt).encode()).hexdigest()
            return password_hash_check == stored_hash
        except ValueError:
            return False
    
    @staticmethod
    def register(username: str, email: str, password: str, api_key: Optional[str] = None) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Регистрирует нового пользователя и привязывает API ключ.
        
        Args:
            username (str): Имя пользователя
            email (str): Email пользователя
            password (str): Пароль
            api_key (str, optional): API ключ для привязки
            
        Returns:
            Tuple[bool, Optional[int], Optional[str]]: (success, user_id, error_message)
        """
        # Валидация входных данных
        if not username or len(username) < 3:
            return False, None, "Username должен содержать минимум 3 символа"
        
        if not email or "@" not in email:
            return False, None, "Неверный email"
        
        if not password or len(password) < 6:
            return False, None, "Пароль должен содержать минимум 6 символов"
        
        # Проверка уникальности
        if db_manager.get_account_by_username(username):
            return False, None, "Username уже занят"
        
        if db_manager.get_account_by_email(email):
            return False, None, "Email уже зарегистрирован"
        
        # Хешируем пароль
        password_hash = AuthManager.hash_password(password)
        
        # Создаем аккаунт
        user_id = db_manager.create_account(username, email, password_hash)
        
        if not user_id:
            return False, None, "Ошибка создания аккаунта"
        
        # Привязываем ключ, если указан
        if api_key:
            if not db_manager.bind_api_key_to_account(api_key, user_id):
                # Если не удалось привязать ключ, возвращаем ошибку
                # В продакшене можно удалить аккаунт или просто предупредить
                return False, None, "API ключ не найден или уже привязан"
        
        logger.info(f"Account created: username={username}, user_id={user_id}")
        return True, user_id, None
    
    @staticmethod
    def login(username: str, password: str, device_id: str = None) -> Tuple[bool, Optional[dict], Optional[str], Optional[str]]:
        """
        Авторизует пользователя.
        КРИТИЧНО: При входе на новом устройстве старая сессия автоматически удаляется.
        Старое устройство автоматически выйдет из аккаунта.
        
        Args:
            username (str): Имя пользователя или email
            password (str): Пароль
            device_id (str, optional): Уникальный идентификатор устройства
            
        Returns:
            Tuple[bool, Optional[dict], Optional[str], Optional[str]]: 
            (success, account_data, session_token, error_message)
        """
        if not username or not password:
            return False, None, None, "Username и password обязательны"
        
        # Ищем аккаунт по username или email
        account = db_manager.get_account_by_username(username)
        if not account:
            account = db_manager.get_account_by_email(username)
        
        if not account:
            return False, None, None, "Неверный username или пароль"
        
        if not account["is_active"]:
            return False, None, None, "Аккаунт деактивирован"
        
        # Проверяем пароль
        if not AuthManager.verify_password(password, account["password_hash"]):
            return False, None, None, "Неверный username или пароль"
        
        # Генерируем device_id если не передан
        if not device_id:
            import secrets
            device_id = secrets.token_hex(16)
        
        # Проверяем существующую сессию для этого device_id
        existing_session = db_manager.get_session_by_device_id(account["id"], device_id)
        
        if existing_session and existing_session.get("session_token"):
            # Если сессия существует для этого device_id - используем её и обновляем срок действия
            session_token = existing_session["session_token"]
            # Обновляем срок действия существующей сессии
            db_manager.set_active_session(account["id"], session_token, device_id, expires_hours=720)
            logger.info(f"Reusing existing session for user_id={account['id']}, device_id={device_id}")
        else:
            # Генерируем новый session_token только если нет существующей сессии для этого device_id
            import secrets
            session_token = secrets.token_urlsafe(32)
            
            # Устанавливаем новую сессию только если это новое устройство
            # Если device_id совпадает - обновляем существующую сессию
            if not db_manager.set_active_session(account["id"], session_token, device_id, expires_hours=720):
                logger.error(f"Failed to set active session for user_id={account['id']}")
                return False, None, None, "Ошибка создания сессии"
        
        # Обновляем время последнего входа
        db_manager.update_last_login(account["id"])
        
        # Убираем пароль из ответа
        account_data = {
            "id": account["id"],
            "username": account["username"],
            "email": account["email"],
            "created_at": account["created_at"],
            "last_login": account["last_login"]
        }
        
        logger.info(f"User logged in: username={username}, user_id={account['id']}, device_id={device_id}")
        return True, account_data, session_token, None
    
    @staticmethod
    def get_user_from_api_key(api_key: str) -> Optional[dict]:
        """
        Возвращает информацию о пользователе по API ключу.
        
        Args:
            api_key (str): API ключ
            
        Returns:
            Optional[dict]: Данные пользователя или None
        """
        try:
            key_info = db_manager.get_api_key_info(api_key)
            if not key_info or not key_info.get("user_id"):
                return None
            
            account = db_manager.get_account_by_id(key_info["user_id"])
            return account
        except Exception as e:
            logger.error(f"Get user from API key error: {e}")
            return None

# Глобальный экземпляр менеджера аутентификации
auth_manager = AuthManager()
