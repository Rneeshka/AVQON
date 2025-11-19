# app/validators.py
import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional
from app.config import security_config

class SecurityValidator:
    """Валидатор безопасности для входных данных"""
    
    @staticmethod
    def validate_url(url: str) -> Optional[str]:
        """Валидация и нормализация URL"""
        try:
            # Проверяем длину URL
            if len(url) > security_config.MAX_URL_LENGTH:
                return f"URL too long (max {security_config.MAX_URL_LENGTH} characters)"
            
            parsed = urlparse(url)
            
            if not parsed.scheme in ['http', 'https']:
                return "Invalid URL scheme (only http/https allowed)"
            
            if not parsed.netloc:
                return "Invalid domain"
            
            # Проверяем на подозрительные паттерны
            if '@' in url:
                return "URL contains '@' symbol (potentially malicious)"
            
            # Проверяем длину домена
            if len(parsed.netloc) > 253:
                return "Domain name too long"
            
            # Проверяем количество поддоменов
            subdomain_count = len(parsed.netloc.split('.'))
            if subdomain_count > 10:
                return "Too many subdomains"
            
            return None
            
        except Exception as e:
            return f"URL validation error: {str(e)}"
    
    @staticmethod
    def validate_file_hash(file_hash: str) -> Optional[str]:
        """Валидация хэша файла"""
        if not file_hash:
            return "File hash is required"
        
        if not re.match(r'^[a-fA-F0-9]{64}$', file_hash):
            return "Invalid SHA-256 hash format (must be 64 hex characters)"
        
        return None
    
    @staticmethod
    def validate_ip_address(ip_address: str) -> Optional[str]:
        """Валидация IP адреса"""
        try:
            ipaddress.ip_address(ip_address)
            return None
        except ValueError:
            return "Invalid IP address format"
    
    @staticmethod
    def validate_file_size(file_size: int) -> Optional[str]:
        """Валидация размера файла"""
        if file_size > security_config.MAX_FILE_SIZE_BYTES:
            return f"File too large (max {security_config.MAX_FILE_SIZE_MB}MB)"
        
        if file_size <= 0:
            return "File size must be positive"
        
        return None
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Санация имени файла"""
        if not filename:
            return "unknown_file"
        
        # Удаляем опасные символы
        cleaned = re.sub(r'[^\w\.\-_]', '_', filename)
        
        # Ограничиваем длину
        cleaned = cleaned[:100]
        
        # Убираем множественные точки и подчеркивания
        cleaned = re.sub(r'\.{2,}', '.', cleaned)
        cleaned = re.sub(r'_{2,}', '_', cleaned)
        
        return cleaned or "sanitized_file"
    
    @staticmethod
    def validate_domain(domain: str) -> Optional[str]:
        """Валидация доменного имени"""
        if not domain:
            return "Domain is required"
        
        if len(domain) > 253:
            return "Domain name too long"
        
        # Проверяем формат домена
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain):
            return "Invalid domain format"
        
        return None

# Глобальный экземпляр валидатора
security_validator = SecurityValidator()