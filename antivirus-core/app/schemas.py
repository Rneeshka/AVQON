# Импортируем необходимые классы из Pydantic
# Pydantic отвечает за валидацию данных и автоматическую документацию
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any
from datetime import datetime

# Модель для запроса на проверку URL
class UrlCheckRequest(BaseModel):
    """
    Модель запроса для проверки URL.
    
    Attributes:
        url (HttpUrl): URL для проверки. Pydantic автоматически валидирует,
                      что это корректный URL.
    """
    # HttpUrl - специальный тип Pydantic, который автоматически проверяет,
    # что строка является валидным URL
    url: HttpUrl = Field(
        ...,
        example="https://example.com",
        description="URL для проверки на вредоносность"
    )

# Модель для запроса на проверку файла по хэшу
class FileCheckRequest(BaseModel):
    """
    Модель запроса для проверки файла по его хэшу.
    
    Attributes:
        file_hash (str): SHA-256 хэш файла для проверки.
    """
    file_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        example="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        description="SHA-256 хэш файла для проверки (64 символа)"
    )

# Модель для ответа от сервера
class CheckResponse(BaseModel):
    """
    Модель ответа на запрос проверки.
    
    Attributes:
        status (str): Статус выполнения запроса ("success" или "error")
        safe (bool): Результат проверки (True - безопасно, False - опасно)
        threat_type (Optional[str]): Тип угрозы, если обнаружена
        details (Optional[str]): Детальная информация об угрозе
        request_id (Optional[str]): Уникальный идентификатор запроса
    """
    status: str = Field(
        default="success",
        example="success",
        description="Статус выполнения запроса"
    )
    safe: Optional[bool] = Field(
        default=None,
        example=True,
        description="Результат проверки: True - безопасно, False - опасно, None - неизвестно"
    )
    threat_type: Optional[str] = Field(
        default=None,
        example="phishing",
        description="Тип обнаруженной угрозы (malware, phishing, adware, etc.)"
    )
    details: Optional[str] = Field(
        default=None,
        example="URL found in phishing database",
        description="Детальное описание обнаруженной угрозы"
    )
    request_id: Optional[str] = Field(
        default=None,
        example="req_123456789",
        description="Уникальный идентификатор запроса для отслеживания"
    )

# Модель для ошибок API
class ErrorResponse(BaseModel):
    """
    Модель ответа при ошибке.
    
    Attributes:
        status (str): Статус ошибки ("error")
        message (str): Сообщение об ошибке
        error_code (Optional[str]): Код ошибки
    """
    status: str = Field(
        default="error",
        example="error",
        description="Статус ошибки"
    )
    message: str = Field(
        ...,
        example="Invalid API key",
        description="Сообщение об ошибке"
    )
    error_code: Optional[str] = Field(
        default=None,
        example="INVALID_API_KEY",
        description="Код ошибки для программной обработки"
    )


class LocalCacheCheckRequest(BaseModel):
    url: HttpUrl = Field(..., description="URL для проверки в локальном кэше")


class LocalCacheSaveRequest(BaseModel):
    url: HttpUrl
    safe: bool
    threat_type: Optional[str] = None
    details: Optional[str] = None
    detection_ratio: Optional[str] = None
    confidence: Optional[int] = None
    source: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None


class LocalCacheResponse(BaseModel):
    status: str = Field(..., example="hit")
    safe: Optional[bool] = None
    threat_type: Optional[str] = None
    details: Optional[str] = None
    source: Optional[str] = None
    detection_ratio: Optional[str] = None
    confidence: Optional[int] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    storage: Optional[str] = None
    cached_at: Optional[datetime] = None


class LocalCacheStatsResponse(BaseModel):
    whitelist_entries: int
    blacklist_entries: int
    whitelist_hits: int
    blacklist_hits: int
    bytes_estimated: int
    total_entries: int

# Модель для создания отзыва
class CreateReviewRequest(BaseModel):
    rating: int = Field(..., ge=1, le=5, description="Оценка от 1 до 5 звезд")
    text: Optional[str] = Field(None, max_length=1000, description="Текст отзыва (опционально)")

# Модель для ответа при создании отзыва
class CreateReviewResponse(BaseModel):
    status: str
    review_id: Optional[int] = None
    message: Optional[str] = None