# app/external_apis/base_client.py
import aiohttp
import asyncio
from typing import Dict, Any, Optional
import time
from app.logger import logger
from app.config import config

class BaseAPIClient:
    """Базовый асинхронный клиент для внешних API"""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_times = []
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(
                total=min(config.REQUEST_TIMEOUT, 20),  # общий таймаут
                sock_connect=5,  # быстрое подключение
                sock_read=10      # читаем быстро
            )
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _check_rate_limit(self, max_requests: int, time_window: int = 3600) -> bool:
        """Проверка rate limiting"""
        now = time.time()
        # Удаляем старые запросы
        self.request_times = [t for t in self.request_times if now - t < time_window]
        
        if len(self.request_times) >= max_requests:
            return False
        
        self.request_times.append(now)
        return True
    
    async def _make_request(self, method: str, endpoint: str, 
                          params: Dict = None, data: Dict = None, 
                          max_retries: int = config.MAX_RETRIES) -> Optional[Dict[str, Any]]:
        """Выполнение HTTP запроса с retry логикой"""
        
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")
        
        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers()
        
        for attempt in range(max_retries):
            try:
                async with self.session.request(
                    method, url, params=params, json=data, headers=headers
                ) as response:
                    
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 404:
                        # 404 - ресурс не найден, это нормально для некоторых API (например, VirusTotal когда URL не в базе)
                        logger.debug(f"Resource not found (404) for {endpoint}")
                        return None
                    elif response.status == 429:  # Rate limit
                        wait_time = 2 ** attempt  # Exponential backoff
                        logger.warning(f"Rate limit hit, waiting {wait_time}s")
                        await asyncio.sleep(wait_time)
                        continue
                    elif response.status in (500, 502, 503, 504):
                        logger.error(f"Server error {response.status}, attempt {attempt + 1}")
                        await asyncio.sleep(1)
                        continue
                    else:
                        error_text = await response.text()
                        logger.error(f"API error {response.status} for {endpoint}: {error_text[:500]}")
                        return None
                        
            except aiohttp.ClientError as e:
                logger.error(f"Request error (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                continue
            except asyncio.TimeoutError:
                logger.error(f"Timeout error (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                continue
        
        return None
    
    def _get_headers(self) -> Dict[str, str]:
        """Возвращает заголовки для конкретного API"""
        raise NotImplementedError("Subclasses must implement this method")