# app/background_jobs.py
import asyncio
import time
from typing import Dict, Any, List, Optional
from app.logger import logger
from app.database import db_manager
from app.external_apis.manager import external_api_manager

class BackgroundJobManager:
    """Менеджер фоновых задач для долгих проверок"""
    
    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.running = False
        self.task = None
    
    async def start(self):
        """Запуск фонового обработчика задач"""
        if self.running:
            return
        
        self.running = True
        self.task = asyncio.create_task(self._job_processor())
        logger.info("Background job manager started")
    
    async def stop(self):
        """Остановка фонового обработчика задач"""
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("Background job manager stopped")
    
    async def _job_processor(self):
        """Основной цикл обработки фоновых задач"""
        while self.running:
            try:
                # Получаем задачи из БД
                pending_jobs = self._get_pending_jobs()
                
                for job in pending_jobs:
                    await self._process_job(job)
                
                # Ждем перед следующей итерацией
                await asyncio.sleep(10)  # Проверяем каждые 10 секунд
                
            except Exception as e:
                logger.error(f"Background job processor error: {e}")
                await asyncio.sleep(30)  # При ошибке ждем дольше
    
    def _get_pending_jobs(self) -> List[Dict[str, Any]]:
        """Получение ожидающих задач из БД"""
        try:
            with db_manager._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, job_type, job_data, created_at, retry_count
                    FROM background_jobs 
                    WHERE status = 'pending' AND retry_count < 3
                    ORDER BY created_at ASC
                    LIMIT 10
                """)
                rows = [dict(row) for row in cursor.fetchall()]
                # Пытаемся преобразовать job_data из JSON
                import json
                for r in rows:
                    try:
                        if isinstance(r.get('job_data'), str):
                            r['job_data'] = json.loads(r['job_data'])
                    except Exception:
                        pass
                return rows
        except Exception as e:
            logger.error(f"Get pending jobs error: {e}")
            return []
    
    async def _process_job(self, job: Dict[str, Any]):
        """Обработка отдельной задачи"""
        job_id = job['id']
        job_type = job['job_type']
        job_data = job['job_data']
        
        try:
            # Обновляем статус на "processing"
            self._update_job_status(job_id, 'processing')
            
            # Выполняем задачу в зависимости от типа
            if job_type == 'url_recheck':
                await self._process_url_recheck(job_data)
            elif job_type == 'file_recheck':
                await self._process_file_recheck(job_data)
            elif job_type == 'ip_recheck':
                await self._process_ip_recheck(job_data)
            else:
                logger.warning(f"Unknown job type: {job_type}")
                self._update_job_status(job_id, 'failed', 'Unknown job type')
                return
            
            # Отмечаем как выполненную
            self._update_job_status(job_id, 'completed')
            
        except Exception as e:
            logger.error(f"Job {job_id} processing error: {e}")
            # Увеличиваем счетчик попыток
            self._increment_retry_count(job_id)
    
    async def _process_url_recheck(self, job_data: Dict[str, Any]):
        """Повторная проверка URL через внешние API"""
        url = job_data.get('url')
        if not url:
            return
        
        try:
            # Проверяем через внешние API
            result = await external_api_manager.check_url_multiple_apis(url)
            
            # Если найдена угроза, сохраняем в БД
            if not result.get("safe", True):
                db_manager.add_malicious_url(
                    url,
                    result.get("threat_type", "malware"),
                    result.get("details", "Detected by background recheck")
                )
                logger.info(f"Background recheck found threat for URL: {url}")
        
        except Exception as e:
            logger.error(f"URL recheck error for {url}: {e}")
            raise
    
    async def _process_file_recheck(self, job_data: Dict[str, Any]):
        """Повторная проверка файла через внешние API"""
        file_hash = job_data.get('file_hash')
        if not file_hash:
            return
        
        try:
            # Проверяем через внешние API
            result = await external_api_manager.check_file_hash_multiple_apis(file_hash)
            
            # Если найдена угроза, сохраняем в БД
            if not result.get("safe", True):
                db_manager.add_malicious_hash(
                    file_hash,
                    result.get("threat_type", "malware"),
                    result.get("details", "Detected by background recheck")
                )
                logger.info(f"Background recheck found threat for file hash: {file_hash}")
        
        except Exception as e:
            logger.error(f"File recheck error for {file_hash}: {e}")
            raise
    
    async def _process_ip_recheck(self, job_data: Dict[str, Any]):
        """Повторная проверка IP через внешние API"""
        ip_address = job_data.get('ip_address')
        if not ip_address:
            return
        
        try:
            # Проверяем через внешние API
            result = await external_api_manager.check_ip_multiple_apis(ip_address)
            
            # Результат уже сохраняется в _combine_ip_results
            logger.info(f"Background IP recheck completed for: {ip_address}")
        
        except Exception as e:
            logger.error(f"IP recheck error for {ip_address}: {e}")
            raise
    
    def _update_job_status(self, job_id: int, status: str, error_message: str = None):
        """Обновление статуса задачи"""
        try:
            with db_manager._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE background_jobs 
                    SET status = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (status, error_message, job_id))
                conn.commit()
        except Exception as e:
            logger.error(f"Update job status error: {e}")
    
    def _increment_retry_count(self, job_id: int):
        """Увеличение счетчика попыток"""
        try:
            with db_manager._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE background_jobs 
                    SET retry_count = retry_count + 1, status = 'pending'
                    WHERE id = ?
                """, (job_id,))
                conn.commit()
        except Exception as e:
            logger.error(f"Increment retry count error: {e}")
    
    def add_job(self, job_type: str, job_data: Dict[str, Any]) -> bool:
        """Добавление новой фоновой задачи"""
        try:
            with db_manager._get_connection() as conn:
                cursor = conn.cursor()
                import json
                cursor.execute("""
                    INSERT INTO background_jobs (job_type, job_data, status, created_at)
                    VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
                """, (job_type, json.dumps(job_data)))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Add job error: {e}")
            return False

# Глобальный экземпляр менеджера фоновых задач
background_job_manager = BackgroundJobManager()
