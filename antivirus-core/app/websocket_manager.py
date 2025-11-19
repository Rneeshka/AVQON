import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Set

from fastapi import WebSocket

from app.logger import logger


class ClientConnection:
    """Представление активного WebSocket клиента."""

    def __init__(self, websocket: WebSocket, api_key_info: Optional[Dict[str, Any]], meta: Optional[Dict[str, Any]] = None):
        self.id: str = str(uuid.uuid4())
        self.websocket: WebSocket = websocket
        self.api_key_info: Optional[Dict[str, Any]] = api_key_info
        self.meta: Dict[str, Any] = meta or {}
        self.connected_at: datetime = datetime.utcnow()
        self.last_heartbeat: datetime = self.connected_at
        self.subscriptions: Set[str] = set()

    @property
    def features(self) -> Set[str]:
        """Возвращает набор функций, доступных клиенту согласно API ключу."""
        features_raw = (self.api_key_info or {}).get("features", "[]")
        if isinstance(features_raw, str):
            try:
                import json

                parsed = json.loads(features_raw or "[]")
            except Exception:
                parsed = []
        elif isinstance(features_raw, (list, tuple, set)):
            parsed = list(features_raw)
        else:
            parsed = []
        return set(parsed)

    def touch(self) -> None:
        """Обновляет timestamp последнего heartbeat."""
        self.last_heartbeat = datetime.utcnow()


class WebSocketManager:
    """Менеджер для отслеживания активных WebSocket подключений."""

    def __init__(self) -> None:
        self._clients: Dict[str, ClientConnection] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, api_key_info: Optional[Dict[str, Any]], meta: Optional[Dict[str, Any]]) -> ClientConnection:
        client = ClientConnection(websocket, api_key_info, meta)
        async with self._lock:
            self._clients[client.id] = client
        logger.info(f"[WS] Client connected: id={client.id}, ip={meta.get('ip') if meta else 'unknown'}")
        return client

    async def disconnect(self, client_id: str, close_code: int = 1000, reason: Optional[str] = None) -> None:
        async with self._lock:
            client = self._clients.pop(client_id, None)
        if client:
            try:
                if client.websocket.application_state.value != 3:  # 3 = WebSocketState.DISCONNECTED
                    await client.websocket.close(code=close_code, reason=reason)
            except RuntimeError:
                pass
            except Exception as exc:
                logger.debug(f"[WS] Error closing websocket for {client_id}: {exc}")
            logger.info(f"[WS] Client disconnected: id={client_id}, reason={reason or 'unknown'}")

    async def send_json(self, client: ClientConnection, payload: Dict[str, Any]) -> None:
        try:
            await client.websocket.send_json(payload)
        except RuntimeError:
            # Соединение уже закрыто
            logger.debug(f"[WS] Attempted to send to closed connection {client.id}")
        except Exception as exc:
            logger.warning(f"[WS] Failed to send message to {client.id}: {exc}")

    async def send_error(self, client: ClientConnection, request_id: Optional[str], message: str, code: str = "error") -> None:
        payload = {
            "type": "error",
            "code": code,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if request_id:
            payload["requestId"] = request_id
        await self.send_json(client, payload)

    async def broadcast(self, payload: Dict[str, Any], subscription: Optional[str] = None) -> None:
        async with self._lock:
            clients = list(self._clients.values())
        for client in clients:
            if subscription and subscription not in client.subscriptions:
                continue
            await self.send_json(client, payload)

    async def mark_heartbeat(self, client: ClientConnection) -> None:
        client.touch()

    async def remove_stale_clients(self, timeout_seconds: int = 90) -> None:
        """Закрывает соединения, которые давно не отправляли heartbeat."""
        now = datetime.utcnow()
        stale_clients: Dict[str, ClientConnection] = {}

        async with self._lock:
            for client_id, client in list(self._clients.items()):
                if (now - client.last_heartbeat) > timedelta(seconds=timeout_seconds):
                    stale_clients[client_id] = client
                    self._clients.pop(client_id, None)

        for client_id, client in stale_clients.items():
            try:
                await client.websocket.close(code=4000, reason="Heartbeat timeout")
            except Exception:
                pass
            logger.info(f"[WS] Client removed due to heartbeat timeout: id={client_id}")

    async def close_all(self) -> None:
        async with self._lock:
            clients = list(self._clients.items())
            self._clients.clear()
        for client_id, client in clients:
            try:
                await client.websocket.close(code=1001, reason="Server shutdown")
            except Exception:
                pass
            logger.info(f"[WS] Closed connection for client {client_id} (server shutdown)")

