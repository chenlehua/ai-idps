import asyncio
from typing import Dict, Optional
from dataclasses import dataclass, field
from fastapi import WebSocket


@dataclass
class WebSocketClient:
    websocket: WebSocket
    filters: dict = field(default_factory=dict)


class WebSocketManager:
    def __init__(self):
        self.clients: Dict[str, WebSocketClient] = {}
        self._lock = asyncio.Lock()

    async def connect(self, client_id: str, websocket: WebSocket):
        """添加新的 WebSocket 连接"""
        await websocket.accept()
        async with self._lock:
            self.clients[client_id] = WebSocketClient(websocket=websocket)

    async def disconnect(self, client_id: str):
        """移除 WebSocket 连接"""
        async with self._lock:
            if client_id in self.clients:
                del self.clients[client_id]

    async def subscribe(self, client_id: str, filters: dict):
        """设置客户端的订阅过滤条件"""
        async with self._lock:
            if client_id in self.clients:
                self.clients[client_id].filters = filters

    async def broadcast_log(self, log: dict):
        """广播日志到所有订阅的客户端"""
        disconnected = []

        async with self._lock:
            clients_copy = list(self.clients.items())

        for client_id, client in clients_copy:
            try:
                if self._match_filters(log, client.filters):
                    await client.websocket.send_json({
                        "event": "log",
                        "data": log
                    })
            except Exception:
                # 连接已断开，标记为待移除
                disconnected.append(client_id)

        # 移除断开的连接
        for client_id in disconnected:
            await self.disconnect(client_id)

    def _match_filters(self, log: dict, filters: dict) -> bool:
        """检查日志是否匹配过滤条件"""
        if not filters:
            return True

        if 'probe_id' in filters and filters['probe_id']:
            if log.get('probe_id') != filters['probe_id']:
                return False

        if 'severity' in filters and filters['severity']:
            severity_list = filters['severity']
            if isinstance(severity_list, list):
                alert = log.get('alert', {})
                log_severity = alert.get('severity', log.get('severity'))
                if log_severity not in severity_list:
                    return False

        if 'probe_type' in filters and filters['probe_type']:
            if log.get('probe_type') != filters['probe_type']:
                return False

        return True

    @property
    def client_count(self) -> int:
        """获取当前连接的客户端数量"""
        return len(self.clients)


websocket_manager = WebSocketManager()
