from typing import List, Dict, Any

from app.services.clickhouse_service import clickhouse_service
from app.services.websocket_service import websocket_manager


class LogService:
    async def insert_logs(self, probe_id: str, logs: List[Dict[str, Any]]) -> int:
        """插入日志并广播到 WebSocket 客户端"""
        if not logs:
            return 0

        # 为每条日志添加 probe_id
        for log in logs:
            log['probe_id'] = probe_id

        # 插入到 ClickHouse
        count = await clickhouse_service.insert_logs(logs)

        # 广播到 WebSocket 客户端
        for log in logs:
            await websocket_manager.broadcast_log(log)

        return count


log_service = LogService()
