from typing import List, Dict, Any


class LogService:
    async def insert_logs(self, probe_id: str, logs: List[Dict[str, Any]]) -> int:
        return len(logs)


log_service = LogService()
