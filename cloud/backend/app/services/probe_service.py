from typing import Optional, List, Dict, Any


class ProbeService:
    async def list_probes(self) -> List[Dict[str, Any]]:
        return []

    async def get_probe(self, probe_id: str) -> Optional[Dict[str, Any]]:
        return None


probe_service = ProbeService()
