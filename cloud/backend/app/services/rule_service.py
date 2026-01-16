from typing import Optional, List, Dict


class RuleService:
    async def get_latest_version(self) -> Optional[str]:
        return None

    async def get_rule_by_version(self, version: str) -> Optional[Dict]:
        return None

    async def create_rule_version(self, content: str, description: str = "") -> Dict:
        return {"version": "v0", "checksum": "sha256:placeholder"}

    async def list_versions(self, limit: int = 20) -> List[Dict]:
        return []


rule_service = RuleService()
