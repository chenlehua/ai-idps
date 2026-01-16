import json
from typing import Optional, Set
import redis.asyncio as redis

from app.config import settings


class RedisService:
    def __init__(self):
        self.client: Optional[redis.Redis] = None

    async def connect(self):
        self.client = redis.from_url(settings.redis_url, decode_responses=True)

    async def disconnect(self):
        if self.client:
            await self.client.close()
            self.client = None

    # 规则缓存
    async def get_latest_rule_version(self) -> Optional[str]:
        if not self.client:
            return None
        return await self.client.get("rule:latest_version")

    async def set_latest_rule_version(self, version: str):
        if self.client:
            await self.client.set("rule:latest_version", version)

    async def get_rule_content(self, version: str) -> Optional[str]:
        if not self.client:
            return None
        return await self.client.get(f"rule:content:{version}")

    async def set_rule_content(self, version: str, content: str):
        if self.client:
            await self.client.setex(
                f"rule:content:{version}",
                settings.rule_cache_ttl,
                content
            )

    # 探针状态缓存
    async def set_probe_status(self, probe_id: str, status: dict):
        if self.client:
            # 将 dict 转换为字符串存储
            status_str = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) 
                         for k, v in status.items()}
            await self.client.hset(f"probe:status:{probe_id}", mapping=status_str)
            await self.client.expire(f"probe:status:{probe_id}", settings.probe_status_ttl)

    async def get_probe_status(self, probe_id: str) -> dict:
        if not self.client:
            return {}
        result = await self.client.hgetall(f"probe:status:{probe_id}")
        return result if result else {}

    async def add_online_probe(self, probe_id: str):
        if self.client:
            await self.client.sadd("probe:online", probe_id)

    async def remove_online_probe(self, probe_id: str):
        if self.client:
            await self.client.srem("probe:online", probe_id)

    async def get_online_probes(self) -> Set[str]:
        if not self.client:
            return set()
        result = await self.client.smembers("probe:online")
        return result if result else set()


redis_service = RedisService()
