import json
from typing import Optional, Set, Dict, Any, Mapping
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

    # ========== 通用操作 ==========
    async def get(self, key: str) -> Optional[str]:
        """获取字符串值"""
        if not self.client:
            return None
        return await self.client.get(key)

    async def set(self, key: str, value: str, ex: Optional[int] = None):
        """设置字符串值"""
        if self.client:
            if ex:
                await self.client.setex(key, ex, value)
            else:
                await self.client.set(key, value)

    async def delete(self, *keys: str):
        """删除键"""
        if self.client and keys:
            await self.client.delete(*keys)

    async def expire(self, key: str, seconds: int):
        """设置过期时间"""
        if self.client:
            await self.client.expire(key, seconds)

    async def exists(self, key: str) -> bool:
        """检查键是否存在"""
        if not self.client:
            return False
        return await self.client.exists(key) > 0

    # ========== Hash 操作 ==========
    async def hset(self, key: str, mapping: Optional[Mapping[str, str]] = None, **kwargs):
        """设置 Hash 字段"""
        if self.client:
            if mapping:
                await self.client.hset(key, mapping=mapping)
            if kwargs:
                await self.client.hset(key, mapping=kwargs)

    async def hget(self, key: str, field: str) -> Optional[str]:
        """获取 Hash 字段值"""
        if not self.client:
            return None
        return await self.client.hget(key, field)

    async def hgetall(self, key: str) -> Dict[str, str]:
        """获取 Hash 所有字段"""
        if not self.client:
            return {}
        result = await self.client.hgetall(key)
        return result if result else {}

    async def hdel(self, key: str, *fields: str):
        """删除 Hash 字段"""
        if self.client and fields:
            await self.client.hdel(key, *fields)

    # ========== List 操作 ==========
    async def lpush(self, key: str, *values: str):
        """从左边推入列表"""
        if self.client and values:
            await self.client.lpush(key, *values)

    async def rpush(self, key: str, *values: str):
        """从右边推入列表"""
        if self.client and values:
            await self.client.rpush(key, *values)

    async def lpop(self, key: str, count: int = 1) -> Optional[str]:
        """从左边弹出"""
        if not self.client:
            return None
        return await self.client.lpop(key, count)

    async def lrange(self, key: str, start: int, end: int) -> list:
        """获取列表范围"""
        if not self.client:
            return []
        result = await self.client.lrange(key, start, end)
        return result if result else []

    async def llen(self, key: str) -> int:
        """获取列表长度"""
        if not self.client:
            return 0
        return await self.client.llen(key)

    # ========== Set 操作 ==========
    async def sadd(self, key: str, *members: str):
        """添加集合成员"""
        if self.client and members:
            await self.client.sadd(key, *members)

    async def srem(self, key: str, *members: str):
        """删除集合成员"""
        if self.client and members:
            await self.client.srem(key, *members)

    async def smembers(self, key: str) -> Set[str]:
        """获取集合所有成员"""
        if not self.client:
            return set()
        result = await self.client.smembers(key)
        return result if result else set()

    async def sismember(self, key: str, member: str) -> bool:
        """检查是否是集合成员"""
        if not self.client:
            return False
        return await self.client.sismember(key, member)

    # ========== 规则缓存 (兼容旧代码) ==========
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

    # ========== 探针状态缓存 ==========
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
