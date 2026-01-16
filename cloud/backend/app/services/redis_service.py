from typing import Optional
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


redis_service = RedisService()
