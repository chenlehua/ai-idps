from typing import Optional, List, Any
import aiomysql

from app.config import settings


class MySQLService:
    def __init__(self):
        self.pool: Optional[aiomysql.Pool] = None

    async def connect(self):
        self.pool = await aiomysql.create_pool(
            host=settings.mysql_host,
            port=settings.mysql_port,
            user=settings.mysql_user,
            password=settings.mysql_password,
            db=settings.mysql_database,
            autocommit=True,
            charset='utf8mb4',
        )

    async def disconnect(self):
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()
            self.pool = None

    async def execute(self, query: str, args: tuple = None) -> int:
        """执行写操作，返回影响的行数"""
        if not self.pool:
            return 0
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(query, args)
                return cur.rowcount

    async def fetchone(self, query: str, args: tuple = None) -> Optional[dict]:
        """查询单条记录"""
        if not self.pool:
            return None
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(query, args)
                return await cur.fetchone()

    async def fetchall(self, query: str, args: tuple = None) -> List[dict]:
        """查询多条记录"""
        if not self.pool:
            return []
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(query, args)
                return await cur.fetchall()

    async def insert(self, query: str, args: tuple = None) -> int:
        """插入记录，返回最后插入的 ID"""
        if not self.pool:
            return 0
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(query, args)
                return cur.lastrowid


mysql_service = MySQLService()
