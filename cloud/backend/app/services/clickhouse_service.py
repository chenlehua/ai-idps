import clickhouse_connect

from app.config import settings


class ClickHouseService:
    def __init__(self):
        self.client = None

    async def connect(self):
        self.client = clickhouse_connect.get_client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            database=settings.clickhouse_database,
        )

    async def disconnect(self):
        if self.client:
            self.client.close()
            self.client = None


clickhouse_service = ClickHouseService()
