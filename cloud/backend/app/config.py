from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    redis_url: str = "redis://localhost:6379"

    mysql_host: str = "localhost"
    mysql_port: int = 3306
    mysql_user: str = "root"
    mysql_password: str = "password"
    mysql_database: str = "nids"

    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123  # HTTP 端口，clickhouse-connect 使用 HTTP 接口
    clickhouse_database: str = "nids"

    rule_cache_ttl: int = 3600
    probe_status_ttl: int = 600
    probe_offline_threshold: int = 900

    class Config:
        env_file = ".env"


settings = Settings()
