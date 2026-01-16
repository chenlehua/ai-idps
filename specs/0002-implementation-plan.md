# 网络入侵检测系统实现计划

本文档基于 [0001-spec.md](./0001-spec.md) 设计文档，提供详细的实现计划。

## 目录

- [1. 实现概览](#1-实现概览)
- [2. 第一阶段：环境搭建与基础框架](#2-第一阶段环境搭建与基础框架)
- [3. 第二阶段：云端后端核心功能](#3-第二阶段云端后端核心功能)
- [4. 第三阶段：探针管理程序 (Probe Manager)](#4-第三阶段探针管理程序-probe-manager)
- [5. 第四阶段：NIDS 探针实现](#5-第四阶段nids-探针实现)
- [6. 第五阶段：云端前端实现](#6-第五阶段云端前端实现)
- [7. 第六阶段：集成测试与优化](#7-第六阶段集成测试与优化)
- [附录 A：文件清单](#附录-a文件清单)
- [附录 B：依赖版本](#附录-b依赖版本)

---

## 1. 实现概览

### 1.1 实现顺序

```mermaid
graph LR
    P1[第一阶段<br/>环境搭建] --> P2[第二阶段<br/>云端后端]
    P2 --> P3[第三阶段<br/>Probe Manager]
    P3 --> P4[第四阶段<br/>NIDS 探针]
    P2 --> P5[第五阶段<br/>云端前端]
    P4 --> P6[第六阶段<br/>集成测试]
    P5 --> P6

    style P1 fill:#e3f2fd
    style P2 fill:#e8f5e9
    style P3 fill:#fff3e0
    style P4 fill:#fce4ec
    style P5 fill:#f3e5f5
    style P6 fill:#e0f2f1
```

### 1.2 组件依赖关系

```mermaid
graph TB
    subgraph 云端
        BE[Backend API]
        FE[Frontend]
        REDIS[(Redis)]
        MYSQL[(MySQL)]
        CH[(ClickHouse)]
    end

    subgraph 探针端
        PM[Probe Manager]
        NIDS[NIDS 探针]
        SR[Suricata]
    end

    FE --> BE
    BE --> REDIS
    BE --> MYSQL
    BE --> CH
    PM --> BE
    NIDS --> PM
    NIDS -.-> SR
```

---

## 2. 第一阶段：环境搭建与基础框架

### 2.1 目标

- 搭建完整的开发环境
- 创建项目目录结构
- 配置 Docker 开发环境
- 验证各组件连通性

### 2.2 任务清单

#### 2.2.1 项目初始化

| 任务 | 说明 | 输出文件 |
|:-----|:-----|:---------|
| 创建目录结构 | 按照设计文档创建完整目录 | 见 [附录 A](#附录-a文件清单) |
| 初始化 Git | 配置 .gitignore | `.gitignore` |
| 添加 Suricata 子模块 | `git submodule add` | `third_party/suricata/` |

#### 2.2.2 Docker 环境配置

**docker-compose.yml 实现:**

```yaml
# cloud/docker-compose.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - frontend
      - backend

  frontend:
    build: ./frontend
    expose:
      - "3000"
    environment:
      - VITE_API_URL=/api

  backend:
    build: ./backend
    expose:
      - "8000"
    environment:
      - REDIS_URL=redis://redis:6379
      - MYSQL_URL=mysql://root:password@mysql:3306/nids
      - CLICKHOUSE_URL=clickhouse://clickhouse:9000/nids
    depends_on:
      - redis
      - mysql
      - clickhouse

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  mysql:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=password
      - MYSQL_DATABASE=nids
    volumes:
      - mysql_data:/var/lib/mysql
      - ./mysql/init.sql:/docker-entrypoint-initdb.d/init.sql:ro

  clickhouse:
    image: clickhouse/clickhouse-server:latest
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - ./clickhouse/init.sql:/docker-entrypoint-initdb.d/init.sql:ro

volumes:
  redis_data:
  mysql_data:
  clickhouse_data:
```

**Nginx 配置:**

```nginx
# cloud/nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream frontend {
        server frontend:3000;
    }

    upstream backend {
        server backend:8000;
    }

    server {
        listen 80;

        # 前端静态资源
        location / {
            proxy_pass http://frontend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        # 后端 API
        location /api/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        # WebSocket
        location /api/v1/ws/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 86400;
        }
    }
}
```

#### 2.2.3 数据库初始化脚本

**MySQL 初始化:**

```sql
-- cloud/mysql/init.sql

-- 探针节点表
CREATE TABLE IF NOT EXISTS probe_nodes (
    node_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    status ENUM('online', 'offline', 'unknown') DEFAULT 'unknown',
    last_seen DATETIME,
    current_rule_version VARCHAR(32),
    system_status JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 探针实例表
CREATE TABLE IF NOT EXISTS probe_instances (
    instance_id VARCHAR(64) PRIMARY KEY,
    node_id VARCHAR(64) NOT NULL,
    probe_type VARCHAR(32) NOT NULL,
    interface VARCHAR(32),
    status ENUM('running', 'stopped', 'error') DEFAULT 'stopped',
    last_seen DATETIME,
    metrics JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES probe_nodes(node_id) ON DELETE CASCADE,
    INDEX idx_node_id (node_id),
    INDEX idx_probe_type (probe_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 规则版本表
CREATE TABLE IF NOT EXISTS rule_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    version VARCHAR(32) UNIQUE NOT NULL,
    content LONGTEXT NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_version (version),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**ClickHouse 初始化:**

```sql
-- cloud/clickhouse/init.sql

-- 创建数据库
CREATE DATABASE IF NOT EXISTS nids;

-- 告警日志表 (按日分区)
CREATE TABLE IF NOT EXISTS nids.alert_logs (
    id UUID DEFAULT generateUUIDv4(),
    node_id String,
    instance_id String,
    probe_type LowCardinality(String),
    timestamp DateTime64(3),
    src_ip IPv4,
    dest_ip IPv4,
    src_port UInt16,
    dest_port UInt16,
    protocol LowCardinality(String),
    alert_msg String,
    signature_id UInt32,
    severity UInt8,
    category LowCardinality(String),
    raw_log String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, node_id, severity)
TTL timestamp + INTERVAL 90 DAY;

-- 统计物化视图 (按小时聚合)
CREATE MATERIALIZED VIEW IF NOT EXISTS nids.alert_stats_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, node_id, severity)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    node_id,
    severity,
    count() AS alert_count
FROM nids.alert_logs
GROUP BY hour, node_id, severity;

-- 按探针类型统计视图
CREATE MATERIALIZED VIEW IF NOT EXISTS nids.alert_stats_by_type
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, probe_type, category)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    probe_type,
    category,
    count() AS alert_count
FROM nids.alert_logs
GROUP BY hour, probe_type, category;
```

#### 2.2.4 后端基础框架

**项目配置:**

```toml
# cloud/backend/pyproject.toml
[project]
name = "nids-backend"
version = "0.1.0"
description = "Network Intrusion Detection System - Backend"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.109.0",
    "uvicorn[standard]>=0.27.0",
    "redis>=5.0.0",
    "aiomysql>=0.2.0",
    "clickhouse-connect>=0.7.0",
    "pydantic>=2.5.0",
    "pydantic-settings>=2.1.0",
    "python-multipart>=0.0.6",
    "websockets>=12.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

**应用入口:**

```python
# cloud/backend/app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import probe_router, rules_router, logs_router, frontend_router
from app.services.redis_service import redis_service
from app.services.mysql_service import mysql_service
from app.services.clickhouse_service import clickhouse_service
from app.services.websocket_service import websocket_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时初始化连接
    await redis_service.connect()
    await mysql_service.connect()
    await clickhouse_service.connect()
    yield
    # 关闭时清理连接
    await redis_service.disconnect()
    await mysql_service.disconnect()
    await clickhouse_service.disconnect()


app = FastAPI(
    title="NIDS Backend API",
    version="0.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 探针通信接口
app.include_router(probe_router, prefix="/api/v1")

# 前端 API 接口
app.include_router(rules_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(frontend_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {"status": "ok"}
```

**配置管理:**

```python
# cloud/backend/app/config.py
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Redis
    redis_url: str = "redis://localhost:6379"

    # MySQL
    mysql_host: str = "localhost"
    mysql_port: int = 3306
    mysql_user: str = "root"
    mysql_password: str = "password"
    mysql_database: str = "nids"

    # ClickHouse
    clickhouse_host: str = "localhost"
    clickhouse_port: int = 9000
    clickhouse_database: str = "nids"

    # 缓存配置
    rule_cache_ttl: int = 3600  # 1小时
    probe_status_ttl: int = 600  # 10分钟

    # 探针配置
    probe_offline_threshold: int = 900  # 15分钟

    class Config:
        env_file = ".env"


settings = Settings()
```

#### 2.2.5 前端基础框架

**项目配置:**

```json
// cloud/frontend/package.json
{
  "name": "nids-frontend",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "@tanstack/react-query": "^5.17.0",
    "axios": "^1.6.0",
    "zustand": "^4.4.0",
    "date-fns": "^3.2.0",
    "recharts": "^2.10.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "@vitejs/plugin-react": "^4.2.0",
    "typescript": "^5.3.0",
    "vite": "^5.0.0",
    "tailwindcss": "^3.4.0",
    "postcss": "^8.4.0",
    "autoprefixer": "^10.4.0"
  }
}
```

**应用入口:**

```tsx
// cloud/frontend/src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)
```

#### 2.2.6 验收标准

- [ ] `docker-compose up` 成功启动所有服务
- [ ] 访问 `http://localhost/health` 返回 `{"status": "ok"}`
- [ ] Redis 连接正常 (通过 redis-cli 验证)
- [ ] MySQL 数据库和表创建成功
- [ ] ClickHouse 数据库和表创建成功
- [ ] 前端页面可以正常访问

---

## 3. 第二阶段：云端后端核心功能

### 3.1 目标

- 实现探针通信协议 (cmd + data)
- 实现规则管理 CRUD
- 实现日志接收和存储
- 实现 WebSocket 实时推送
- 实现 Redis 缓存层

### 3.2 任务清单

#### 3.2.1 探针通信协议实现

**协议模型定义:**

```python
# cloud/backend/app/models/probe_protocol.py
from enum import IntEnum
from typing import Any, Optional, List
from pydantic import BaseModel


class ProbeCommand(IntEnum):
    """探针命令码"""
    LOG_UPLOAD = 10
    LOG_UPLOAD_RESPONSE = 11
    HEARTBEAT = 20
    HEARTBEAT_RESPONSE = 21
    REGISTER = 30
    REGISTER_RESPONSE = 31
    RULE_DOWNLOAD = 40
    RULE_DOWNLOAD_RESPONSE = 41


class ProbeRequest(BaseModel):
    """探针请求基础模型"""
    cmd: int
    data: dict[str, Any]


class ProbeResponse(BaseModel):
    """探针响应基础模型"""
    cmd: int
    data: dict[str, Any]


# 具体请求/响应模型
class RegisterData(BaseModel):
    probe_id: str
    name: str
    ip: str
    probe_types: List[str]


class HeartbeatData(BaseModel):
    probe_id: str
    rule_version: Optional[str]
    status: dict[str, Any]
    probes: List[dict[str, Any]]


class RuleDownloadData(BaseModel):
    probe_id: str
    version: str


class LogUploadData(BaseModel):
    probe_id: str
    logs: List[dict[str, Any]]
```

**探针路由实现:**

```python
# cloud/backend/app/routers/probe.py
from fastapi import APIRouter, HTTPException
from app.models.probe_protocol import (
    ProbeCommand, ProbeRequest, ProbeResponse,
    RegisterData, HeartbeatData, RuleDownloadData, LogUploadData
)
from app.services.probe_service import probe_service
from app.services.rule_service import rule_service
from app.services.log_service import log_service

router = APIRouter(tags=["probe"])


@router.post("/probe", response_model=ProbeResponse)
async def handle_probe_request(request: ProbeRequest) -> ProbeResponse:
    """统一探针通信入口"""
    cmd = request.cmd
    data = request.data

    try:
        if cmd == ProbeCommand.REGISTER:
            return await handle_register(RegisterData(**data))
        elif cmd == ProbeCommand.HEARTBEAT:
            return await handle_heartbeat(HeartbeatData(**data))
        elif cmd == ProbeCommand.RULE_DOWNLOAD:
            return await handle_rule_download(RuleDownloadData(**data))
        elif cmd == ProbeCommand.LOG_UPLOAD:
            return await handle_log_upload(LogUploadData(**data))
        else:
            return ProbeResponse(
                cmd=cmd + 1,
                data={"status": "error", "error_code": 1004, "message": "未知命令"}
            )
    except Exception as e:
        return ProbeResponse(
            cmd=cmd + 1,
            data={"status": "error", "error_code": 1005, "message": str(e)}
        )


async def handle_register(data: RegisterData) -> ProbeResponse:
    """处理探针注册"""
    result = await probe_service.register_probe(
        probe_id=data.probe_id,
        name=data.name,
        ip=data.ip,
        probe_types=data.probe_types
    )
    return ProbeResponse(
        cmd=ProbeCommand.REGISTER_RESPONSE,
        data=result
    )


async def handle_heartbeat(data: HeartbeatData) -> ProbeResponse:
    """处理心跳请求"""
    # 更新探针状态
    await probe_service.update_probe_status(
        probe_id=data.probe_id,
        status=data.status,
        probes=data.probes,
        rule_version=data.rule_version
    )

    # 获取最新规则版本
    latest_version = await rule_service.get_latest_version()

    return ProbeResponse(
        cmd=ProbeCommand.HEARTBEAT_RESPONSE,
        data={
            "status": "ok",
            "latest_rule_version": latest_version,
            "server_time": datetime.utcnow().isoformat() + "Z"
        }
    )


async def handle_rule_download(data: RuleDownloadData) -> ProbeResponse:
    """处理规则下载"""
    rule = await rule_service.get_rule_by_version(data.version)
    if not rule:
        return ProbeResponse(
            cmd=ProbeCommand.RULE_DOWNLOAD_RESPONSE,
            data={"status": "error", "error_code": 1003, "message": "规则版本不存在"}
        )

    return ProbeResponse(
        cmd=ProbeCommand.RULE_DOWNLOAD_RESPONSE,
        data={
            "status": "ok",
            "version": rule["version"],
            "content": rule["content"],
            "checksum": rule["checksum"]
        }
    )


async def handle_log_upload(data: LogUploadData) -> ProbeResponse:
    """处理日志上报"""
    count = await log_service.insert_logs(data.probe_id, data.logs)

    return ProbeResponse(
        cmd=ProbeCommand.LOG_UPLOAD_RESPONSE,
        data={
            "status": "ok",
            "received": count,
            "message": "日志接收成功"
        }
    )
```

#### 3.2.2 服务层实现

**Redis 服务:**

```python
# cloud/backend/app/services/redis_service.py
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

    # 规则缓存
    async def get_latest_rule_version(self) -> Optional[str]:
        return await self.client.get("rule:latest_version")

    async def set_latest_rule_version(self, version: str):
        await self.client.set("rule:latest_version", version)

    async def get_rule_content(self, version: str) -> Optional[str]:
        return await self.client.get(f"rule:content:{version}")

    async def set_rule_content(self, version: str, content: str):
        await self.client.setex(
            f"rule:content:{version}",
            settings.rule_cache_ttl,
            content
        )

    # 探针状态缓存
    async def set_probe_status(self, probe_id: str, status: dict):
        await self.client.hset(f"probe:status:{probe_id}", mapping=status)
        await self.client.expire(f"probe:status:{probe_id}", settings.probe_status_ttl)

    async def get_probe_status(self, probe_id: str) -> dict:
        return await self.client.hgetall(f"probe:status:{probe_id}")

    async def add_online_probe(self, probe_id: str):
        await self.client.sadd("probe:online", probe_id)

    async def remove_online_probe(self, probe_id: str):
        await self.client.srem("probe:online", probe_id)

    async def get_online_probes(self) -> Set[str]:
        return await self.client.smembers("probe:online")


redis_service = RedisService()
```

**MySQL 服务:**

```python
# cloud/backend/app/services/mysql_service.py
from typing import Optional, List
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
            autocommit=True
        )

    async def disconnect(self):
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()

    async def execute(self, query: str, args: tuple = None) -> int:
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(query, args)
                return cur.rowcount

    async def fetchone(self, query: str, args: tuple = None) -> Optional[dict]:
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(query, args)
                return await cur.fetchone()

    async def fetchall(self, query: str, args: tuple = None) -> List[dict]:
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(query, args)
                return await cur.fetchall()


mysql_service = MySQLService()
```

**ClickHouse 服务:**

```python
# cloud/backend/app/services/clickhouse_service.py
from typing import List
import clickhouse_connect
from app.config import settings


class ClickHouseService:
    def __init__(self):
        self.client = None

    async def connect(self):
        self.client = clickhouse_connect.get_client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            database=settings.clickhouse_database
        )

    async def disconnect(self):
        if self.client:
            self.client.close()

    async def insert_logs(self, logs: List[dict]):
        """批量插入告警日志"""
        if not logs:
            return 0

        columns = [
            'node_id', 'instance_id', 'probe_type', 'timestamp',
            'src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol',
            'alert_msg', 'signature_id', 'severity', 'category', 'raw_log'
        ]

        data = []
        for log in logs:
            data.append([
                log.get('probe_id', ''),
                log.get('instance_id', ''),
                log.get('probe_type', 'nids'),
                log.get('timestamp'),
                log.get('src_ip', '0.0.0.0'),
                log.get('dest_ip', '0.0.0.0'),
                log.get('src_port', 0),
                log.get('dest_port', 0),
                log.get('protocol', ''),
                log.get('alert', {}).get('signature', ''),
                log.get('alert', {}).get('signature_id', 0),
                log.get('alert', {}).get('severity', 0),
                log.get('alert', {}).get('category', ''),
                log.get('raw', '')
            ])

        self.client.insert('alert_logs', data, column_names=columns)
        return len(data)

    async def query_logs(
        self,
        start_time: str = None,
        end_time: str = None,
        probe_id: str = None,
        severity: int = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[dict]:
        """查询告警日志"""
        conditions = ["1=1"]
        params = {}

        if start_time:
            conditions.append("timestamp >= %(start_time)s")
            params['start_time'] = start_time
        if end_time:
            conditions.append("timestamp <= %(end_time)s")
            params['end_time'] = end_time
        if probe_id:
            conditions.append("node_id = %(probe_id)s")
            params['probe_id'] = probe_id
        if severity is not None:
            conditions.append("severity = %(severity)s")
            params['severity'] = severity

        query = f"""
            SELECT *
            FROM alert_logs
            WHERE {' AND '.join(conditions)}
            ORDER BY timestamp DESC
            LIMIT {limit} OFFSET {offset}
        """

        result = self.client.query(query, parameters=params)
        return result.result_rows

    async def get_stats(self, hours: int = 24) -> dict:
        """获取统计数据"""
        query = f"""
            SELECT
                toStartOfHour(timestamp) as hour,
                severity,
                count() as count
            FROM alert_logs
            WHERE timestamp >= now() - INTERVAL {hours} HOUR
            GROUP BY hour, severity
            ORDER BY hour
        """
        result = self.client.query(query)
        return result.result_rows


clickhouse_service = ClickHouseService()
```

#### 3.2.3 WebSocket 实时推送

```python
# cloud/backend/app/services/websocket_service.py
import json
import asyncio
from typing import Dict, Set, Optional
from fastapi import WebSocket
from dataclasses import dataclass, field


@dataclass
class WebSocketClient:
    websocket: WebSocket
    filters: dict = field(default_factory=dict)


class WebSocketManager:
    def __init__(self):
        self.clients: Dict[str, WebSocketClient] = {}
        self._lock = asyncio.Lock()

    async def connect(self, client_id: str, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.clients[client_id] = WebSocketClient(websocket=websocket)

    async def disconnect(self, client_id: str):
        async with self._lock:
            if client_id in self.clients:
                del self.clients[client_id]

    async def subscribe(self, client_id: str, filters: dict):
        async with self._lock:
            if client_id in self.clients:
                self.clients[client_id].filters = filters

    async def broadcast_log(self, log: dict):
        """广播日志到所有订阅的客户端"""
        async with self._lock:
            for client_id, client in list(self.clients.items()):
                try:
                    if self._match_filters(log, client.filters):
                        await client.websocket.send_json({
                            "event": "log",
                            "data": log
                        })
                except Exception:
                    # 连接已断开，移除客户端
                    del self.clients[client_id]

    def _match_filters(self, log: dict, filters: dict) -> bool:
        """检查日志是否匹配过滤条件"""
        if not filters:
            return True

        if 'probe_id' in filters and log.get('probe_id') != filters['probe_id']:
            return False
        if 'severity' in filters and log.get('severity') not in filters['severity']:
            return False
        if 'probe_type' in filters and log.get('probe_type') != filters['probe_type']:
            return False

        return True


websocket_manager = WebSocketManager()
```

**WebSocket 路由:**

```python
# cloud/backend/app/routers/websocket.py
import uuid
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.websocket_service import websocket_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    client_id = str(uuid.uuid4())
    await websocket_manager.connect(client_id, websocket)

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")

            if action == "subscribe":
                filters = data.get("filters", {})
                await websocket_manager.subscribe(client_id, filters)
                await websocket.send_json({
                    "event": "subscribed",
                    "filters": filters
                })
            elif action == "unsubscribe":
                await websocket_manager.subscribe(client_id, {})
                await websocket.send_json({"event": "unsubscribed"})
            elif action == "ping":
                await websocket.send_json({"event": "pong"})

    except WebSocketDisconnect:
        await websocket_manager.disconnect(client_id)
```

#### 3.2.4 规则管理服务

```python
# cloud/backend/app/services/rule_service.py
import hashlib
from typing import Optional, List
from datetime import datetime
from app.services.redis_service import redis_service
from app.services.mysql_service import mysql_service


class RuleService:
    async def get_latest_version(self) -> Optional[str]:
        """获取最新规则版本号"""
        # 先查缓存
        version = await redis_service.get_latest_rule_version()
        if version:
            return version

        # 缓存未命中，查数据库
        result = await mysql_service.fetchone(
            "SELECT version FROM rule_versions WHERE is_active = TRUE ORDER BY id DESC LIMIT 1"
        )
        if result:
            version = result['version']
            await redis_service.set_latest_rule_version(version)
            return version
        return None

    async def get_rule_by_version(self, version: str) -> Optional[dict]:
        """获取指定版本规则"""
        # 先查缓存
        content = await redis_service.get_rule_content(version)
        if content:
            return {"version": version, "content": content, "checksum": self._checksum(content)}

        # 缓存未命中，查数据库
        result = await mysql_service.fetchone(
            "SELECT version, content, checksum FROM rule_versions WHERE version = %s",
            (version,)
        )
        if result:
            await redis_service.set_rule_content(version, result['content'])
            return result
        return None

    async def create_rule_version(self, content: str, description: str = "") -> dict:
        """创建新规则版本"""
        version = f"v{int(datetime.utcnow().timestamp())}"
        checksum = self._checksum(content)

        # 将之前的版本设为非活跃
        await mysql_service.execute(
            "UPDATE rule_versions SET is_active = FALSE WHERE is_active = TRUE"
        )

        # 插入新版本
        await mysql_service.execute(
            """INSERT INTO rule_versions (version, content, checksum, description, is_active)
               VALUES (%s, %s, %s, %s, TRUE)""",
            (version, content, checksum, description)
        )

        # 更新缓存
        await redis_service.set_latest_rule_version(version)
        await redis_service.set_rule_content(version, content)

        return {"version": version, "checksum": checksum}

    async def list_versions(self, limit: int = 20) -> List[dict]:
        """获取规则版本列表"""
        return await mysql_service.fetchall(
            """SELECT id, version, checksum, description, is_active, created_at
               FROM rule_versions ORDER BY id DESC LIMIT %s""",
            (limit,)
        )

    def _checksum(self, content: str) -> str:
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"


rule_service = RuleService()
```

#### 3.2.5 前端 API 路由

```python
# cloud/backend/app/routers/rules.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.services.rule_service import rule_service

router = APIRouter(prefix="/rules", tags=["rules"])


class CreateRuleRequest(BaseModel):
    content: str
    description: Optional[str] = ""


@router.get("")
async def list_rules(limit: int = 20):
    """获取规则版本列表"""
    versions = await rule_service.list_versions(limit)
    return {"versions": versions}


@router.post("")
async def create_rule(request: CreateRuleRequest):
    """创建新规则版本"""
    result = await rule_service.create_rule_version(
        content=request.content,
        description=request.description
    )
    return result


@router.get("/{version}")
async def get_rule(version: str):
    """获取指定版本规则"""
    rule = await rule_service.get_rule_by_version(version)
    if not rule:
        raise HTTPException(status_code=404, detail="规则版本不存在")
    return rule
```

```python
# cloud/backend/app/routers/logs.py
from fastapi import APIRouter, Query
from typing import Optional, List
from app.services.clickhouse_service import clickhouse_service

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("")
async def query_logs(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    probe_id: Optional[str] = None,
    severity: Optional[int] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0
):
    """查询告警日志"""
    logs = await clickhouse_service.query_logs(
        start_time=start_time,
        end_time=end_time,
        probe_id=probe_id,
        severity=severity,
        limit=limit,
        offset=offset
    )
    return {"logs": logs, "count": len(logs)}


@router.get("/stats")
async def get_stats(hours: int = Query(default=24, le=168)):
    """获取日志统计"""
    stats = await clickhouse_service.get_stats(hours)
    return {"stats": stats}
```

```python
# cloud/backend/app/routers/probes.py
from fastapi import APIRouter, HTTPException
from app.services.probe_service import probe_service

router = APIRouter(prefix="/probes", tags=["probes"])


@router.get("")
async def list_probes():
    """获取探针列表"""
    probes = await probe_service.list_probes()
    return {"probes": probes}


@router.get("/{probe_id}")
async def get_probe(probe_id: str):
    """获取探针详情"""
    probe = await probe_service.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="探针不存在")
    return probe
```

#### 3.2.6 验收标准

- [ ] `POST /api/v1/probe` cmd=30 探针注册成功
- [ ] `POST /api/v1/probe` cmd=20 心跳响应正确返回最新版本
- [ ] `POST /api/v1/probe` cmd=40 规则下载成功
- [ ] `POST /api/v1/probe` cmd=10 日志上报写入 ClickHouse
- [ ] WebSocket 连接成功并能接收实时日志
- [ ] 规则 CRUD API 正常工作
- [ ] Redis 缓存命中率正常
- [ ] 日志查询和统计 API 正常工作

---

## 4. 第三阶段：探针管理程序 (Probe Manager)

### 4.1 目标

- 实现基于 epoll 的高性能事件循环
- 实现与云端的 HTTP 通信
- 实现与探针的 TCP Socket 通信
- 实现规则下载和分发
- 实现日志聚合和批量上报

### 4.2 任务清单

#### 4.2.1 项目结构

```
probe/
├── common/                    # 公共库
│   ├── include/
│   │   ├── protocol.h         # 通信协议定义
│   │   ├── json.hpp           # nlohmann/json
│   │   └── logger.h           # 日志工具
│   └── CMakeLists.txt
├── manager/                   # Probe Manager
│   ├── include/
│   │   ├── config.h           # 配置管理
│   │   ├── epoll_server.h     # epoll 服务器
│   │   ├── probe_connection.h # 探针连接管理
│   │   ├── cloud_client.h     # 云端 HTTP 客户端
│   │   ├── rule_manager.h     # 规则管理
│   │   └── log_aggregator.h   # 日志聚合器
│   ├── src/
│   │   ├── main.cpp
│   │   ├── config.cpp
│   │   ├── epoll_server.cpp
│   │   ├── probe_connection.cpp
│   │   ├── cloud_client.cpp
│   │   ├── rule_manager.cpp
│   │   └── log_aggregator.cpp
│   └── CMakeLists.txt
└── CMakeLists.txt
```

#### 4.2.2 协议定义

```cpp
// probe/common/include/protocol.h
#pragma once

#include <cstdint>
#include <string>
#include "json.hpp"

using json = nlohmann::json;

namespace protocol {

// 消息头结构 (网络字节序)
struct MessageHeader {
    uint32_t length;  // payload 长度
};

constexpr size_t HEADER_SIZE = sizeof(MessageHeader);

// Manager -> 探针 命令
enum class Command : int {
    CMD_START = 1,
    CMD_STOP = 2,
    CMD_RELOAD_RULES = 3,
    CMD_GET_STATUS = 4,
    CMD_SHUTDOWN = 5
};

// 探针 -> Manager 事件
enum class Event : int {
    EVT_ALERT = 1,
    EVT_STATUS = 2,
    EVT_ERROR = 3,
    EVT_ACK = 4
};

// 云端通信命令码
enum class CloudCommand : int {
    LOG_UPLOAD = 10,
    LOG_UPLOAD_RESPONSE = 11,
    HEARTBEAT = 20,
    HEARTBEAT_RESPONSE = 21,
    REGISTER = 30,
    REGISTER_RESPONSE = 31,
    RULE_DOWNLOAD = 40,
    RULE_DOWNLOAD_RESPONSE = 41
};

// 序列化消息
std::vector<uint8_t> serialize(const json& msg);

// 反序列化消息
json deserialize(const uint8_t* data, size_t length);

}  // namespace protocol
```

#### 4.2.3 epoll 服务器实现

```cpp
// probe/manager/include/epoll_server.h
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <sys/epoll.h>

class ProbeConnection;

class EpollServer {
public:
    EpollServer(int port);
    ~EpollServer();

    // 启动事件循环
    void run();

    // 停止事件循环
    void stop();

    // 设置回调
    using MessageCallback = std::function<void(int fd, const json& msg)>;
    using ConnectionCallback = std::function<void(int fd)>;

    void set_message_callback(MessageCallback cb) { message_callback_ = cb; }
    void set_connect_callback(ConnectionCallback cb) { connect_callback_ = cb; }
    void set_disconnect_callback(ConnectionCallback cb) { disconnect_callback_ = cb; }

    // 发送消息到探针
    void send_to_probe(int fd, const json& msg);

    // 添加定时器
    void add_timer(int interval_ms, std::function<void()> callback);

private:
    void handle_accept();
    void handle_read(int fd);
    void handle_timer();

    void add_to_epoll(int fd, uint32_t events);
    void remove_from_epoll(int fd);

private:
    int epoll_fd_;
    int listen_fd_;
    int timer_fd_;
    bool running_;

    std::map<int, std::unique_ptr<ProbeConnection>> connections_;

    MessageCallback message_callback_;
    ConnectionCallback connect_callback_;
    ConnectionCallback disconnect_callback_;
    std::function<void()> timer_callback_;
};
```

```cpp
// probe/manager/src/epoll_server.cpp
#include "epoll_server.h"
#include "probe_connection.h"
#include "protocol.h"
#include "logger.h"

#include <sys/socket.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

constexpr int MAX_EVENTS = 64;

EpollServer::EpollServer(int port) : running_(false) {
    // 创建 epoll 实例
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        throw std::runtime_error("Failed to create epoll");
    }

    // 创建监听 socket
    listen_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listen_fd_ < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error("Failed to bind");
    }

    if (listen(listen_fd_, SOMAXCONN) < 0) {
        throw std::runtime_error("Failed to listen");
    }

    add_to_epoll(listen_fd_, EPOLLIN);
    LOG_INFO("Listening on port {}", port);
}

EpollServer::~EpollServer() {
    close(listen_fd_);
    close(epoll_fd_);
    if (timer_fd_ > 0) close(timer_fd_);
}

void EpollServer::add_timer(int interval_ms, std::function<void()> callback) {
    timer_callback_ = callback;

    timer_fd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (timer_fd_ < 0) {
        throw std::runtime_error("Failed to create timer");
    }

    itimerspec spec{};
    spec.it_interval.tv_sec = interval_ms / 1000;
    spec.it_interval.tv_nsec = (interval_ms % 1000) * 1000000;
    spec.it_value = spec.it_interval;

    timerfd_settime(timer_fd_, 0, &spec, nullptr);
    add_to_epoll(timer_fd_, EPOLLIN);
}

void EpollServer::run() {
    running_ = true;
    epoll_event events[MAX_EVENTS];

    while (running_) {
        int n = epoll_wait(epoll_fd_, events, MAX_EVENTS, -1);

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;

            if (fd == listen_fd_) {
                handle_accept();
            } else if (fd == timer_fd_) {
                handle_timer();
            } else if (events[i].events & EPOLLIN) {
                handle_read(fd);
            }
        }
    }
}

void EpollServer::stop() {
    running_ = false;
}

void EpollServer::handle_accept() {
    while (true) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);

        int fd = accept4(listen_fd_, (sockaddr*)&client_addr, &len, SOCK_NONBLOCK);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            LOG_ERROR("Accept failed: {}", strerror(errno));
            break;
        }

        connections_[fd] = std::make_unique<ProbeConnection>(fd);
        add_to_epoll(fd, EPOLLIN | EPOLLET);

        LOG_INFO("New probe connection: fd={}", fd);

        if (connect_callback_) {
            connect_callback_(fd);
        }
    }
}

void EpollServer::handle_read(int fd) {
    auto it = connections_.find(fd);
    if (it == connections_.end()) return;

    auto& conn = it->second;

    while (true) {
        auto msg = conn->read_message();
        if (!msg.has_value()) {
            if (conn->is_closed()) {
                LOG_INFO("Probe disconnected: fd={}", fd);
                if (disconnect_callback_) {
                    disconnect_callback_(fd);
                }
                remove_from_epoll(fd);
                connections_.erase(fd);
            }
            break;
        }

        if (message_callback_) {
            message_callback_(fd, msg.value());
        }
    }
}

void EpollServer::handle_timer() {
    uint64_t exp;
    read(timer_fd_, &exp, sizeof(exp));

    if (timer_callback_) {
        timer_callback_();
    }
}

void EpollServer::send_to_probe(int fd, const json& msg) {
    auto it = connections_.find(fd);
    if (it != connections_.end()) {
        it->second->send_message(msg);
    }
}

void EpollServer::add_to_epoll(int fd, uint32_t events) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev);
}

void EpollServer::remove_from_epoll(int fd) {
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
}
```

#### 4.2.4 云端 HTTP 客户端

```cpp
// probe/manager/include/cloud_client.h
#pragma once

#include <string>
#include "json.hpp"

using json = nlohmann::json;

class CloudClient {
public:
    CloudClient(const std::string& base_url);

    // 发送请求到云端
    json send_request(int cmd, const json& data);

    // 探针注册
    json register_probe(const std::string& probe_id, const std::string& name,
                        const std::string& ip, const std::vector<std::string>& types);

    // 心跳/规则检查
    json heartbeat(const std::string& probe_id, const std::string& rule_version,
                   const json& status, const json& probes);

    // 下载规则
    json download_rules(const std::string& probe_id, const std::string& version);

    // 上报日志
    json upload_logs(const std::string& probe_id, const std::vector<json>& logs);

private:
    std::string base_url_;

    // 简单的 HTTP POST 实现 (使用 libcurl 或 socket)
    std::string http_post(const std::string& url, const std::string& body);
};
```

#### 4.2.5 日志聚合器

```cpp
// probe/manager/include/log_aggregator.h
#pragma once

#include <vector>
#include <mutex>
#include <chrono>
#include "json.hpp"

using json = nlohmann::json;

class LogAggregator {
public:
    LogAggregator(size_t batch_size = 100, int flush_interval_ms = 10000);

    // 添加日志
    void add_log(const json& log);

    // 获取待上报的日志批次
    std::vector<json> flush();

    // 检查是否需要上报
    bool should_flush() const;

private:
    std::vector<json> logs_;
    mutable std::mutex mutex_;

    size_t batch_size_;
    int flush_interval_ms_;
    std::chrono::steady_clock::time_point last_flush_;
};
```

#### 4.2.6 主程序

```cpp
// probe/manager/src/main.cpp
#include "config.h"
#include "epoll_server.h"
#include "cloud_client.h"
#include "rule_manager.h"
#include "log_aggregator.h"
#include "protocol.h"
#include "logger.h"

#include <signal.h>
#include <map>

EpollServer* g_server = nullptr;

void signal_handler(int sig) {
    if (g_server) {
        g_server->stop();
    }
}

int main(int argc, char* argv[]) {
    // 加载配置
    Config config;
    config.load(argc > 1 ? argv[1] : "/etc/probe-manager/config.json");

    // 初始化组件
    CloudClient cloud(config.cloud_url);
    RuleManager rules(config.rules_dir);
    LogAggregator logs(config.log_batch_size, config.log_flush_interval);

    // 探针连接映射: fd -> probe_info
    std::map<int, json> probe_map;

    // 创建 epoll 服务器
    EpollServer server(config.listen_port);
    g_server = &server;

    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 设置消息回调
    server.set_message_callback([&](int fd, const json& msg) {
        std::string event = msg["event"];

        if (event == "EVT_ALERT") {
            // 收到告警日志，添加到聚合器
            logs.add_log(msg["data"]);
        } else if (event == "EVT_STATUS") {
            // 更新探针状态
            probe_map[fd]["status"] = msg["data"];
        } else if (event == "EVT_ACK") {
            LOG_DEBUG("Received ACK from probe fd={}", fd);
        }
    });

    // 设置连接回调
    server.set_connect_callback([&](int fd) {
        probe_map[fd] = {{"fd", fd}, {"connected_at", time(nullptr)}};
    });

    server.set_disconnect_callback([&](int fd) {
        probe_map.erase(fd);
    });

    // 设置定时器: 5分钟心跳和规则检查
    server.add_timer(config.heartbeat_interval * 1000, [&]() {
        // 发送心跳
        json status = {/* 系统状态 */};
        json probes_info = json::array();
        for (const auto& [fd, info] : probe_map) {
            probes_info.push_back(info);
        }

        auto response = cloud.heartbeat(
            config.probe_id,
            rules.current_version(),
            status,
            probes_info
        );

        // 检查是否有新规则
        if (response["data"]["status"] == "ok") {
            std::string latest = response["data"]["latest_rule_version"];
            if (latest != rules.current_version()) {
                LOG_INFO("New rule version available: {}", latest);

                // 下载新规则
                auto rule_response = cloud.download_rules(config.probe_id, latest);
                if (rule_response["data"]["status"] == "ok") {
                    rules.update(
                        rule_response["data"]["version"],
                        rule_response["data"]["content"]
                    );

                    // 通知所有探针重载规则
                    json reload_cmd = {
                        {"cmd", "CMD_RELOAD_RULES"},
                        {"data", {{"rules_path", rules.rules_path()}}}
                    };
                    for (const auto& [fd, _] : probe_map) {
                        server.send_to_probe(fd, reload_cmd);
                    }
                }
            }
        }

        // 检查并上报日志
        if (logs.should_flush()) {
            auto batch = logs.flush();
            if (!batch.empty()) {
                cloud.upload_logs(config.probe_id, batch);
            }
        }
    });

    // 向云端注册
    auto reg_response = cloud.register_probe(
        config.probe_id,
        config.probe_name,
        config.probe_ip,
        config.probe_types
    );

    if (reg_response["data"]["status"] != "ok") {
        LOG_ERROR("Failed to register probe: {}", reg_response.dump());
        return 1;
    }

    LOG_INFO("Probe registered successfully");

    // 启动事件循环
    server.run();

    return 0;
}
```

#### 4.2.7 CMake 配置

```cmake
# probe/manager/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(probe-manager CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找依赖
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

# 源文件
set(SOURCES
    src/main.cpp
    src/config.cpp
    src/epoll_server.cpp
    src/probe_connection.cpp
    src/cloud_client.cpp
    src/rule_manager.cpp
    src/log_aggregator.cpp
)

# 可执行文件
add_executable(probe-manager ${SOURCES})

target_include_directories(probe-manager PRIVATE
    include
    ${CMAKE_SOURCE_DIR}/common/include
)

target_link_libraries(probe-manager PRIVATE
    ${CURL_LIBRARIES}
    Threads::Threads
)

# 安装
install(TARGETS probe-manager DESTINATION bin)
```

#### 4.2.8 验收标准

- [ ] `probe-manager` 进程启动成功
- [ ] 成功向云端注册探针
- [ ] 5分钟定时心跳正常
- [ ] 探针可通过 TCP Socket 连接
- [ ] 规则下载和分发正常
- [ ] 日志聚合和批量上报正常

---

## 5. 第四阶段：NIDS 探针实现

### 5.1 目标

- 实现 NIDS 探针基础框架
- 实现 Suricata 进程管理 (fork/exec)
- 实现 eve.json 日志解析 (inotify)
- 实现 SIGUSR2 规则热更新
- 集成 ET Open 规则集

### 5.2 任务清单

#### 5.2.1 项目结构

```
probe/nids/
├── include/
│   ├── nids_probe.h           # 探针主类
│   ├── suricata_manager.h     # Suricata 进程管理
│   ├── eve_parser.h           # eve.json 解析
│   └── socket_client.h        # Manager 通信客户端
├── src/
│   ├── main.cpp
│   ├── nids_probe.cpp
│   ├── suricata_manager.cpp
│   ├── eve_parser.cpp
│   └── socket_client.cpp
└── CMakeLists.txt
```

#### 5.2.2 Suricata 进程管理

```cpp
// probe/nids/include/suricata_manager.h
#pragma once

#include <string>
#include <sys/types.h>

class SuricataManager {
public:
    SuricataManager(const std::string& config_path, const std::string& interface);
    ~SuricataManager();

    // 启动 Suricata
    bool start();

    // 停止 Suricata
    void stop();

    // 重载规则 (SIGUSR2)
    bool reload_rules();

    // 检查进程状态
    bool is_running() const;

    // 获取 PID
    pid_t pid() const { return pid_; }

    // 获取 eve.json 路径
    const std::string& eve_log_path() const { return eve_log_path_; }

private:
    std::string config_path_;
    std::string interface_;
    std::string eve_log_path_;
    std::string pid_file_;
    pid_t pid_;
};
```

```cpp
// probe/nids/src/suricata_manager.cpp
#include "suricata_manager.h"
#include "logger.h"

#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <fstream>

SuricataManager::SuricataManager(const std::string& config_path, const std::string& interface)
    : config_path_(config_path)
    , interface_(interface)
    , eve_log_path_("/var/log/suricata/eve.json")
    , pid_file_("/var/run/suricata.pid")
    , pid_(-1)
{
}

SuricataManager::~SuricataManager() {
    stop();
}

bool SuricataManager::start() {
    pid_ = fork();

    if (pid_ < 0) {
        LOG_ERROR("Failed to fork: {}", strerror(errno));
        return false;
    }

    if (pid_ == 0) {
        // 子进程: 执行 Suricata
        const char* args[] = {
            "suricata",
            "-c", config_path_.c_str(),
            "-i", interface_.c_str(),
            "--pidfile", pid_file_.c_str(),
            "-D",  // daemon 模式
            nullptr
        };

        execvp("suricata", const_cast<char**>(args));

        // execvp 失败
        LOG_ERROR("Failed to exec suricata: {}", strerror(errno));
        _exit(1);
    }

    // 父进程: 等待 Suricata 启动
    sleep(2);

    if (is_running()) {
        LOG_INFO("Suricata started with PID {}", pid_);
        return true;
    }

    return false;
}

void SuricataManager::stop() {
    if (pid_ > 0 && is_running()) {
        kill(pid_, SIGTERM);

        // 等待进程退出
        int status;
        waitpid(pid_, &status, 0);

        LOG_INFO("Suricata stopped");
        pid_ = -1;
    }
}

bool SuricataManager::reload_rules() {
    if (!is_running()) {
        LOG_ERROR("Suricata is not running");
        return false;
    }

    if (kill(pid_, SIGUSR2) == 0) {
        LOG_INFO("Sent SIGUSR2 to Suricata (PID {})", pid_);
        return true;
    }

    LOG_ERROR("Failed to send SIGUSR2: {}", strerror(errno));
    return false;
}

bool SuricataManager::is_running() const {
    if (pid_ <= 0) return false;
    return kill(pid_, 0) == 0;
}
```

#### 5.2.3 eve.json 解析器

```cpp
// probe/nids/include/eve_parser.h
#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include "json.hpp"

using json = nlohmann::json;

class EveParser {
public:
    using AlertCallback = std::function<void(const json& alert)>;

    EveParser(const std::string& eve_path);
    ~EveParser();

    // 设置告警回调
    void set_alert_callback(AlertCallback cb) { alert_callback_ = cb; }

    // 开始监听
    void start();

    // 停止监听
    void stop();

private:
    void watch_loop();
    void process_line(const std::string& line);

private:
    std::string eve_path_;
    std::atomic<bool> running_;
    std::thread watch_thread_;
    AlertCallback alert_callback_;

    int inotify_fd_;
    int watch_fd_;
    std::streampos file_pos_;
};
```

```cpp
// probe/nids/src/eve_parser.cpp
#include "eve_parser.h"
#include "logger.h"

#include <sys/inotify.h>
#include <unistd.h>
#include <fstream>

constexpr size_t EVENT_BUF_SIZE = 4096;

EveParser::EveParser(const std::string& eve_path)
    : eve_path_(eve_path)
    , running_(false)
    , inotify_fd_(-1)
    , watch_fd_(-1)
    , file_pos_(0)
{
}

EveParser::~EveParser() {
    stop();
}

void EveParser::start() {
    // 初始化 inotify
    inotify_fd_ = inotify_init1(IN_NONBLOCK);
    if (inotify_fd_ < 0) {
        throw std::runtime_error("Failed to init inotify");
    }

    watch_fd_ = inotify_add_watch(inotify_fd_, eve_path_.c_str(), IN_MODIFY);
    if (watch_fd_ < 0) {
        throw std::runtime_error("Failed to add watch");
    }

    // 定位到文件末尾
    std::ifstream file(eve_path_);
    if (file) {
        file.seekg(0, std::ios::end);
        file_pos_ = file.tellg();
    }

    running_ = true;
    watch_thread_ = std::thread(&EveParser::watch_loop, this);

    LOG_INFO("Started watching {}", eve_path_);
}

void EveParser::stop() {
    running_ = false;

    if (watch_thread_.joinable()) {
        watch_thread_.join();
    }

    if (watch_fd_ >= 0) {
        inotify_rm_watch(inotify_fd_, watch_fd_);
    }
    if (inotify_fd_ >= 0) {
        close(inotify_fd_);
    }
}

void EveParser::watch_loop() {
    char event_buf[EVENT_BUF_SIZE];

    while (running_) {
        int len = read(inotify_fd_, event_buf, EVENT_BUF_SIZE);

        if (len > 0) {
            // 文件有更新，读取新内容
            std::ifstream file(eve_path_);
            if (file) {
                file.seekg(file_pos_);

                std::string line;
                while (std::getline(file, line)) {
                    if (!line.empty()) {
                        process_line(line);
                    }
                }

                file_pos_ = file.tellg();
            }
        }

        // 短暂休眠避免 CPU 空转
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void EveParser::process_line(const std::string& line) {
    try {
        json event = json::parse(line);

        // 只处理 alert 类型的事件
        if (event.contains("event_type") && event["event_type"] == "alert") {
            if (alert_callback_) {
                alert_callback_(event);
            }
        }
    } catch (const json::exception& e) {
        LOG_WARN("Failed to parse eve.json line: {}", e.what());
    }
}
```

#### 5.2.4 NIDS 探针主类

```cpp
// probe/nids/include/nids_probe.h
#pragma once

#include "suricata_manager.h"
#include "eve_parser.h"
#include "socket_client.h"
#include "json.hpp"

using json = nlohmann::json;

class NidsProbe {
public:
    NidsProbe(const std::string& manager_host, int manager_port,
              const std::string& interface, const std::string& config_path);
    ~NidsProbe();

    // 启动探针
    void start();

    // 停止探针
    void stop();

    // 处理 Manager 命令
    void handle_command(const json& cmd);

private:
    void on_alert(const json& alert);
    void send_alert(const json& alert);
    void send_status();

private:
    std::string probe_id_;
    std::string interface_;

    std::unique_ptr<SuricataManager> suricata_;
    std::unique_ptr<EveParser> eve_parser_;
    std::unique_ptr<SocketClient> manager_client_;

    bool running_;
};
```

```cpp
// probe/nids/src/nids_probe.cpp
#include "nids_probe.h"
#include "protocol.h"
#include "logger.h"

NidsProbe::NidsProbe(const std::string& manager_host, int manager_port,
                     const std::string& interface, const std::string& config_path)
    : interface_(interface)
    , running_(false)
{
    probe_id_ = "nids-" + interface;

    suricata_ = std::make_unique<SuricataManager>(config_path, interface);
    manager_client_ = std::make_unique<SocketClient>(manager_host, manager_port);
}

NidsProbe::~NidsProbe() {
    stop();
}

void NidsProbe::start() {
    // 连接 Manager
    if (!manager_client_->connect()) {
        throw std::runtime_error("Failed to connect to manager");
    }

    // 启动 Suricata
    if (!suricata_->start()) {
        throw std::runtime_error("Failed to start Suricata");
    }

    // 启动 eve.json 监听
    eve_parser_ = std::make_unique<EveParser>(suricata_->eve_log_path());
    eve_parser_->set_alert_callback([this](const json& alert) {
        on_alert(alert);
    });
    eve_parser_->start();

    // 设置命令处理回调
    manager_client_->set_message_callback([this](const json& msg) {
        handle_command(msg);
    });

    running_ = true;
    LOG_INFO("NIDS probe started on interface {}", interface_);

    // 主循环
    while (running_) {
        manager_client_->poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void NidsProbe::stop() {
    running_ = false;

    if (eve_parser_) {
        eve_parser_->stop();
    }

    if (suricata_) {
        suricata_->stop();
    }

    if (manager_client_) {
        manager_client_->disconnect();
    }
}

void NidsProbe::handle_command(const json& cmd) {
    std::string command = cmd["cmd"];

    if (command == "CMD_RELOAD_RULES") {
        LOG_INFO("Reloading rules...");
        bool success = suricata_->reload_rules();

        // 发送 ACK
        json ack = {
            {"event", "EVT_ACK"},
            {"probe_id", probe_id_},
            {"data", {{"success", success}, {"cmd", command}}}
        };
        manager_client_->send(ack);

    } else if (command == "CMD_GET_STATUS") {
        send_status();

    } else if (command == "CMD_STOP") {
        suricata_->stop();

    } else if (command == "CMD_SHUTDOWN") {
        stop();
    }
}

void NidsProbe::on_alert(const json& alert) {
    // 转换为标准格式并发送
    json log = {
        {"probe_type", "nids"},
        {"instance_id", probe_id_},
        {"timestamp", alert.value("timestamp", "")},
        {"src_ip", alert.value("src_ip", "")},
        {"dest_ip", alert.value("dest_ip", "")},
        {"src_port", alert.value("src_port", 0)},
        {"dest_port", alert.value("dest_port", 0)},
        {"protocol", alert.value("proto", "")},
        {"alert", {
            {"signature", alert["alert"].value("signature", "")},
            {"signature_id", alert["alert"].value("signature_id", 0)},
            {"severity", alert["alert"].value("severity", 0)},
            {"category", alert["alert"].value("category", "")}
        }},
        {"raw", alert.dump()}
    };

    send_alert(log);
}

void NidsProbe::send_alert(const json& alert) {
    json msg = {
        {"event", "EVT_ALERT"},
        {"probe_type", "nids"},
        {"probe_id", probe_id_},
        {"data", alert}
    };
    manager_client_->send(msg);
}

void NidsProbe::send_status() {
    json status = {
        {"event", "EVT_STATUS"},
        {"probe_id", probe_id_},
        {"data", {
            {"running", suricata_->is_running()},
            {"interface", interface_},
            {"suricata_pid", suricata_->pid()}
        }}
    };
    manager_client_->send(status);
}
```

#### 5.2.5 主程序

```cpp
// probe/nids/src/main.cpp
#include "nids_probe.h"
#include "logger.h"

#include <signal.h>
#include <getopt.h>

NidsProbe* g_probe = nullptr;

void signal_handler(int sig) {
    if (g_probe) {
        g_probe->stop();
    }
}

void print_usage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -m, --manager <host:port>  Manager address (default: localhost:9000)\n");
    printf("  -i, --interface <name>     Network interface to monitor\n");
    printf("  -c, --config <path>        Suricata config file\n");
    printf("  -h, --help                 Show this help\n");
}

int main(int argc, char* argv[]) {
    std::string manager_host = "localhost";
    int manager_port = 9000;
    std::string interface = "eth0";
    std::string config_path = "/etc/suricata/suricata.yaml";

    static struct option long_options[] = {
        {"manager", required_argument, 0, 'm'},
        {"interface", required_argument, 0, 'i'},
        {"config", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:i:c:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'm': {
                std::string addr = optarg;
                auto pos = addr.find(':');
                if (pos != std::string::npos) {
                    manager_host = addr.substr(0, pos);
                    manager_port = std::stoi(addr.substr(pos + 1));
                }
                break;
            }
            case 'i':
                interface = optarg;
                break;
            case 'c':
                config_path = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    LOG_INFO("Starting NIDS probe...");
    LOG_INFO("  Manager: {}:{}", manager_host, manager_port);
    LOG_INFO("  Interface: {}", interface);
    LOG_INFO("  Config: {}", config_path);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    try {
        NidsProbe probe(manager_host, manager_port, interface, config_path);
        g_probe = &probe;
        probe.start();
    } catch (const std::exception& e) {
        LOG_ERROR("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}
```

#### 5.2.6 ET Open 规则集成

```bash
# scripts/download-et-rules.sh
#!/bin/bash

RULES_DIR="/var/lib/nids/rules"
ET_RULES_URL="https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"

mkdir -p "$RULES_DIR"
cd "$RULES_DIR"

# 下载规则
curl -L -o emerging.rules.tar.gz "$ET_RULES_URL"

# 解压
tar xzf emerging.rules.tar.gz

# 合并所有规则到单个文件
cat rules/*.rules > suricata.rules

echo "ET Open rules downloaded to $RULES_DIR/suricata.rules"
```

#### 5.2.7 验收标准

- [ ] `nids-probe` 进程启动成功
- [ ] Suricata 子进程正常运行
- [ ] 成功连接到 Probe Manager
- [ ] eve.json 日志实时解析
- [ ] 告警日志正确发送到 Manager
- [ ] SIGUSR2 规则热更新正常
- [ ] ET Open 规则正常加载

---

## 6. 第五阶段：云端前端实现

### 6.1 目标

- 实现规则管理页面
- 实现日志实时展示页面 (WebSocket)
- 实现探针管理页面
- 实现统计分析页面

### 6.2 任务清单

#### 6.2.1 页面结构

```
src/
├── pages/
│   ├── Dashboard/           # 仪表盘
│   │   └── index.tsx
│   ├── Rules/               # 规则管理
│   │   ├── index.tsx        # 规则列表
│   │   ├── RuleEditor.tsx   # 规则编辑器
│   │   └── VersionHistory.tsx
│   ├── Logs/                # 日志展示
│   │   ├── index.tsx        # 实时日志
│   │   ├── LogTable.tsx     # 日志表格
│   │   └── LogStats.tsx     # 统计图表
│   └── Probes/              # 探针管理
│       ├── index.tsx        # 探针列表
│       └── ProbeDetail.tsx  # 探针详情
├── components/
│   ├── Layout/
│   ├── Sidebar/
│   └── common/
├── hooks/
│   ├── useWebSocket.ts      # WebSocket 钩子
│   └── useApi.ts            # API 钩子
├── services/
│   └── api.ts               # API 服务
└── store/
    └── index.ts             # Zustand 状态管理
```

#### 6.2.2 WebSocket 钩子

```typescript
// src/hooks/useWebSocket.ts
import { useEffect, useRef, useCallback, useState } from 'react'

interface WebSocketOptions {
  url: string
  onMessage?: (data: any) => void
  onConnect?: () => void
  onDisconnect?: () => void
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

export function useWebSocket(options: WebSocketOptions) {
  const {
    url,
    onMessage,
    onConnect,
    onDisconnect,
    reconnectInterval = 1000,
    maxReconnectAttempts = 10
  } = options

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttempts = useRef(0)
  const [isConnected, setIsConnected] = useState(false)

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url)

      ws.onopen = () => {
        setIsConnected(true)
        reconnectAttempts.current = 0
        onConnect?.()
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          onMessage?.(data)
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e)
        }
      }

      ws.onclose = () => {
        setIsConnected(false)
        onDisconnect?.()

        // 自动重连
        if (reconnectAttempts.current < maxReconnectAttempts) {
          const delay = Math.min(
            reconnectInterval * Math.pow(2, reconnectAttempts.current),
            30000
          )
          reconnectAttempts.current++
          setTimeout(connect, delay)
        }
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      wsRef.current = ws
    } catch (e) {
      console.error('Failed to create WebSocket:', e)
    }
  }, [url, onMessage, onConnect, onDisconnect, reconnectInterval, maxReconnectAttempts])

  const send = useCallback((data: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  const subscribe = useCallback((filters: any = {}) => {
    send({ action: 'subscribe', filters })
  }, [send])

  const unsubscribe = useCallback(() => {
    send({ action: 'unsubscribe' })
  }, [send])

  useEffect(() => {
    connect()

    return () => {
      wsRef.current?.close()
    }
  }, [connect])

  // 心跳保活
  useEffect(() => {
    const interval = setInterval(() => {
      if (isConnected) {
        send({ action: 'ping' })
      }
    }, 30000)

    return () => clearInterval(interval)
  }, [isConnected, send])

  return {
    isConnected,
    send,
    subscribe,
    unsubscribe
  }
}
```

#### 6.2.3 实时日志页面

```tsx
// src/pages/Logs/index.tsx
import { useState, useCallback } from 'react'
import { useWebSocket } from '@/hooks/useWebSocket'
import LogTable from './LogTable'
import LogStats from './LogStats'

interface LogEntry {
  id: string
  probe_id: string
  probe_type: string
  timestamp: string
  src_ip: string
  dest_ip: string
  src_port: number
  dest_port: number
  protocol: string
  alert_msg: string
  signature_id: number
  severity: number
}

interface LogFilters {
  probe_id?: string
  severity?: number[]
  probe_type?: string
}

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [filters, setFilters] = useState<LogFilters>({})
  const [isPaused, setIsPaused] = useState(false)

  const handleMessage = useCallback((data: any) => {
    if (data.event === 'log' && !isPaused) {
      setLogs(prev => [data.data, ...prev].slice(0, 1000)) // 保留最新1000条
    }
  }, [isPaused])

  const { isConnected, subscribe } = useWebSocket({
    url: `ws://${window.location.host}/api/v1/ws/logs`,
    onMessage: handleMessage,
    onConnect: () => {
      subscribe(filters)
    }
  })

  const handleFilterChange = (newFilters: LogFilters) => {
    setFilters(newFilters)
    subscribe(newFilters)
  }

  const getSeverityColor = (severity: number) => {
    switch (severity) {
      case 1: return 'bg-red-500'
      case 2: return 'bg-orange-500'
      case 3: return 'bg-yellow-500'
      default: return 'bg-gray-500'
    }
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">实时日志</h1>
        <div className="flex items-center gap-4">
          <span className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span>{isConnected ? '已连接' : '未连接'}</span>
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`px-4 py-2 rounded ${isPaused ? 'bg-green-500' : 'bg-yellow-500'} text-white`}
          >
            {isPaused ? '继续' : '暂停'}
          </button>
          <button
            onClick={() => setLogs([])}
            className="px-4 py-2 rounded bg-gray-500 text-white"
          >
            清空
          </button>
        </div>
      </div>

      {/* 过滤器 */}
      <div className="mb-4 flex gap-4">
        <select
          className="border rounded px-3 py-2"
          onChange={(e) => handleFilterChange({ ...filters, severity: e.target.value ? [parseInt(e.target.value)] : undefined })}
        >
          <option value="">所有级别</option>
          <option value="1">严重 (1)</option>
          <option value="2">高 (2)</option>
          <option value="3">中 (3)</option>
        </select>
        <input
          type="text"
          placeholder="探针 ID"
          className="border rounded px-3 py-2"
          onChange={(e) => handleFilterChange({ ...filters, probe_id: e.target.value || undefined })}
        />
      </div>

      {/* 日志表格 */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left">级别</th>
              <th className="px-4 py-3 text-left">时间</th>
              <th className="px-4 py-3 text-left">探针</th>
              <th className="px-4 py-3 text-left">源 IP</th>
              <th className="px-4 py-3 text-left">目标 IP</th>
              <th className="px-4 py-3 text-left">告警信息</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {logs.map((log) => (
              <tr key={log.id} className="hover:bg-gray-50">
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-white text-sm ${getSeverityColor(log.severity)}`}>
                    {log.severity}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-gray-500">
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-3">{log.probe_id}</td>
                <td className="px-4 py-3 font-mono">{log.src_ip}:{log.src_port}</td>
                <td className="px-4 py-3 font-mono">{log.dest_ip}:{log.dest_port}</td>
                <td className="px-4 py-3 truncate max-w-md">{log.alert_msg}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
```

#### 6.2.4 规则管理页面

```tsx
// src/pages/Rules/index.tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '@/services/api'

export default function RulesPage() {
  const [content, setContent] = useState('')
  const [description, setDescription] = useState('')
  const queryClient = useQueryClient()

  const { data: rules, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: () => rulesApi.list()
  })

  const createMutation = useMutation({
    mutationFn: (data: { content: string; description: string }) =>
      rulesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      setContent('')
      setDescription('')
    }
  })

  const handleCreate = () => {
    if (content.trim()) {
      createMutation.mutate({ content, description })
    }
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">规则管理</h1>

      {/* 创建新规则 */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h2 className="text-lg font-semibold mb-4">创建新版本</h2>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">描述</label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full border rounded px-3 py-2"
            placeholder="版本描述..."
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">规则内容</label>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="w-full border rounded px-3 py-2 font-mono text-sm"
            rows={10}
            placeholder="# Suricata Rules..."
          />
        </div>
        <button
          onClick={handleCreate}
          disabled={createMutation.isPending}
          className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
        >
          {createMutation.isPending ? '创建中...' : '创建新版本'}
        </button>
      </div>

      {/* 版本列表 */}
      <div className="bg-white rounded-lg shadow">
        <h2 className="text-lg font-semibold p-6 border-b">版本历史</h2>
        {isLoading ? (
          <div className="p-6">加载中...</div>
        ) : (
          <table className="min-w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left">版本</th>
                <th className="px-6 py-3 text-left">描述</th>
                <th className="px-6 py-3 text-left">状态</th>
                <th className="px-6 py-3 text-left">创建时间</th>
                <th className="px-6 py-3 text-left">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {rules?.versions?.map((rule: any) => (
                <tr key={rule.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 font-mono">{rule.version}</td>
                  <td className="px-6 py-4">{rule.description || '-'}</td>
                  <td className="px-6 py-4">
                    {rule.is_active ? (
                      <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-sm">
                        当前
                      </span>
                    ) : (
                      <span className="px-2 py-1 bg-gray-100 text-gray-600 rounded text-sm">
                        历史
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500">
                    {new Date(rule.created_at).toLocaleString()}
                  </td>
                  <td className="px-6 py-4">
                    <button className="text-blue-500 hover:underline">
                      查看
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
```

#### 6.2.5 探针管理页面

```tsx
// src/pages/Probes/index.tsx
import { useQuery } from '@tanstack/react-query'
import { probesApi } from '@/services/api'
import { formatDistanceToNow } from 'date-fns'
import { zhCN } from 'date-fns/locale'

export default function ProbesPage() {
  const { data: probes, isLoading } = useQuery({
    queryKey: ['probes'],
    queryFn: () => probesApi.list(),
    refetchInterval: 30000 // 30秒刷新一次
  })

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'bg-green-500'
      case 'offline': return 'bg-red-500'
      default: return 'bg-gray-500'
    }
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">探针管理</h1>

      {isLoading ? (
        <div>加载中...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {probes?.probes?.map((probe: any) => (
            <div key={probe.node_id} className="bg-white rounded-lg shadow p-6">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="text-lg font-semibold">{probe.name}</h3>
                  <p className="text-sm text-gray-500">{probe.node_id}</p>
                </div>
                <span className={`w-3 h-3 rounded-full ${getStatusColor(probe.status)}`} />
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">IP 地址</span>
                  <span className="font-mono">{probe.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">规则版本</span>
                  <span className="font-mono">{probe.current_rule_version || '-'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">最后心跳</span>
                  <span>
                    {probe.last_seen
                      ? formatDistanceToNow(new Date(probe.last_seen), { addSuffix: true, locale: zhCN })
                      : '-'
                    }
                  </span>
                </div>
              </div>

              {/* 探针实例列表 */}
              {probe.instances?.length > 0 && (
                <div className="mt-4 pt-4 border-t">
                  <h4 className="text-sm font-medium mb-2">探针实例</h4>
                  {probe.instances.map((instance: any) => (
                    <div key={instance.instance_id} className="flex items-center gap-2 text-sm">
                      <span className={`w-2 h-2 rounded-full ${getStatusColor(instance.status)}`} />
                      <span>{instance.probe_type}</span>
                      <span className="text-gray-500">({instance.interface})</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
```

#### 6.2.6 API 服务

```typescript
// src/services/api.ts
import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10000
})

export const rulesApi = {
  list: async () => {
    const { data } = await api.get('/rules')
    return data
  },

  get: async (version: string) => {
    const { data } = await api.get(`/rules/${version}`)
    return data
  },

  create: async (payload: { content: string; description: string }) => {
    const { data } = await api.post('/rules', payload)
    return data
  }
}

export const logsApi = {
  query: async (params: {
    start_time?: string
    end_time?: string
    probe_id?: string
    severity?: number
    limit?: number
    offset?: number
  }) => {
    const { data } = await api.get('/logs', { params })
    return data
  },

  stats: async (hours: number = 24) => {
    const { data } = await api.get('/logs/stats', { params: { hours } })
    return data
  }
}

export const probesApi = {
  list: async () => {
    const { data } = await api.get('/probes')
    return data
  },

  get: async (probeId: string) => {
    const { data } = await api.get(`/probes/${probeId}`)
    return data
  }
}
```

#### 6.2.7 验收标准

- [ ] 规则管理页面：列表、创建、查看功能正常
- [ ] 日志页面：WebSocket 实时接收并展示日志
- [ ] 日志页面：过滤功能正常工作
- [ ] 日志页面：暂停/继续、清空功能正常
- [ ] 探针页面：探针列表正确展示
- [ ] 探针页面：在线状态实时更新
- [ ] 统计图表：数据展示正确

---

## 7. 第六阶段：集成测试与优化

### 7.1 目标

- 完成端到端集成测试
- 性能测试和优化
- 文档完善

### 7.2 任务清单

#### 7.2.1 集成测试场景

| 场景 | 测试步骤 | 预期结果 |
|:-----|:---------|:---------|
| 探针注册 | 启动 Probe Manager → 连接云端 | 云端显示新探针 |
| 规则下发 | 云端创建新规则 → 等待5分钟 | 探针收到新规则并热更新 |
| 日志上报 | 触发网络告警 → 观察日志 | 前端实时显示告警 |
| 断线重连 | 断开网络 → 恢复 | 自动重连成功 |
| 规则热更新 | 更新规则 → 不重启 Suricata | 新规则生效 |

#### 7.2.2 性能测试

```bash
# 日志写入性能测试
# 目标: 1000 条/秒 写入 ClickHouse
python scripts/perf_test_logs.py --rate 1000 --duration 60

# WebSocket 推送性能测试
# 目标: 支持 100 个并发 WebSocket 连接
python scripts/perf_test_ws.py --connections 100 --rate 100

# 探针连接性能测试
# 目标: 单 Manager 支持 10 个探针连接
./scripts/perf_test_probes.sh --probes 10
```

#### 7.2.3 监控指标

| 指标 | 告警阈值 | 监控方式 |
|:-----|:---------|:---------|
| API 响应时间 | > 500ms | Prometheus |
| 日志写入延迟 | > 1s | ClickHouse metrics |
| WebSocket 连接数 | > 1000 | Application metrics |
| Redis 内存使用 | > 80% | Redis INFO |
| MySQL 连接池 | > 90% | MySQL status |

#### 7.2.4 验收标准

- [ ] 所有集成测试场景通过
- [ ] 性能指标达标
- [ ] 无内存泄漏
- [ ] 错误处理完善
- [ ] 日志记录完整

---

## 附录 A：文件清单

```
ai-idps/
├── cloud/
│   ├── backend/
│   │   ├── app/
│   │   │   ├── __init__.py
│   │   │   ├── main.py
│   │   │   ├── config.py
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   └── probe_protocol.py
│   │   │   ├── routers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── probe.py
│   │   │   │   ├── rules.py
│   │   │   │   ├── logs.py
│   │   │   │   ├── probes.py
│   │   │   │   └── websocket.py
│   │   │   └── services/
│   │   │       ├── __init__.py
│   │   │       ├── redis_service.py
│   │   │       ├── mysql_service.py
│   │   │       ├── clickhouse_service.py
│   │   │       ├── probe_service.py
│   │   │       ├── rule_service.py
│   │   │       ├── log_service.py
│   │   │       └── websocket_service.py
│   │   ├── pyproject.toml
│   │   ├── Dockerfile
│   │   └── .env.example
│   ├── frontend/
│   │   ├── src/
│   │   │   ├── main.tsx
│   │   │   ├── App.tsx
│   │   │   ├── index.css
│   │   │   ├── pages/
│   │   │   │   ├── Dashboard/
│   │   │   │   ├── Rules/
│   │   │   │   ├── Logs/
│   │   │   │   └── Probes/
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   │   ├── useWebSocket.ts
│   │   │   │   └── useApi.ts
│   │   │   ├── services/
│   │   │   │   └── api.ts
│   │   │   └── store/
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── vite.config.ts
│   │   ├── tailwind.config.js
│   │   └── Dockerfile
│   ├── nginx/
│   │   └── nginx.conf
│   ├── mysql/
│   │   └── init.sql
│   ├── clickhouse/
│   │   └── init.sql
│   └── docker-compose.yml
├── probe/
│   ├── common/
│   │   ├── include/
│   │   │   ├── protocol.h
│   │   │   ├── json.hpp
│   │   │   └── logger.h
│   │   ├── src/
│   │   │   └── protocol.cpp
│   │   └── CMakeLists.txt
│   ├── manager/
│   │   ├── include/
│   │   │   ├── config.h
│   │   │   ├── epoll_server.h
│   │   │   ├── probe_connection.h
│   │   │   ├── cloud_client.h
│   │   │   ├── rule_manager.h
│   │   │   └── log_aggregator.h
│   │   ├── src/
│   │   │   ├── main.cpp
│   │   │   ├── config.cpp
│   │   │   ├── epoll_server.cpp
│   │   │   ├── probe_connection.cpp
│   │   │   ├── cloud_client.cpp
│   │   │   ├── rule_manager.cpp
│   │   │   └── log_aggregator.cpp
│   │   └── CMakeLists.txt
│   ├── nids/
│   │   ├── include/
│   │   │   ├── nids_probe.h
│   │   │   ├── suricata_manager.h
│   │   │   ├── eve_parser.h
│   │   │   └── socket_client.h
│   │   ├── src/
│   │   │   ├── main.cpp
│   │   │   ├── nids_probe.cpp
│   │   │   ├── suricata_manager.cpp
│   │   │   ├── eve_parser.cpp
│   │   │   └── socket_client.cpp
│   │   └── CMakeLists.txt
│   └── CMakeLists.txt
├── third_party/
│   └── suricata/              # Git Submodule
├── rules/
│   └── et-open/
├── scripts/
│   ├── download-et-rules.sh
│   └── perf_test_*.py
├── specs/
│   ├── 0001-spec.md
│   └── 0002-implementation-plan.md
├── .gitignore
├── .gitmodules
└── README.md
```

---

## 附录 B：依赖版本

### 云端后端 (Python)

| 依赖 | 版本 |
|:-----|:-----|
| Python | >= 3.11 |
| FastAPI | >= 0.109.0 |
| uvicorn | >= 0.27.0 |
| redis | >= 5.0.0 |
| aiomysql | >= 0.2.0 |
| clickhouse-connect | >= 0.7.0 |
| pydantic | >= 2.5.0 |
| websockets | >= 12.0 |

### 云端前端 (TypeScript)

| 依赖 | 版本 |
|:-----|:-----|
| Node.js | >= 18.0 |
| React | >= 18.2.0 |
| TypeScript | >= 5.3.0 |
| Vite | >= 5.0.0 |
| TailwindCSS | >= 3.4.0 |
| @tanstack/react-query | >= 5.17.0 |

### 探针端 (C++)

| 依赖 | 版本 |
|:-----|:-----|
| GCC/Clang | >= 11 (C++17) |
| CMake | >= 3.16 |
| libcurl | >= 7.0 |
| nlohmann/json | >= 3.11 |

### 基础设施

| 组件 | 版本 |
|:-----|:-----|
| Docker | >= 24.0 |
| Docker Compose | >= 2.20 |
| Redis | >= 7.0 |
| MySQL | >= 8.0 |
| ClickHouse | >= 23.0 |
| Nginx | >= 1.25 |
| Suricata | >= 7.0 |
