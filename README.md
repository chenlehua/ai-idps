# AI-IDPS (网络入侵检测系统)

本仓库为网络入侵检测系统的开发项目，包含云端服务与探针端的完整框架。

## 目录结构

```
ai-idps/
├── cloud/                    # 云端服务
│   ├── backend/              # FastAPI 后端
│   │   ├── app/
│   │   │   ├── main.py       # 应用入口
│   │   │   ├── config.py     # 配置管理
│   │   │   ├── models/       # 数据模型
│   │   │   ├── routers/      # API 路由
│   │   │   └── services/     # 业务服务
│   │   ├── Dockerfile
│   │   └── pyproject.toml
│   ├── frontend/             # React 前端
│   ├── nginx/                # Nginx 配置
│   ├── mysql/                # MySQL 初始化脚本
│   ├── clickhouse/           # ClickHouse 初始化脚本
│   ├── docker-compose.yml
│   └── Makefile              # Docker 管理命令
├── probe/                    # 探针端
│   ├── common/               # 公共库
│   └── manager/              # Probe Manager
├── rules/                    # 规则集目录
│   └── et-open/              # ET Open 规则
├── third_party/              # 第三方依赖
│   └── suricata/             # Suricata 子模块
├── specs/                    # 需求与实现计划
│   ├── 0001-spec.md          # 系统设计文档
│   └── 0002-implementation-plan.md  # 实现计划
├── scripts/                  # 脚本工具
└── Makefile                  # 项目管理命令
```

## 快速开始

### 前置要求

- Docker >= 24.0
- Docker Compose >= 2.20
- Make

### 启动云端服务

1. **构建并启动所有服务**

```bash
# 方式一：使用 Makefile（推荐）
make build    # 构建所有服务
make up       # 启动所有服务

# 方式二：直接使用 docker compose
docker compose -f cloud/docker-compose.yml up --build -d
```

2. **验证服务状态**

```bash
# 查看所有服务状态
make list

# 访问健康检查
curl http://localhost/health
# 返回: {"status":"ok"}
```

3. **访问服务**

- 前端界面: http://localhost/
- API 文档: http://localhost/docs (FastAPI Swagger UI)
- 健康检查: http://localhost/health

### 服务管理命令

```bash
# 构建服务
make build                    # 构建所有服务
make build SERVICE=backend    # 只构建后端

# 重新构建（无缓存）
make rebuild                  # 重新构建所有服务
make rebuild SERVICE=frontend # 重新构建前端

# 启动/停止服务
make up                       # 启动所有服务
make up SERVICE=backend       # 只启动后端
make down                     # 停止所有服务
make down SERVICE=mysql       # 停止 MySQL

# 重启服务
make restart                  # 重启所有服务
make restart SERVICE=backend  # 重启后端

# 查看日志
make logs                     # 查看所有服务日志
make logs SERVICE=backend     # 查看后端日志

# 查看服务状态
make list                     # 查看所有服务状态
```

## API 接口

### 探针通信接口

统一入口: `POST /api/v1/probe`

| cmd | 说明 | 请求数据 |
|:----|:-----|:---------|
| 30 | 探针注册 | `{probe_id, name, ip, probe_types}` |
| 20 | 心跳/规则检查 | `{probe_id, rule_version, status, probes}` |
| 40 | 规则下载 | `{probe_id, version}` |
| 10 | 日志上报 | `{probe_id, logs[]}` |

### 前端 API 接口

| 接口 | 方法 | 说明 |
|:-----|:-----|:-----|
| `/api/v1/probes` | GET | 获取探针列表 |
| `/api/v1/probes/{probe_id}` | GET | 获取探针详情 |
| `/api/v1/rules` | GET | 获取规则列表 |
| `/api/v1/rules` | POST | 创建新规则版本 |
| `/api/v1/rules/{version}` | GET | 获取指定版本规则 |
| `/api/v1/logs` | GET | 查询告警日志 |
| `/api/v1/logs/stats` | GET | 日志统计分析 |

### WebSocket 接口

- 实时日志: `ws://localhost/api/v1/ws/logs`

```javascript
// 订阅日志
ws.send(JSON.stringify({
  action: "subscribe",
  filters: {
    probe_id: "probe-001",   // 可选
    severity: [1, 2],        // 可选
    probe_type: "nids"       // 可选
  }
}));

// 接收日志
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.event === "log") {
    console.log("收到日志:", data.data);
  }
};
```

## 开发进度

### 已完成

- [x] **Phase 1**: 环境搭建与基础框架
  - Docker Compose 配置
  - 后端 FastAPI 框架
  - 前端 Vite + React 框架
  - 数据库初始化脚本 (MySQL, ClickHouse)

- [x] **Phase 2**: 云端后端核心功能
  - 探针通信协议实现 (cmd + data)
  - 规则管理 CRUD
  - 日志接收和存储 (ClickHouse)
  - WebSocket 实时推送
  - Redis 缓存层

### 待完成

- [ ] **Phase 3**: 探针管理程序 (Probe Manager)
- [ ] **Phase 4**: NIDS 探针实现
- [ ] **Phase 5**: 云端前端实现
- [ ] **Phase 6**: 集成测试与优化

## 技术栈

| 组件 | 技术 |
|:-----|:-----|
| 云端后端 | Python 3.11 / FastAPI / UV |
| 云端前端 | TypeScript / Vite / React / TailwindCSS |
| 缓存 | Redis 7 |
| 元数据库 | MySQL 8.0 |
| 日志存储 | ClickHouse |
| 反向代理 | Nginx |
| 容器化 | Docker / Docker Compose |
| 探针端 | C++ / CMake / epoll |
| NIDS 引擎 | Suricata (GPL) |

## 配置说明

### 环境变量

后端服务支持以下环境变量配置：

| 变量 | 默认值 | 说明 |
|:-----|:-------|:-----|
| `REDIS_URL` | `redis://localhost:6379` | Redis 连接地址 |
| `MYSQL_HOST` | `localhost` | MySQL 主机 |
| `MYSQL_PORT` | `3306` | MySQL 端口 |
| `MYSQL_USER` | `root` | MySQL 用户 |
| `MYSQL_PASSWORD` | `password` | MySQL 密码 |
| `MYSQL_DATABASE` | `nids` | MySQL 数据库 |
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse 主机 |
| `CLICKHOUSE_PORT` | `8123` | ClickHouse HTTP 端口 |
| `CLICKHOUSE_DATABASE` | `nids` | ClickHouse 数据库 |

## 许可证

本项目代码为私有代码。Suricata 组件遵循 GPL 许可证，通过进程隔离方式集成。
