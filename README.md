# AI-IDPS (网络入侵检测系统)

本仓库为网络入侵检测系统的开发项目，包含云端服务与探针端的完整框架。

## 目录结构

```
ai-idps/
├── cloud/                    # 云端服务
│   ├── backend/              # FastAPI 后端
│   ├── frontend/             # React 前端
│   ├── nginx/                # Nginx 配置
│   ├── mysql/                # MySQL 初始化脚本
│   ├── clickhouse/           # ClickHouse 初始化脚本
│   └── docker-compose.yml
├── probe/                    # 探针端
│   ├── common/               # 公共库
│   ├── manager/              # Probe Manager
│   └── nids/                 # NIDS 探针
├── third_party/              # 第三方依赖
│   └── suricata/             # Suricata 子模块
├── rules/                    # 规则集目录
├── scripts/                  # 脚本工具
├── fixtures/                 # 测试用例
├── specs/                    # 需求与设计文档
└── Makefile                  # 项目统一管理命令
```

## 快速开始

### 前置要求

- Docker >= 24.0 (云端服务)
- Docker Compose >= 2.20 (云端服务)
- CMake >= 3.16 (探针)
- GCC >= 11 (探针)
- libcurl-dev (探针)

### 查看所有服务状态

```bash
make list
```

### 启动云端服务

```bash
make build                    # 构建云端服务
make up                       # 启动云端服务

# 验证
curl http://localhost/health  # 返回: {"status":"ok"}
```

### 构建并启动探针

```bash
# 构建所有探针
make build SERVICE=probes

# 启动 Probe Manager
make up SERVICE=probe-manager

# 启动 NIDS Probe
make up SERVICE=nids-probe

# 查看状态
make list
```

## 统一服务管理命令

所有服务（云端和探针）使用统一的 `make` 命令管理：

| 命令 | 说明 |
|:-----|:-----|
| `make build [SERVICE=xxx]` | 构建服务 |
| `make rebuild [SERVICE=xxx]` | 完全重新构建 |
| `make up [SERVICE=xxx]` | 启动服务（后台） |
| `make down [SERVICE=xxx]` | 停止服务 |
| `make restart [SERVICE=xxx]` | 重启服务 |
| `make logs [SERVICE=xxx]` | 查看服务日志 |
| `make run [SERVICE=xxx]` | 前台运行（调试） |
| `make clean [SERVICE=xxx]` | 清理构建产物 |
| `make install [SERVICE=xxx]` | 安装到系统 |
| `make uninstall [SERVICE=xxx]` | 从系统卸载 |
| `make list` | 查看所有服务状态 |
| `make help` | 显示帮助信息 |

### SERVICE 可选值

| 值 | 说明 |
|:---|:-----|
| (不指定) | 操作所有云端 Docker 服务 |
| `backend` | 云端后端服务 |
| `frontend` | 云端前端服务 |
| `nginx` | Nginx 代理 |
| `redis` | Redis 服务 |
| `mysql` | MySQL 服务 |
| `clickhouse` | ClickHouse 服务 |
| `probe-manager` | Probe Manager |
| `nids-probe` | NIDS Probe |
| `probes` | 所有探针 (Manager + NIDS) |
| `suricata` | Suricata 检测引擎 |

### 使用示例

```bash
# 构建所有探针
make build SERVICE=probes

# 只构建 Probe Manager
make build SERVICE=probe-manager

# 启动 Probe Manager（后台）
make up SERVICE=probe-manager

# 前台运行 NIDS Probe（调试）
make run SERVICE=nids-probe

# 查看 Probe Manager 日志
make logs SERVICE=probe-manager

# 停止所有探针
make down SERVICE=probes

# 安装探针到系统
make install SERVICE=probes

# 使用自定义端口启动
PROBE_PORT=9020 make up SERVICE=probe-manager

# 指定监控网卡
NIDS_INTERFACE=ens33 make up SERVICE=nids-probe
```

## 编译 Suricata

如果系统未安装 Suricata，可以从源码编译：

```bash
# 初始化 Suricata 子模块
git submodule update --init --recursive

# 编译 Suricata
make build SERVICE=suricata

# 安装 Suricata
make install SERVICE=suricata

# 验证安装
suricata -V
```

## 配置变量

| 变量 | 默认值 | 说明 |
|:-----|:-------|:-----|
| `PROBE_PORT` | `9010` | Probe Manager 监听端口 |
| `CLOUD_URL` | `http://localhost` | 云端 API 地址 |
| `NIDS_INTERFACE` | `eth0` | NIDS 监控网卡 |
| `SURICATA_CONFIG` | `/etc/suricata/suricata.yaml` | Suricata 配置文件 |

## 测试

```bash
# 云端 API 测试
make test-api            # 运行云端 API 测试

# 探针测试
make test-probe          # 运行探针黑盒测试
make test-stress         # 运行压力测试

# NIDS 探针测试
make test-nids           # 运行 NIDS 完整测试套件
make test-nids-quick     # 运行 NIDS 快速测试
make test-nids-manager   # 运行 NIDS-Manager 通信测试

# 集成测试
make test-integration    # 运行端到端集成测试

# 性能测试
make test-performance    # 运行性能测试(快速模式)
make test-perf-full      # 运行完整性能测试

# 所有测试
make test-all            # 运行所有测试
```

### 集成测试

集成测试 (`scripts/integration_tests.py`) 验证以下场景：
- 健康检查
- 探针注册、心跳、详情获取
- 规则创建、列表、下载
- 日志上报、查询、统计
- WebSocket 连接和消息推送
- 错误处理

```bash
# 直接运行
python3 scripts/integration_tests.py --base-url http://localhost

# 使用 Make
make test-integration CLOUD_URL=http://localhost
```

### 性能测试

性能测试 (`scripts/performance_tests.py`) 测试以下指标：
- 日志写入性能 (目标: 1000 条/秒)
- API 响应时间 (目标: P95 < 500ms)
- WebSocket 并发连接 (目标: 100 连接)
- 探针并发心跳 (目标: 10 个探针)

```bash
# 快速性能测试
python3 scripts/performance_tests.py --base-url http://localhost

# 完整性能测试
python3 scripts/performance_tests.py --base-url http://localhost --all \
    --rate 1000 --duration 60 --concurrency 50 --connections 100 --probes 10

# 单项测试
python3 scripts/performance_tests.py --log-write --rate 1000 --duration 60
python3 scripts/performance_tests.py --api-stress --concurrency 50
python3 scripts/performance_tests.py --ws-test --connections 100
python3 scripts/performance_tests.py --probe-test --probes 10
```

### NIDS 探针黑盒测试

NIDS 探针黑盒测试位于 `fixtures/nids_tests/` 目录，包含以下测试用例：

| 测试脚本 | 说明 |
|:---------|:-----|
| `run_nids_tests.py` | Python 测试运行器 |
| `test_manager_comm.py` | Manager 通信协议测试 |
| `test_port_scan.sh` | 端口扫描检测测试 |
| `test_web_attacks.sh` | Web 攻击检测测试 |
| `test_protocol_anomaly.sh` | 协议异常检测测试 |
| `test_malware_traffic.sh` | 恶意流量模拟测试 |
| `test_stress.sh` | 压力测试 |

#### 手动运行测试

```bash
# 进入测试目录
cd fixtures/nids_tests

# 运行所有测试
./run_all_tests.sh <target_ip> <manager_port>

# 运行单个测试
./test_port_scan.sh <target_ip>
./test_web_attacks.sh http://<target_ip>
python3 test_manager_comm.py --port 9010

# Python 测试
python3 run_nids_tests.py --target <target_ip> --manager-port 9010
```

#### 测试依赖

```bash
# 基础工具
sudo apt-get install -y nmap netcat curl

# 高级测试工具（可选）
sudo apt-get install -y hping3 nikto hydra
```

## Probe Manager

Probe Manager 是探针管理程序，负责：
- 与云端通信（注册、心跳、规则同步、日志上报）
- 管理多个探针实例
- 日志聚合和批量上报

### 配置文件

参考 `probe/manager/config.example.json`：

```json
{
    "probe_id": "probe-001",
    "probe_name": "Production Probe 1",
    "probe_ip": "192.168.1.100",
    "probe_types": ["nids"],
    "cloud_url": "http://localhost/api/v1/probe",
    "listen_port": 9010,
    "rules_dir": "/var/lib/nids/rules",
    "heartbeat_interval": 300
}
```

### 环境变量

| 变量 | 默认值 | 说明 |
|:-----|:-------|:-----|
| `PROBE_ID` | `probe-001` | 探针节点 ID |
| `PROBE_NAME` | `default-probe` | 探针名称 |
| `CLOUD_URL` | `http://localhost:8000/api/v1/probe` | 云端 API 地址 |
| `LISTEN_PORT` | `9010` | 监听端口 |
| `RULES_DIR` | `/var/lib/nids/rules` | 规则文件目录 |
| `HEARTBEAT_INTERVAL` | `300` | 心跳间隔 (秒) |

## NIDS Probe

NIDS 探针负责网络入侵检测，通过调用 Suricata 进行流量分析。

### 命令行选项

```
Options:
  -m, --manager <host:port>  Manager 地址 (默认: 127.0.0.1:9000)
  -i, --interface <name>     监控网卡 (默认: eth0)
  -c, --config <path>        Suricata 配置文件
  -r, --rules <path>         规则文件路径
  -l, --log-dir <path>       日志目录
  -p, --probe-id <id>        探针 ID
  -h, --help                 显示帮助
  -v, --version              显示版本
```

### 环境变量

| 变量 | 默认值 | 说明 |
|:-----|:-------|:-----|
| `MANAGER_HOST` | `127.0.0.1` | Probe Manager 主机 |
| `MANAGER_PORT` | `9000` | Probe Manager 端口 |
| `INTERFACE` | `eth0` | 监控网卡 |
| `SURICATA_CONFIG` | `/etc/suricata/suricata.yaml` | Suricata 配置文件 |
| `LOG_DIR` | `/var/log/suricata` | 日志目录 |

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
| `/api/v1/rules` | GET/POST | 规则管理 |
| `/api/v1/logs` | GET | 查询告警日志 |
| `/api/v1/logs/stats` | GET | 日志统计 |

### WebSocket 接口

- 实时日志: `ws://localhost/api/v1/ws/logs`

## 开发进度

### 已完成

- [x] **Phase 1**: 环境搭建与基础框架
- [x] **Phase 2**: 云端后端核心功能
- [x] **Phase 3**: 探针管理程序 (Probe Manager)
- [x] **Phase 4**: NIDS 探针实现
- [x] **Phase 5**: 云端前端实现
  - 仪表盘页面 (统计图表、探针概览)
  - 规则管理页面 (创建、查看版本历史)
  - 日志展示页面 (WebSocket 实时推送、历史查询)
  - 探针管理页面 (卡片/列表视图、详情查看)
- [x] **Phase 6**: 集成测试与优化
  - 端到端集成测试脚本
  - 性能测试脚本 (日志写入、API压力、WebSocket、探针并发)

## 技术栈

| 组件 | 技术 |
|:-----|:-----|
| 云端后端 | Python 3.11 / FastAPI |
| 云端前端 | TypeScript / Vite / React |
| 数据库 | Redis / MySQL / ClickHouse |
| 探针端 | C++17 / CMake / epoll |
| NIDS 引擎 | Suricata (GPL) |

## 许可证

本项目代码为私有代码。Suricata 组件遵循 GPL 许可证，通过进程隔离方式集成。
