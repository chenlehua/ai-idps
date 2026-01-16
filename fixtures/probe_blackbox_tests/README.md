# Phase 3 Black Box Tests

AI-IDPS 探针管理程序 (Probe Manager) 的黑盒测试套件。

## 目录结构

```
probe_blackbox_tests/
├── __init__.py              # 模块初始化
├── probe_simulator.py       # 探针模拟器 (TCP Socket 客户端)
├── cloud_client.py          # 云端 API 客户端 (HTTP)
├── test_probe_connection.py # 探针连接测试用例
├── test_cloud_communication.py # 云端通信测试用例
├── test_stress.py           # 压力测试和边界测试
├── run_tests.py             # 测试运行器
└── README.md                # 本文档
```

## 安装依赖

```bash
pip install requests
```

## 使用方法

### 运行所有测试

```bash
cd fixtures/probe_blackbox_tests
python run_tests.py
```

### 运行特定测试

```bash
# 只运行探针连接测试
python run_tests.py --probe

# 只运行云端通信测试
python run_tests.py --cloud

# 只运行压力测试
python run_tests.py --stress

# 快速模式（跳过压力测试）
python run_tests.py --quick
```

### 指定服务器地址

```bash
python run_tests.py \
    --manager-host 192.168.1.100 \
    --manager-port 9010 \
    --cloud-url http://192.168.1.100
```

### 单独运行测试文件

```bash
# 探针连接测试
python test_probe_connection.py

# 云端通信测试
python test_cloud_communication.py

# 压力测试
python test_stress.py
```

## 测试覆盖

### 1. 探针连接测试 (test_probe_connection.py)

| 测试类 | 测试内容 |
|--------|----------|
| TestProbeConnection | 基本连接、断开、重连 |
| TestProbeMessaging | 状态发送、告警发送、错误发送 |
| TestSmartProbe | 自动响应命令、连续状态更新 |
| TestProbeLifecycle | 完整生命周期、断开重连 |
| TestMultipleProbes | 多探针并发连接、并发消息 |
| TestProbeTypes | NIDS/HIDS 探针类型 |
| TestEdgeCases | 空数据、大数据、特殊字符 |

### 2. 云端通信测试 (test_cloud_communication.py)

| 测试类 | 测试内容 |
|--------|----------|
| TestHealthCheck | 健康检查接口 |
| TestProbeRegistration | 探针注册、重复注册、多类型注册 |
| TestHeartbeat | 基本心跳、带版本心跳、连续心跳 |
| TestRuleManagement | 创建规则、获取规则、下载规则 |
| TestLogUpload | 单条日志、批量日志、大批量日志 |
| TestLogQuery | 查询日志、按条件过滤、分页、统计 |
| TestProbeManagement | 探针列表、探针详情 |
| TestUnknownCommand | 未知命令处理 |
| TestFullWorkflow | 完整工作流程 |

### 3. 压力测试 (test_stress.py)

| 测试类 | 测试内容 |
|--------|----------|
| TestHighConcurrency | 并发连接、并发消息、并发HTTP请求 |
| TestLargeData | 大批量日志、大规则文件、大数据包 |
| TestProtocolBoundary | 零长度、错误JSON、超大长度、截断消息 |
| TestFuzzing | 随机JSON、随机事件类型、模糊HTTP |
| TestConnectionResilience | 超时重连、快速重连、高负载连接 |
| TestLongRunning | 持续连接30秒测试 |
| TestSpecialCases | Unicode、空值、深层嵌套、最大整数 |

## 协议说明

### TCP Socket 协议 (探针 <-> Manager)

消息格式:
```
+----------------+------------------+
| Header (4B)    | Payload (JSON)   |
+----------------+------------------+
| uint32 length  | JSON string      |
+----------------+------------------+
```

Manager -> 探针 命令:
- `CMD_START = 1`: 启动探针
- `CMD_STOP = 2`: 停止探针
- `CMD_RELOAD_RULES = 3`: 重载规则
- `CMD_GET_STATUS = 4`: 获取状态
- `CMD_SHUTDOWN = 5`: 关闭探针

探针 -> Manager 事件:
- `EVT_ALERT = 1`: 告警事件
- `EVT_STATUS = 2`: 状态事件
- `EVT_ERROR = 3`: 错误事件
- `EVT_ACK = 4`: 确认事件

### HTTP API 协议 (Manager <-> 云端)

统一入口: `POST /api/v1/probe`

请求格式:
```json
{
    "cmd": <命令码>,
    "data": {...}
}
```

命令码:
- `10`: 日志上报 (LOG_UPLOAD)
- `20`: 心跳 (HEARTBEAT)
- `30`: 注册 (REGISTER)
- `40`: 规则下载 (RULE_DOWNLOAD)

## 使用示例

### 模拟探针连接

```python
from probe_simulator import SmartProbeSimulator, ProbeInfo

probe = SmartProbeSimulator(
    probe_info=ProbeInfo(probe_id="my-probe-001"),
    manager_host="127.0.0.1",
    manager_port=9010
)

if probe.connect():
    probe.start_receiving()
    probe.send_register()
    probe.send_status()
    probe.send_alert(
        src_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        src_port=54321,
        dest_port=80,
        protocol="TCP",
        signature="Test Alert",
        signature_id=1000001,
        severity=2
    )
    probe.disconnect()
```

### 调用云端 API

```python
from cloud_client import CloudAPIClient, generate_test_log

client = CloudAPIClient("http://localhost")

# 注册探针
client.register_probe(
    probe_id="my-probe-001",
    name="My Probe",
    ip="192.168.1.100",
    probe_types=["nids"]
)

# 发送心跳
client.heartbeat(
    probe_id="my-probe-001",
    rule_version=None,
    status={"cpu_usage": 25.5},
    probes=[]
)

# 上报日志
logs = [generate_test_log() for _ in range(10)]
client.upload_logs("my-probe-001", logs)
```

## 注意事项

1. 运行测试前确保 Probe Manager 和云端服务已启动
2. 压力测试可能需要较长时间（约 2-3 分钟）
3. 部分测试可能因服务配置不同而失败，需根据实际情况调整
4. 建议在独立测试环境中运行，避免影响生产数据
