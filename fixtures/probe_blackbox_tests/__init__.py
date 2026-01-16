"""
AI-IDPS Phase 3 Black Box Tests
===============================

本模块包含 Probe Manager 的黑盒测试用例，用于验证:
1. 探针与 Manager 的 TCP Socket 通信
2. Manager 与云端的 HTTP API 通信
3. 协议正确性和健壮性
4. 性能和压力测试

模块结构:
- probe_simulator.py: 探针模拟器
- cloud_client.py: 云端 API 客户端
- test_probe_connection.py: 探针连接测试
- test_cloud_communication.py: 云端通信测试
- test_stress.py: 压力测试
- run_tests.py: 测试运行器
"""

from .probe_simulator import (
    ProbeSimulator,
    SmartProbeSimulator,
    ProbeInfo,
    Event,
    Command
)

from .cloud_client import (
    CloudAPIClient,
    CloudCommand,
    CloudResponse,
    generate_test_log,
    generate_test_rule
)

__all__ = [
    'ProbeSimulator',
    'SmartProbeSimulator',
    'ProbeInfo',
    'Event',
    'Command',
    'CloudAPIClient',
    'CloudCommand',
    'CloudResponse',
    'generate_test_log',
    'generate_test_rule'
]
