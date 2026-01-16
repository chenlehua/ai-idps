#!/usr/bin/env python3
"""
AI-IDPS 集成测试脚本
===================

完整的端到端集成测试，验证：
1. 探针注册流程
2. 规则下发流程
3. 日志上报流程
4. 实时日志推送 (WebSocket)
5. 前端 API 功能

使用方法:
    python scripts/integration_tests.py [--base-url URL]
"""

import sys
import json
import time
import asyncio
import argparse
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from enum import Enum

try:
    import requests
    import websockets
except ImportError:
    print("请先安装依赖: pip install requests websockets")
    sys.exit(1)


class TestStatus(Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class TestResult:
    name: str
    status: TestStatus
    duration: float
    message: str = ""
    details: Optional[Dict] = None


class IntegrationTest:
    """集成测试类"""

    def __init__(self, base_url: str = "http://localhost"):
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/api/v1"
        self.results: List[TestResult] = []
        self.test_probe_id = f"integration-test-{int(time.time())}"
        self.test_rule_version = None

    def run_test(self, name: str, test_func):
        """运行单个测试"""
        print(f"  测试: {name} ... ", end="", flush=True)
        start_time = time.time()

        try:
            result = test_func()
            duration = time.time() - start_time

            if result is True or result is None:
                status = TestStatus.PASSED
                message = "成功"
            elif isinstance(result, str):
                status = TestStatus.FAILED
                message = result
            else:
                status = TestStatus.PASSED
                message = str(result)

            test_result = TestResult(
                name=name,
                status=status,
                duration=duration,
                message=message
            )

        except Exception as e:
            duration = time.time() - start_time
            test_result = TestResult(
                name=name,
                status=TestStatus.FAILED,
                duration=duration,
                message=str(e)
            )

        self.results.append(test_result)

        if test_result.status == TestStatus.PASSED:
            print(f"\033[92m通过\033[0m ({duration:.2f}s)")
        else:
            print(f"\033[91m失败\033[0m - {test_result.message}")

        return test_result.status == TestStatus.PASSED

    # ================== 测试场景 ==================

    def test_health_check(self) -> bool:
        """健康检查"""
        resp = requests.get(f"{self.base_url}/health", timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"
        data = resp.json()
        if data.get("status") != "ok":
            return f"状态异常: {data}"
        return True

    def test_probe_register(self) -> bool:
        """探针注册测试"""
        payload = {
            "cmd": 30,
            "data": {
                "probe_id": self.test_probe_id,
                "name": "集成测试探针",
                "ip": "192.168.100.1",
                "probe_types": ["nids", "hids"]
            }
        }
        resp = requests.post(f"{self.api_url}/probe", json=payload, timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if data.get("cmd") != 31:
            return f"响应命令码错误: {data}"
        if data.get("data", {}).get("status") != "ok":
            return f"注册失败: {data}"

        return True

    def test_probe_heartbeat(self) -> bool:
        """探针心跳测试"""
        payload = {
            "cmd": 20,
            "data": {
                "probe_id": self.test_probe_id,
                "rule_version": self.test_rule_version,
                "status": {
                    "cpu_usage": 15.5,
                    "memory_usage": 256,
                    "uptime": 7200
                },
                "probes": [
                    {
                        "type": "nids",
                        "id": f"{self.test_probe_id}-nids-eth0",
                        "status": "running",
                        "interface": "eth0"
                    }
                ]
            }
        }
        resp = requests.post(f"{self.api_url}/probe", json=payload, timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if data.get("cmd") != 21:
            return f"响应命令码错误: {data}"
        if data.get("data", {}).get("status") != "ok":
            return f"心跳失败: {data}"

        return True

    def test_create_rule(self) -> bool:
        """创建规则测试"""
        rule_content = """# AI-IDPS Integration Test Rules
# 生成时间: {timestamp}

# SQL注入检测
alert http any any -> any any (msg:"Integration Test - SQL Injection"; content:"SELECT"; nocase; content:"FROM"; nocase; sid:9900001; rev:1;)

# XSS检测
alert http any any -> any any (msg:"Integration Test - XSS Attack"; content:"<script>"; nocase; sid:9900002; rev:1;)

# 目录遍历检测
alert http any any -> any any (msg:"Integration Test - Path Traversal"; content:"../"; sid:9900003; rev:1;)
""".format(timestamp=datetime.now().isoformat())

        payload = {
            "content": rule_content,
            "description": "集成测试规则 - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        resp = requests.post(f"{self.api_url}/rules", json=payload, timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if "version" not in data:
            return f"未返回版本号: {data}"

        self.test_rule_version = data["version"]
        return True

    def test_list_rules(self) -> bool:
        """获取规则列表测试"""
        resp = requests.get(f"{self.api_url}/rules", timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if "versions" not in data:
            return f"响应格式错误: {data}"

        return True

    def test_download_rule(self) -> bool:
        """下载规则测试"""
        if not self.test_rule_version:
            return "跳过: 无可用规则版本"

        payload = {
            "cmd": 40,
            "data": {
                "probe_id": self.test_probe_id,
                "version": self.test_rule_version
            }
        }

        resp = requests.post(f"{self.api_url}/probe", json=payload, timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if data.get("cmd") != 41:
            return f"响应命令码错误: {data}"
        if data.get("data", {}).get("status") != "ok":
            return f"下载失败: {data}"
        if "content" not in data.get("data", {}):
            return f"未返回规则内容: {data}"

        return True

    def test_upload_logs(self) -> bool:
        """上报日志测试"""
        test_logs = []
        for i in range(5):
            test_logs.append({
                "probe_type": "nids",
                "instance_id": f"{self.test_probe_id}-nids-eth0",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "src_ip": f"192.168.1.{100 + i}",
                "dest_ip": "10.0.0.1",
                "src_port": 50000 + i,
                "dest_port": 80,
                "protocol": "TCP",
                "alert": {
                    "signature": f"Integration Test Alert {i + 1}",
                    "signature_id": 9900001 + i,
                    "severity": (i % 3) + 1,
                    "category": "integration-test"
                },
                "raw": json.dumps({"test": True, "index": i})
            })

        payload = {
            "cmd": 10,
            "data": {
                "probe_id": self.test_probe_id,
                "logs": test_logs
            }
        }

        resp = requests.post(f"{self.api_url}/probe", json=payload, timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if data.get("cmd") != 11:
            return f"响应命令码错误: {data}"
        if data.get("data", {}).get("status") != "ok":
            return f"上报失败: {data}"

        return True

    def test_query_logs(self) -> bool:
        """查询日志测试"""
        resp = requests.get(f"{self.api_url}/logs", params={"limit": 10}, timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if "logs" not in data:
            return f"响应格式错误: {data}"

        return True

    def test_log_stats(self) -> bool:
        """日志统计测试"""
        resp = requests.get(f"{self.api_url}/logs/stats", params={"hours": 24}, timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if "stats" not in data:
            return f"响应格式错误: {data}"

        return True

    def test_list_probes(self) -> bool:
        """获取探针列表测试"""
        resp = requests.get(f"{self.api_url}/probes", timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if "probes" not in data:
            return f"响应格式错误: {data}"

        # 检查测试探针是否在列表中
        probes = data.get("probes", [])
        test_probe = next((p for p in probes if p.get("node_id") == self.test_probe_id), None)
        if not test_probe:
            return f"未找到测试探针: {self.test_probe_id}"

        return True

    def test_get_probe_detail(self) -> bool:
        """获取探针详情测试"""
        resp = requests.get(f"{self.api_url}/probes/{self.test_probe_id}", timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        if data.get("node_id") != self.test_probe_id:
            return f"探针ID不匹配: {data}"

        return True

    def test_unknown_command(self) -> bool:
        """未知命令测试"""
        payload = {
            "cmd": 999,
            "data": {}
        }
        resp = requests.post(f"{self.api_url}/probe", json=payload, timeout=10)
        if resp.status_code != 200:
            return f"状态码错误: {resp.status_code}"

        data = resp.json()
        # 应该返回错误响应
        if data.get("data", {}).get("status") != "error":
            return f"应返回错误状态: {data}"

        return True

    async def test_websocket_connection(self) -> bool:
        """WebSocket 连接测试"""
        ws_url = self.base_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = f"{ws_url}/api/v1/ws/logs"

        try:
            async with websockets.connect(ws_url, timeout=5) as ws:
                # 发送订阅请求
                await ws.send(json.dumps({"action": "subscribe", "filters": {}}))

                # 等待响应
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                data = json.loads(response)

                if data.get("event") != "subscribed":
                    return f"订阅响应异常: {data}"

                # 发送 ping
                await ws.send(json.dumps({"action": "ping"}))
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                data = json.loads(response)

                if data.get("event") != "pong":
                    return f"Ping响应异常: {data}"

                return True

        except asyncio.TimeoutError:
            return "WebSocket 连接超时"
        except Exception as e:
            return f"WebSocket 错误: {e}"

    # ================== 测试运行 ==================

    def run_all_tests(self):
        """运行所有测试"""
        print("\n" + "=" * 60)
        print("AI-IDPS 集成测试")
        print("=" * 60)
        print(f"目标: {self.base_url}")
        print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        # 基础连接测试
        print("\n1. 基础连接测试")
        print("-" * 40)
        self.run_test("健康检查", self.test_health_check)

        # 探针注册流程
        print("\n2. 探针注册流程")
        print("-" * 40)
        self.run_test("探针注册", self.test_probe_register)
        self.run_test("探针心跳", self.test_probe_heartbeat)
        self.run_test("探针列表", self.test_list_probes)
        self.run_test("探针详情", self.test_get_probe_detail)

        # 规则管理流程
        print("\n3. 规则管理流程")
        print("-" * 40)
        self.run_test("创建规则", self.test_create_rule)
        self.run_test("规则列表", self.test_list_rules)
        self.run_test("规则下载", self.test_download_rule)

        # 日志上报流程
        print("\n4. 日志上报流程")
        print("-" * 40)
        self.run_test("日志上报", self.test_upload_logs)
        time.sleep(1)  # 等待日志写入
        self.run_test("日志查询", self.test_query_logs)
        self.run_test("日志统计", self.test_log_stats)

        # 错误处理
        print("\n5. 错误处理")
        print("-" * 40)
        self.run_test("未知命令处理", self.test_unknown_command)

        # WebSocket 测试
        print("\n6. WebSocket 测试")
        print("-" * 40)
        try:
            loop = asyncio.get_event_loop()
            self.run_test("WebSocket 连接", lambda: loop.run_until_complete(self.test_websocket_connection()))
        except Exception as e:
            self.results.append(TestResult(
                name="WebSocket 连接",
                status=TestStatus.FAILED,
                duration=0,
                message=str(e)
            ))
            print(f"  测试: WebSocket 连接 ... \033[91m失败\033[0m - {e}")

        # 打印结果汇总
        self.print_summary()

    def print_summary(self):
        """打印测试结果汇总"""
        print("\n" + "=" * 60)
        print("测试结果汇总")
        print("=" * 60)

        passed = sum(1 for r in self.results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAILED)
        skipped = sum(1 for r in self.results if r.status == TestStatus.SKIPPED)
        total = len(self.results)
        total_duration = sum(r.duration for r in self.results)

        print(f"通过: \033[92m{passed}\033[0m")
        print(f"失败: \033[91m{failed}\033[0m")
        if skipped > 0:
            print(f"跳过: \033[93m{skipped}\033[0m")
        print(f"总计: {total}")
        print(f"耗时: {total_duration:.2f}s")
        print("=" * 60)

        if failed > 0:
            print("\n失败的测试:")
            for r in self.results:
                if r.status == TestStatus.FAILED:
                    print(f"  - {r.name}: {r.message}")

        if failed == 0:
            print("\n\033[92m所有测试通过!\033[0m")
            return 0
        else:
            print(f"\n\033[91m有 {failed} 个测试失败\033[0m")
            return 1


def main():
    parser = argparse.ArgumentParser(description="AI-IDPS 集成测试")
    parser.add_argument("--base-url", default="http://localhost",
                        help="API 基础 URL (默认: http://localhost)")
    args = parser.parse_args()

    test = IntegrationTest(args.base_url)
    test.run_all_tests()

    # 返回退出码
    failed = sum(1 for r in test.results if r.status == TestStatus.FAILED)
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
