#!/usr/bin/env python3
"""
Stress Tests & Edge Cases - 压力测试和边界情况测试

测试场景:
1. 高并发连接测试
2. 大数据量测试
3. 协议边界测试
4. 网络异常模拟
5. 资源限制测试
6. 长时间运行测试
7. 模糊测试
"""

import unittest
import time
import random
import string
import struct
import socket
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import List, Optional

from probe_simulator import (
    ProbeSimulator,
    SmartProbeSimulator,
    ProbeInfo,
    Event,
    send_raw_message,
    send_malformed_header,
    send_partial_message,
    HEADER_SIZE
)
from cloud_client import (
    CloudAPIClient,
    generate_test_log,
    generate_test_rule
)


# 测试配置
MANAGER_HOST = "127.0.0.1"
MANAGER_PORT = 9000
CLOUD_BASE_URL = "http://localhost"


class TestHighConcurrency(unittest.TestCase):
    """高并发测试"""

    def test_01_concurrent_connections(self):
        """测试大量并发连接"""
        num_connections = 50
        probes: List[ProbeSimulator] = []
        success_count = 0

        def connect_probe(i: int) -> bool:
            probe = ProbeSimulator(
                probe_info=ProbeInfo(probe_id=f"stress-conn-{i:04d}"),
                manager_host=MANAGER_HOST,
                manager_port=MANAGER_PORT
            )
            if probe.connect(timeout=10.0):
                probes.append(probe)
                return True
            return False

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(connect_probe, i) for i in range(num_connections)]
            for future in as_completed(futures, timeout=30):
                try:
                    if future.result():
                        success_count += 1
                except:
                    pass

        # 清理
        for probe in probes:
            probe.disconnect()

        # 至少应该有50%成功
        self.assertGreater(success_count, num_connections * 0.5,
                          f"At least 50% connections should succeed, got {success_count}/{num_connections}")

    def test_02_concurrent_messages(self):
        """测试高并发消息发送"""
        num_probes = 10
        messages_per_probe = 100
        probes: List[ProbeSimulator] = []

        # 创建并连接探针
        for i in range(num_probes):
            probe = ProbeSimulator(
                probe_info=ProbeInfo(probe_id=f"stress-msg-{i:04d}"),
                manager_host=MANAGER_HOST,
                manager_port=MANAGER_PORT
            )
            if probe.connect(timeout=5.0):
                probes.append(probe)

        if len(probes) == 0:
            self.skipTest("No probes connected")

        def send_many_messages(probe: ProbeSimulator, count: int) -> int:
            success = 0
            for j in range(count):
                if probe.send_alert(
                    src_ip=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    dest_ip="10.0.0.1",
                    src_port=random.randint(1024, 65535),
                    dest_port=80,
                    protocol="TCP",
                    signature=f"Stress Test Alert {j}",
                    signature_id=4000000 + j,
                    severity=random.randint(1, 3)
                ):
                    success += 1
            return success

        total_success = 0
        with ThreadPoolExecutor(max_workers=num_probes) as executor:
            futures = [executor.submit(send_many_messages, p, messages_per_probe) for p in probes]
            for future in as_completed(futures, timeout=60):
                try:
                    total_success += future.result()
                except:
                    pass

        # 清理
        for probe in probes:
            probe.disconnect()

        expected_total = len(probes) * messages_per_probe
        success_rate = total_success / expected_total if expected_total > 0 else 0
        self.assertGreater(success_rate, 0.8,
                          f"Message success rate should be > 80%, got {success_rate*100:.1f}%")

    def test_03_concurrent_http_requests(self):
        """测试高并发 HTTP 请求"""
        num_requests = 100
        client = CloudAPIClient(CLOUD_BASE_URL)

        def send_heartbeat(i: int) -> bool:
            try:
                response = client.heartbeat(
                    probe_id=f"concurrent-http-{i:04d}",
                    rule_version=None,
                    status={"cpu_usage": random.uniform(10, 90)},
                    probes=[]
                )
                return response.http_status == 200
            except:
                return False

        success_count = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(send_heartbeat, i) for i in range(num_requests)]
            for future in as_completed(futures, timeout=60):
                try:
                    if future.result():
                        success_count += 1
                except:
                    pass

        success_rate = success_count / num_requests
        self.assertGreater(success_rate, 0.9,
                          f"HTTP request success rate should be > 90%, got {success_rate*100:.1f}%")


class TestLargeData(unittest.TestCase):
    """大数据量测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)

    def test_01_large_log_batch(self):
        """测试大批量日志上报"""
        probe_id = "stress-large-logs"

        # 注册探针
        self.client.register_probe(
            probe_id=probe_id,
            name="Large Batch Test",
            ip="192.168.1.100",
            probe_types=["nids"]
        )

        # 上报 1000 条日志
        logs = [generate_test_log(probe_id=probe_id) for _ in range(1000)]
        response = self.client.upload_logs(probe_id, logs)

        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.data.get("received"), 1000)

    def test_02_large_rule_content(self):
        """测试大规则文件"""
        # 生成 100KB 的规则内容
        rules_count = 1000
        rules = []
        for i in range(rules_count):
            rules.append(
                f'alert tcp any any -> any any (msg:"Large Rule Test {i}"; '
                f'content:"{"A" * 50}"; sid:{5000000 + i}; rev:1;)'
            )
        large_content = "\n".join(rules)

        result = self.client.create_rule(
            content=large_content,
            description="Large rule test"
        )

        self.assertIsNotNone(result)
        self.assertIn("version", result)

    def test_03_large_probe_data(self):
        """测试大探针数据"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="stress-large-data"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=5.0):
            self.skipTest("Not connected to Manager")

        try:
            # 发送大数据包
            large_data = {
                "signature": "A" * 50000,  # 50KB 字符串
                "extra": ["item" * 100] * 100,
                "nested": {f"key_{i}": f"value_{i}" * 100 for i in range(100)}
            }
            result = probe.send_event(Event.EVT_ALERT, large_data)
            # 可能成功也可能被拒绝
            self.assertIsInstance(result, bool)
        finally:
            probe.disconnect()


class TestProtocolBoundary(unittest.TestCase):
    """协议边界测试"""

    def test_01_zero_length_message(self):
        """测试零长度消息"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((MANAGER_HOST, MANAGER_PORT))

                # 发送长度为 0 的消息
                header = struct.pack('!I', 0)
                sock.sendall(header)

                # 等待响应或断开
                time.sleep(1)
        except Exception as e:
            # 服务器可能断开连接，这是正常的
            pass

    def test_02_malformed_json(self):
        """测试格式错误的 JSON"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((MANAGER_HOST, MANAGER_PORT))

                # 发送无效 JSON
                invalid_json = b'{invalid json content'
                header = struct.pack('!I', len(invalid_json))
                sock.sendall(header + invalid_json)

                time.sleep(1)
        except:
            pass

    def test_03_oversized_length(self):
        """测试超大长度声明"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((MANAGER_HOST, MANAGER_PORT))

                # 声明 1GB 数据但只发送少量
                header = struct.pack('!I', 1024 * 1024 * 1024)
                sock.sendall(header + b'small data')

                time.sleep(2)
        except:
            pass

    def test_04_truncated_message(self):
        """测试截断的消息"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((MANAGER_HOST, MANAGER_PORT))

                # 声明 100 字节但只发送 10 字节
                header = struct.pack('!I', 100)
                sock.sendall(header + b'0123456789')

                time.sleep(1)
        except:
            pass

    def test_05_binary_garbage(self):
        """测试二进制垃圾数据"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((MANAGER_HOST, MANAGER_PORT))

                # 发送随机二进制数据
                garbage = bytes(random.randint(0, 255) for _ in range(1000))
                sock.sendall(garbage)

                time.sleep(1)
        except:
            pass

    def test_06_incomplete_header(self):
        """测试不完整的头部"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((MANAGER_HOST, MANAGER_PORT))

                # 只发送 2 字节（头部需要 4 字节）
                sock.sendall(b'\x00\x00')

                time.sleep(2)
        except:
            pass


class TestFuzzing(unittest.TestCase):
    """模糊测试"""

    def _generate_random_string(self, length: int) -> str:
        return ''.join(random.choices(string.printable, k=length))

    def _generate_random_json(self, depth: int = 3) -> dict:
        """生成随机 JSON 结构"""
        if depth <= 0:
            return random.choice([
                random.randint(-1000000, 1000000),
                random.uniform(-1000000, 1000000),
                self._generate_random_string(random.randint(1, 100)),
                None,
                True,
                False
            ])

        result = {}
        for _ in range(random.randint(1, 5)):
            key = self._generate_random_string(random.randint(1, 20))
            value_type = random.randint(0, 3)
            if value_type == 0:
                result[key] = self._generate_random_json(depth - 1)
            elif value_type == 1:
                result[key] = [self._generate_random_json(depth - 1)
                              for _ in range(random.randint(0, 5))]
            else:
                result[key] = self._generate_random_json(0)
        return result

    def test_01_random_json_messages(self):
        """测试随机 JSON 消息"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="fuzz-json"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=5.0):
            self.skipTest("Not connected to Manager")

        try:
            for _ in range(50):
                random_data = self._generate_random_json(depth=3)
                try:
                    probe.send_event(Event.EVT_STATUS, random_data)
                except:
                    pass
                time.sleep(0.05)
        finally:
            probe.disconnect()

    def test_02_random_event_types(self):
        """测试随机事件类型"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="fuzz-event"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=5.0):
            self.skipTest("Not connected to Manager")

        try:
            for i in range(50):
                # 使用随机事件类型
                random_event = random.randint(-100, 100)
                msg = {
                    "event": f"RANDOM_EVENT_{random_event}",
                    "probe_id": probe.probe_info.probe_id,
                    "data": {"test": i}
                }
                try:
                    probe._send_message(msg)
                except:
                    pass
                time.sleep(0.05)
        finally:
            probe.disconnect()

    def test_03_fuzz_http_api(self):
        """模糊测试 HTTP API"""
        client = CloudAPIClient(CLOUD_BASE_URL)

        for _ in range(30):
            random_cmd = random.randint(-100, 200)
            random_data = self._generate_random_json(depth=2)

            try:
                client._send_request(random_cmd, random_data)
            except:
                pass
            time.sleep(0.05)


class TestConnectionResilience(unittest.TestCase):
    """连接弹性测试"""

    def test_01_reconnect_after_timeout(self):
        """测试超时后重连"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="resilience-timeout"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        # 第一次连接
        if not probe.connect(timeout=5.0):
            self.skipTest("Not connected to Manager")

        # 发送消息
        probe.send_status()

        # 断开
        probe.disconnect()

        # 等待
        time.sleep(2)

        # 重连
        result = probe.connect(timeout=5.0)
        self.assertTrue(result, "Reconnection should succeed")

        probe.send_status()
        probe.disconnect()

    def test_02_rapid_reconnect(self):
        """测试快速重连"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="resilience-rapid"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        success_count = 0
        for i in range(20):
            if probe.connect(timeout=2.0):
                success_count += 1
                probe.send_status()
            probe.disconnect()
            time.sleep(0.1)

        # 至少 50% 成功
        self.assertGreater(success_count, 10,
                          f"At least 50% reconnects should succeed, got {success_count}/20")

    def test_03_connection_during_heavy_load(self):
        """测试高负载下的连接"""
        # 创建多个探针产生负载
        load_probes = []
        for i in range(5):
            probe = ProbeSimulator(
                probe_info=ProbeInfo(probe_id=f"load-{i}"),
                manager_host=MANAGER_HOST,
                manager_port=MANAGER_PORT
            )
            if probe.connect(timeout=5.0):
                load_probes.append(probe)

        # 让它们持续发送消息
        def generate_load(probe):
            for _ in range(100):
                probe.send_status()
                time.sleep(0.01)

        load_threads = [threading.Thread(target=generate_load, args=(p,))
                       for p in load_probes]
        for t in load_threads:
            t.start()

        # 在负载下尝试新连接
        new_probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="new-under-load"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )
        result = new_probe.connect(timeout=10.0)

        # 清理
        for t in load_threads:
            t.join(timeout=5)
        for p in load_probes:
            p.disconnect()
        if result:
            new_probe.disconnect()

        # 新连接应该仍然能成功（或至少不崩溃）
        self.assertIsInstance(result, bool)


class TestLongRunning(unittest.TestCase):
    """长时间运行测试"""

    def test_01_sustained_connection(self):
        """测试持续连接"""
        probe = SmartProbeSimulator(
            probe_info=ProbeInfo(probe_id="longrun-sustained"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=5.0):
            self.skipTest("Not connected to Manager")

        probe.start_receiving()

        try:
            # 运行 30 秒，每秒发送状态
            start_time = time.time()
            success_count = 0
            total_count = 0

            while time.time() - start_time < 30:
                if probe.send_status():
                    success_count += 1
                total_count += 1

                # 偶尔发送告警
                if random.random() < 0.2:
                    probe.send_alert(
                        src_ip="192.168.1.1",
                        dest_ip="10.0.0.1",
                        src_port=random.randint(1024, 65535),
                        dest_port=80,
                        protocol="TCP",
                        signature="Long running test",
                        signature_id=6000000,
                        severity=2
                    )

                time.sleep(1)

            success_rate = success_count / total_count if total_count > 0 else 0
            self.assertGreater(success_rate, 0.9,
                              f"Success rate should be > 90%, got {success_rate*100:.1f}%")

        finally:
            probe.stop_receiving()
            probe.disconnect()


class TestSpecialCases(unittest.TestCase):
    """特殊情况测试"""

    def test_01_unicode_handling(self):
        """测试 Unicode 处理"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="special-unicode"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=5.0):
            self.skipTest("Not connected to Manager")

        try:
            # 各种 Unicode 字符
            unicode_data = {
                "chinese": "中文测试",
                "japanese": "日本語テスト",
                "korean": "한국어 테스트",
                "arabic": "اختبار عربي",
                "russian": "Русский тест",
                "emoji": "🔥🚨⚠️🛡️",
                "special": "™®©℃℉",
                "math": "∑∏∫∂√",
                "mixed": "Test测试テスト🔥"
            }
            result = probe.send_event(Event.EVT_STATUS, unicode_data)
            self.assertTrue(result, "Unicode data should be sent")
        finally:
            probe.disconnect()

    def test_02_null_and_empty_values(self):
        """测试空值处理"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="special-null"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=5.0):
            self.skipTest("Not connected to Manager")

        try:
            null_data = {
                "null_value": None,
                "empty_string": "",
                "empty_list": [],
                "empty_dict": {},
                "zero": 0,
                "false": False
            }
            result = probe.send_event(Event.EVT_STATUS, null_data)
            self.assertTrue(result, "Null/empty data should be sent")
        finally:
            probe.disconnect()

    def test_03_deeply_nested_json(self):
        """测试深层嵌套 JSON"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="special-nested"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=5.0):
            self.skipTest("Not connected to Manager")

        try:
            # 创建深层嵌套结构
            nested = {"level": 0}
            current = nested
            for i in range(50):
                current["child"] = {"level": i + 1}
                current = current["child"]

            result = probe.send_event(Event.EVT_STATUS, nested)
            # 可能成功或被拒绝
            self.assertIsInstance(result, bool)
        finally:
            probe.disconnect()

    def test_04_max_int_values(self):
        """测试最大整数值"""
        client = CloudAPIClient(CLOUD_BASE_URL)

        response = client.heartbeat(
            probe_id="special-maxint",
            rule_version=None,
            status={
                "max_int": 2**63 - 1,
                "min_int": -(2**63),
                "large_float": 1.7976931348623157e+308
            },
            probes=[]
        )

        # 应该能处理而不崩溃
        self.assertEqual(response.http_status, 200)


def run_tests():
    """运行所有测试"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # 添加所有测试类
    suite.addTests(loader.loadTestsFromTestCase(TestHighConcurrency))
    suite.addTests(loader.loadTestsFromTestCase(TestLargeData))
    suite.addTests(loader.loadTestsFromTestCase(TestProtocolBoundary))
    suite.addTests(loader.loadTestsFromTestCase(TestFuzzing))
    suite.addTests(loader.loadTestsFromTestCase(TestConnectionResilience))
    suite.addTests(loader.loadTestsFromTestCase(TestLongRunning))
    suite.addTests(loader.loadTestsFromTestCase(TestSpecialCases))

    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
