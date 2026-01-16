#!/usr/bin/env python3
"""
Probe Connection Tests - 测试探针与 Probe Manager 的 TCP Socket 通信

测试场景:
1. 基本连接测试
2. 消息发送接收测试
3. 探针注册流程测试
4. 告警上报测试
5. 命令响应测试
6. 断开重连测试
7. 多探针并发测试
"""

import unittest
import time
import threading
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed

from probe_simulator import (
    ProbeSimulator,
    SmartProbeSimulator,
    ProbeInfo,
    Event,
    Command,
    send_raw_message,
    send_malformed_header,
    send_partial_message
)


# 测试配置
MANAGER_HOST = "127.0.0.1"
MANAGER_PORT = 9010
CONNECTION_TIMEOUT = 5.0


class TestProbeConnection(unittest.TestCase):
    """探针连接基础测试"""

    def test_01_basic_connection(self):
        """测试基本连接"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-conn-001"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        result = probe.connect(timeout=CONNECTION_TIMEOUT)
        self.assertTrue(result, "Should connect successfully")
        self.assertTrue(probe.connected, "Connected flag should be True")

        probe.disconnect()
        self.assertFalse(probe.connected, "Connected flag should be False after disconnect")

    def test_02_connection_refused(self):
        """测试连接被拒绝（无效端口）"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-conn-002"),
            manager_host=MANAGER_HOST,
            manager_port=59999  # 无效端口
        )

        result = probe.connect(timeout=2.0)
        self.assertFalse(result, "Should fail to connect to invalid port")

    def test_03_multiple_connect_disconnect(self):
        """测试多次连接断开"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-conn-003"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        for i in range(3):
            result = probe.connect(timeout=CONNECTION_TIMEOUT)
            self.assertTrue(result, f"Connection {i+1} should succeed")
            time.sleep(0.5)
            probe.disconnect()
            time.sleep(0.5)


class TestProbeMessaging(unittest.TestCase):
    """探针消息收发测试"""

    def setUp(self):
        self.probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-msg-001"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )
        self.connected = self.probe.connect(timeout=CONNECTION_TIMEOUT)

    def tearDown(self):
        if self.probe:
            self.probe.stop_receiving()
            self.probe.disconnect()

    def test_01_send_status_event(self):
        """测试发送状态事件"""
        if not self.connected:
            self.skipTest("Not connected to Manager")

        result = self.probe.send_status()
        self.assertTrue(result, "Should send status event successfully")

    def test_02_send_alert_event(self):
        """测试发送告警事件"""
        if not self.connected:
            self.skipTest("Not connected to Manager")

        result = self.probe.send_alert(
            src_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            src_port=54321,
            dest_port=80,
            protocol="TCP",
            signature="Test Alert",
            signature_id=1000001,
            severity=2,
            category="test"
        )
        self.assertTrue(result, "Should send alert event successfully")

    def test_03_send_multiple_alerts(self):
        """测试发送多条告警"""
        if not self.connected:
            self.skipTest("Not connected to Manager")

        for i in range(10):
            result = self.probe.send_alert(
                src_ip=f"192.168.1.{i+1}",
                dest_ip="10.0.0.1",
                src_port=10000 + i,
                dest_port=80,
                protocol="TCP",
                signature=f"Test Alert {i}",
                signature_id=1000000 + i,
                severity=i % 3 + 1
            )
            self.assertTrue(result, f"Alert {i} should be sent successfully")

    def test_04_send_error_event(self):
        """测试发送错误事件"""
        if not self.connected:
            self.skipTest("Not connected to Manager")

        result = self.probe.send_error(
            error_code=1001,
            error_msg="Test error message"
        )
        self.assertTrue(result, "Should send error event successfully")

    def test_05_send_ack_event(self):
        """测试发送确认事件"""
        if not self.connected:
            self.skipTest("Not connected to Manager")

        result = self.probe.send_ack(
            cmd=Command.CMD_START,
            success=True,
            message="Command acknowledged"
        )
        self.assertTrue(result, "Should send ack event successfully")


class TestSmartProbe(unittest.TestCase):
    """智能探针测试 - 自动响应命令"""

    def setUp(self):
        self.probe = SmartProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-smart-001"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )
        self.connected = self.probe.connect(timeout=CONNECTION_TIMEOUT)
        if self.connected:
            self.probe.start_receiving()

    def tearDown(self):
        if self.probe:
            self.probe.stop_receiving()
            self.probe.disconnect()

    def test_01_register_and_status(self):
        """测试注册和状态上报"""
        if not self.connected:
            self.skipTest("Not connected to Manager")

        # 发送注册
        result = self.probe.send_register()
        self.assertTrue(result, "Should send register successfully")

        time.sleep(0.5)

        # 发送状态
        result = self.probe.send_status()
        self.assertTrue(result, "Should send status successfully")

    def test_02_continuous_status_updates(self):
        """测试连续状态更新"""
        if not self.connected:
            self.skipTest("Not connected to Manager")

        for i in range(5):
            self.probe.probe_info.metrics = {
                "alerts_count": i * 10,
                "bytes_processed": i * 1000000
            }
            result = self.probe.send_status()
            self.assertTrue(result, f"Status update {i} should succeed")
            time.sleep(0.2)


class TestProbeLifecycle(unittest.TestCase):
    """探针生命周期测试"""

    def test_01_full_lifecycle(self):
        """测试完整生命周期: 连接 -> 注册 -> 运行 -> 断开"""
        probe = SmartProbeSimulator(
            probe_info=ProbeInfo(
                probe_id="test-lifecycle-001",
                probe_type="nids",
                interface="eth0"
            ),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        # 1. 连接
        result = probe.connect(timeout=CONNECTION_TIMEOUT)
        if not result:
            self.skipTest("Not connected to Manager")

        probe.start_receiving()

        try:
            # 2. 注册
            self.assertTrue(probe.send_register(), "Register should succeed")
            time.sleep(0.3)

            # 3. 发送初始状态
            probe.probe_info.status = "initializing"
            self.assertTrue(probe.send_status(), "Initial status should succeed")
            time.sleep(0.3)

            # 4. 模拟运行
            probe.probe_info.status = "running"
            for i in range(3):
                # 发送状态
                self.assertTrue(probe.send_status(), f"Status {i} should succeed")

                # 发送告警
                self.assertTrue(
                    probe.send_alert(
                        src_ip="192.168.1.100",
                        dest_ip="10.0.0.1",
                        src_port=50000 + i,
                        dest_port=80,
                        protocol="TCP",
                        signature=f"Lifecycle Test Alert {i}",
                        signature_id=2000000 + i,
                        severity=2
                    ),
                    f"Alert {i} should succeed"
                )
                time.sleep(0.2)

            # 5. 停止
            probe.probe_info.status = "stopping"
            self.assertTrue(probe.send_status(), "Stopping status should succeed")

        finally:
            # 6. 断开
            probe.stop_receiving()
            probe.disconnect()

    def test_02_reconnect_after_disconnect(self):
        """测试断开后重连"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-reconnect-001"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        # 第一次连接
        result = probe.connect(timeout=CONNECTION_TIMEOUT)
        if not result:
            self.skipTest("Not connected to Manager")

        probe.send_status()
        time.sleep(0.5)
        probe.disconnect()

        time.sleep(1)

        # 重新连接
        result = probe.connect(timeout=CONNECTION_TIMEOUT)
        self.assertTrue(result, "Reconnection should succeed")
        probe.send_status()
        probe.disconnect()


class TestMultipleProbes(unittest.TestCase):
    """多探针并发测试"""

    def test_01_multiple_probes_connect(self):
        """测试多个探针同时连接"""
        num_probes = 5
        probes: List[ProbeSimulator] = []

        try:
            for i in range(num_probes):
                probe = ProbeSimulator(
                    probe_info=ProbeInfo(probe_id=f"test-multi-{i:03d}"),
                    manager_host=MANAGER_HOST,
                    manager_port=MANAGER_PORT
                )
                result = probe.connect(timeout=CONNECTION_TIMEOUT)
                if result:
                    probes.append(probe)

            # 至少应该有一些连接成功
            self.assertGreater(len(probes), 0, "At least one probe should connect")

            # 所有探针发送状态
            for probe in probes:
                probe.send_status()

            time.sleep(1)

        finally:
            for probe in probes:
                probe.disconnect()

    def test_02_concurrent_messages(self):
        """测试并发消息发送"""
        num_probes = 3
        probes: List[ProbeSimulator] = []

        try:
            # 创建并连接多个探针
            for i in range(num_probes):
                probe = ProbeSimulator(
                    probe_info=ProbeInfo(probe_id=f"test-concurrent-{i:03d}"),
                    manager_host=MANAGER_HOST,
                    manager_port=MANAGER_PORT
                )
                if probe.connect(timeout=CONNECTION_TIMEOUT):
                    probes.append(probe)

            if len(probes) == 0:
                self.skipTest("No probes connected")

            # 并发发送消息
            def send_messages(probe: ProbeSimulator):
                results = []
                for j in range(5):
                    results.append(probe.send_alert(
                        src_ip="192.168.1.1",
                        dest_ip="10.0.0.1",
                        src_port=50000 + j,
                        dest_port=80,
                        protocol="TCP",
                        signature=f"Concurrent Test",
                        signature_id=3000000 + j,
                        severity=2
                    ))
                return all(results)

            with ThreadPoolExecutor(max_workers=num_probes) as executor:
                futures = [executor.submit(send_messages, p) for p in probes]
                results = [f.result() for f in as_completed(futures)]

            # 至少部分成功
            success_count = sum(results)
            self.assertGreater(success_count, 0, "At least some messages should succeed")

        finally:
            for probe in probes:
                probe.disconnect()


class TestProbeTypes(unittest.TestCase):
    """不同类型探针测试"""

    def test_01_nids_probe(self):
        """测试 NIDS 探针"""
        probe = SmartProbeSimulator(
            probe_info=ProbeInfo(
                probe_id="test-nids-001",
                probe_type="nids",
                interface="eth0"
            ),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=CONNECTION_TIMEOUT):
            self.skipTest("Not connected to Manager")

        try:
            probe.send_register()
            probe.send_alert(
                src_ip="192.168.1.100",
                dest_ip="10.0.0.1",
                src_port=54321,
                dest_port=80,
                protocol="TCP",
                signature="ET MALWARE Suspicious User-Agent",
                signature_id=2000001,
                severity=1,
                category="malware"
            )
        finally:
            probe.disconnect()

    def test_02_hids_probe(self):
        """测试 HIDS 探针（预留）"""
        probe = SmartProbeSimulator(
            probe_info=ProbeInfo(
                probe_id="test-hids-001",
                probe_type="hids",
                interface=""
            ),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=CONNECTION_TIMEOUT):
            self.skipTest("Not connected to Manager")

        try:
            probe.send_register()
            # HIDS 类型的告警
            probe.send_event(Event.EVT_ALERT, {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "event_type": "file_integrity",
                "file_path": "/etc/passwd",
                "action": "modified",
                "severity": 2
            })
        finally:
            probe.disconnect()


class TestEdgeCases(unittest.TestCase):
    """边界情况测试"""

    def test_01_empty_data(self):
        """测试空数据发送"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-edge-001"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=CONNECTION_TIMEOUT):
            self.skipTest("Not connected to Manager")

        try:
            # 发送空数据事件
            result = probe.send_event(Event.EVT_STATUS, {})
            self.assertTrue(result, "Empty data should be sent")
        finally:
            probe.disconnect()

    def test_02_large_data(self):
        """测试大数据发送"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-edge-002"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=CONNECTION_TIMEOUT):
            self.skipTest("Not connected to Manager")

        try:
            # 发送大数据
            large_data = {
                "signature": "A" * 10000,  # 10KB 字符串
                "extra_field": ["item"] * 1000
            }
            result = probe.send_event(Event.EVT_ALERT, large_data)
            self.assertTrue(result, "Large data should be sent")
        finally:
            probe.disconnect()

    def test_03_special_characters(self):
        """测试特殊字符"""
        probe = ProbeSimulator(
            probe_info=ProbeInfo(probe_id="test-edge-003"),
            manager_host=MANAGER_HOST,
            manager_port=MANAGER_PORT
        )

        if not probe.connect(timeout=CONNECTION_TIMEOUT):
            self.skipTest("Not connected to Manager")

        try:
            # 发送包含特殊字符的数据
            special_data = {
                "signature": "Test\n\r\t\\\"'特殊字符テスト",
                "unicode": "中文日本語한국어",
                "emoji": "🔥🚨⚠️"
            }
            result = probe.send_event(Event.EVT_ALERT, special_data)
            self.assertTrue(result, "Special characters should be sent")
        finally:
            probe.disconnect()

    def test_04_rapid_connect_disconnect(self):
        """测试快速连接断开"""
        for i in range(10):
            probe = ProbeSimulator(
                probe_info=ProbeInfo(probe_id=f"test-rapid-{i:03d}"),
                manager_host=MANAGER_HOST,
                manager_port=MANAGER_PORT
            )
            probe.connect(timeout=2.0)
            probe.disconnect()
            # 不等待，快速循环


def run_tests():
    """运行所有测试"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # 添加所有测试类
    suite.addTests(loader.loadTestsFromTestCase(TestProbeConnection))
    suite.addTests(loader.loadTestsFromTestCase(TestProbeMessaging))
    suite.addTests(loader.loadTestsFromTestCase(TestSmartProbe))
    suite.addTests(loader.loadTestsFromTestCase(TestProbeLifecycle))
    suite.addTests(loader.loadTestsFromTestCase(TestMultipleProbes))
    suite.addTests(loader.loadTestsFromTestCase(TestProbeTypes))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))

    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
