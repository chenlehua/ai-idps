#!/usr/bin/env python3
"""
Cloud Communication Tests - 测试 Probe Manager 与云端的 HTTP 通信

测试场景:
1. 健康检查测试
2. 探针注册流程测试
3. 心跳机制测试
4. 规则下载测试
5. 日志上报测试
6. 错误处理测试
7. 完整工作流测试
"""

import unittest
import time
import uuid
from typing import Optional

from cloud_client import (
    CloudAPIClient,
    CloudCommand,
    CloudResponse,
    generate_test_log,
    generate_test_rule
)


# 测试配置
CLOUD_BASE_URL = "http://localhost"


class TestHealthCheck(unittest.TestCase):
    """健康检查测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)

    def test_01_health_check(self):
        """测试健康检查接口"""
        result = self.client.health_check()
        self.assertTrue(result, "Health check should return OK")


class TestProbeRegistration(unittest.TestCase):
    """探针注册测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)
        self.probe_id = f"test-probe-{uuid.uuid4().hex[:8]}"

    def test_01_register_new_probe(self):
        """测试注册新探针"""
        response = self.client.register_probe(
            probe_id=self.probe_id,
            name="Test Probe Registration",
            ip="192.168.1.100",
            probe_types=["nids"]
        )

        self.assertEqual(response.http_status, 200, "HTTP status should be 200")
        self.assertEqual(response.cmd, CloudCommand.REGISTER_RESPONSE, "Response cmd should be 31")
        self.assertEqual(response.data.get("status"), "ok", "Status should be ok")

    def test_02_register_with_multiple_types(self):
        """测试注册多类型探针"""
        response = self.client.register_probe(
            probe_id=f"{self.probe_id}-multi",
            name="Multi-type Probe",
            ip="192.168.1.101",
            probe_types=["nids", "hids", "firewall"]
        )

        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.data.get("status"), "ok")

    def test_03_register_duplicate_probe(self):
        """测试重复注册探针（应该更新）"""
        # 第一次注册
        self.client.register_probe(
            probe_id=self.probe_id,
            name="First Registration",
            ip="192.168.1.100",
            probe_types=["nids"]
        )

        # 第二次注册（相同 ID）
        response = self.client.register_probe(
            probe_id=self.probe_id,
            name="Second Registration",
            ip="192.168.1.200",
            probe_types=["nids", "hids"]
        )

        self.assertEqual(response.http_status, 200)
        # 应该成功（更新现有探针）
        self.assertEqual(response.data.get("status"), "ok")

    def test_04_register_with_empty_types(self):
        """测试注册空类型探针"""
        response = self.client.register_probe(
            probe_id=f"{self.probe_id}-empty",
            name="Empty Types Probe",
            ip="192.168.1.102",
            probe_types=[]
        )

        # 应该成功或返回错误
        self.assertEqual(response.http_status, 200)


class TestHeartbeat(unittest.TestCase):
    """心跳机制测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)
        self.probe_id = f"test-heartbeat-{uuid.uuid4().hex[:8]}"

        # 先注册探针
        self.client.register_probe(
            probe_id=self.probe_id,
            name="Heartbeat Test Probe",
            ip="192.168.1.100",
            probe_types=["nids"]
        )

    def test_01_basic_heartbeat(self):
        """测试基本心跳"""
        response = self.client.heartbeat(
            probe_id=self.probe_id,
            rule_version=None,
            status={
                "cpu_usage": 25.5,
                "memory_usage": 512 * 1024 * 1024,
                "uptime": 3600
            },
            probes=[
                {
                    "type": "nids",
                    "id": f"{self.probe_id}-nids",
                    "status": "running",
                    "interface": "eth0"
                }
            ]
        )

        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.cmd, CloudCommand.HEARTBEAT_RESPONSE)
        self.assertEqual(response.data.get("status"), "ok")
        self.assertIn("server_time", response.data)

    def test_02_heartbeat_with_rule_version(self):
        """测试带规则版本的心跳"""
        response = self.client.heartbeat(
            probe_id=self.probe_id,
            rule_version="v1234567890",
            status={"cpu_usage": 30.0},
            probes=[]
        )

        self.assertEqual(response.http_status, 200)
        # 响应应包含最新规则版本
        self.assertIn("latest_rule_version", response.data)

    def test_03_multiple_heartbeats(self):
        """测试连续心跳"""
        for i in range(5):
            response = self.client.heartbeat(
                probe_id=self.probe_id,
                rule_version=None,
                status={
                    "cpu_usage": 20.0 + i * 5,
                    "memory_usage": 500 * 1024 * 1024 + i * 10 * 1024 * 1024
                },
                probes=[]
            )

            self.assertEqual(response.http_status, 200, f"Heartbeat {i} should succeed")
            time.sleep(0.1)

    def test_04_heartbeat_from_unregistered_probe(self):
        """测试未注册探针的心跳"""
        response = self.client.heartbeat(
            probe_id="nonexistent-probe-12345",
            rule_version=None,
            status={},
            probes=[]
        )

        # 应该返回成功（自动注册）或错误
        self.assertEqual(response.http_status, 200)


class TestRuleManagement(unittest.TestCase):
    """规则管理测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)
        self.probe_id = f"test-rules-{uuid.uuid4().hex[:8]}"

        # 注册探针
        self.client.register_probe(
            probe_id=self.probe_id,
            name="Rules Test Probe",
            ip="192.168.1.100",
            probe_types=["nids"]
        )

    def test_01_create_rule(self):
        """测试创建规则"""
        result = self.client.create_rule(
            content=generate_test_rule(1),
            description="Test rule creation"
        )

        self.assertIsNotNone(result, "Should create rule successfully")
        self.assertIn("version", result)
        self.assertIn("checksum", result)

    def test_02_get_rules_list(self):
        """测试获取规则列表"""
        # 先创建一个规则
        self.client.create_rule(
            content=generate_test_rule(2),
            description="Test rule for list"
        )

        result = self.client.get_rules_list(limit=10)
        self.assertIsNotNone(result)
        self.assertIn("versions", result)

    def test_03_get_latest_rule(self):
        """测试获取最新规则"""
        # 创建规则
        created = self.client.create_rule(
            content=generate_test_rule(3),
            description="Latest rule test"
        )

        if created:
            result = self.client.get_latest_rule()
            self.assertIsNotNone(result)
            self.assertIn("version", result)
            self.assertIn("content", result)

    def test_04_download_rule_via_probe_api(self):
        """测试通过探针 API 下载规则"""
        # 创建规则
        created = self.client.create_rule(
            content=generate_test_rule(4),
            description="Download test rule"
        )

        if created and "version" in created:
            response = self.client.download_rules(
                probe_id=self.probe_id,
                version=created["version"]
            )

            self.assertEqual(response.http_status, 200)
            self.assertEqual(response.cmd, CloudCommand.RULE_DOWNLOAD_RESPONSE)
            self.assertEqual(response.data.get("status"), "ok")
            self.assertIn("content", response.data)

    def test_05_download_nonexistent_rule(self):
        """测试下载不存在的规则"""
        response = self.client.download_rules(
            probe_id=self.probe_id,
            version="v9999999999"
        )

        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.data.get("status"), "error")


class TestLogUpload(unittest.TestCase):
    """日志上报测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)
        self.probe_id = f"test-logs-{uuid.uuid4().hex[:8]}"

        # 注册探针
        self.client.register_probe(
            probe_id=self.probe_id,
            name="Log Upload Test Probe",
            ip="192.168.1.100",
            probe_types=["nids"]
        )

    def test_01_upload_single_log(self):
        """测试上报单条日志"""
        log = generate_test_log(probe_id=self.probe_id)
        response = self.client.upload_logs(self.probe_id, [log])

        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.cmd, CloudCommand.LOG_UPLOAD_RESPONSE)
        self.assertEqual(response.data.get("status"), "ok")
        self.assertEqual(response.data.get("received"), 1)

    def test_02_upload_multiple_logs(self):
        """测试上报多条日志"""
        logs = [generate_test_log(probe_id=self.probe_id) for _ in range(10)]
        response = self.client.upload_logs(self.probe_id, logs)

        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.data.get("status"), "ok")
        self.assertEqual(response.data.get("received"), 10)

    def test_03_upload_empty_logs(self):
        """测试上报空日志列表"""
        response = self.client.upload_logs(self.probe_id, [])

        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.data.get("received"), 0)

    def test_04_upload_large_batch(self):
        """测试上报大批量日志"""
        logs = [generate_test_log(probe_id=self.probe_id) for _ in range(100)]
        response = self.client.upload_logs(self.probe_id, logs)

        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.data.get("status"), "ok")
        self.assertEqual(response.data.get("received"), 100)


class TestLogQuery(unittest.TestCase):
    """日志查询测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)
        self.probe_id = f"test-query-{uuid.uuid4().hex[:8]}"

        # 注册探针并上报一些日志
        self.client.register_probe(
            probe_id=self.probe_id,
            name="Log Query Test Probe",
            ip="192.168.1.100",
            probe_types=["nids"]
        )

        # 上报测试日志
        logs = [generate_test_log(probe_id=self.probe_id) for _ in range(5)]
        self.client.upload_logs(self.probe_id, logs)
        time.sleep(0.5)  # 等待写入

    def test_01_query_all_logs(self):
        """测试查询所有日志"""
        result = self.client.get_logs(limit=100)
        self.assertIsNotNone(result)
        self.assertIn("logs", result)

    def test_02_query_by_probe_id(self):
        """测试按探针 ID 查询"""
        result = self.client.get_logs(probe_id=self.probe_id, limit=100)
        self.assertIsNotNone(result)
        self.assertIn("logs", result)

    def test_03_query_by_severity(self):
        """测试按严重级别查询"""
        result = self.client.get_logs(severity=1, limit=100)
        self.assertIsNotNone(result)
        self.assertIn("logs", result)

    def test_04_query_with_pagination(self):
        """测试分页查询"""
        result1 = self.client.get_logs(limit=10, offset=0)
        result2 = self.client.get_logs(limit=10, offset=10)

        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)

    def test_05_get_log_stats(self):
        """测试获取日志统计"""
        result = self.client.get_log_stats(hours=24)
        self.assertIsNotNone(result)
        self.assertIn("stats", result)


class TestProbeManagement(unittest.TestCase):
    """探针管理测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)
        self.probe_id = f"test-mgmt-{uuid.uuid4().hex[:8]}"

        # 注册探针
        self.client.register_probe(
            probe_id=self.probe_id,
            name="Management Test Probe",
            ip="192.168.1.100",
            probe_types=["nids"]
        )

    def test_01_get_probes_list(self):
        """测试获取探针列表"""
        result = self.client.get_probes_list()
        self.assertIsNotNone(result)
        self.assertIn("probes", result)

    def test_02_get_probe_detail(self):
        """测试获取探针详情"""
        result = self.client.get_probe_detail(self.probe_id)
        self.assertIsNotNone(result)
        # 检查没有错误
        self.assertNotEqual(result.get("error"), "not_found")

    def test_03_get_nonexistent_probe(self):
        """测试获取不存在的探针"""
        result = self.client.get_probe_detail("nonexistent-probe-xyz")
        self.assertIsNotNone(result)
        self.assertEqual(result.get("error"), "not_found")


class TestUnknownCommand(unittest.TestCase):
    """未知命令测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)

    def test_01_unknown_command(self):
        """测试未知命令"""
        response = self.client._send_request(99, {"test": "data"})

        self.assertEqual(response.http_status, 200)
        # 应返回错误响应
        self.assertEqual(response.data.get("status"), "error")


class TestFullWorkflow(unittest.TestCase):
    """完整工作流测试"""

    def setUp(self):
        self.client = CloudAPIClient(CLOUD_BASE_URL)
        self.probe_id = f"test-workflow-{uuid.uuid4().hex[:8]}"

    def test_01_complete_probe_workflow(self):
        """测试完整的探针工作流程"""
        # 1. 健康检查
        self.assertTrue(self.client.health_check(), "Health check failed")

        # 2. 探针注册
        reg_response = self.client.register_probe(
            probe_id=self.probe_id,
            name="Workflow Test Probe",
            ip="192.168.1.100",
            probe_types=["nids"]
        )
        self.assertEqual(reg_response.data.get("status"), "ok", "Registration failed")

        # 3. 创建规则
        rule_result = self.client.create_rule(
            content=generate_test_rule(100),
            description="Workflow test rule"
        )
        self.assertIsNotNone(rule_result, "Rule creation failed")
        rule_version = rule_result.get("version")

        # 4. 心跳（检查规则版本）
        hb_response = self.client.heartbeat(
            probe_id=self.probe_id,
            rule_version=None,
            status={"cpu_usage": 10.0},
            probes=[]
        )
        self.assertEqual(hb_response.data.get("status"), "ok", "Heartbeat failed")
        latest_version = hb_response.data.get("latest_rule_version")

        # 5. 下载规则
        if latest_version:
            dl_response = self.client.download_rules(self.probe_id, latest_version)
            self.assertEqual(dl_response.data.get("status"), "ok", "Rule download failed")

        # 6. 上报日志
        logs = [generate_test_log(probe_id=self.probe_id) for _ in range(5)]
        log_response = self.client.upload_logs(self.probe_id, logs)
        self.assertEqual(log_response.data.get("status"), "ok", "Log upload failed")

        # 7. 继续心跳（更新规则版本）
        hb2_response = self.client.heartbeat(
            probe_id=self.probe_id,
            rule_version=latest_version,
            status={"cpu_usage": 20.0},
            probes=[{"type": "nids", "id": "nids-001", "status": "running"}]
        )
        self.assertEqual(hb2_response.data.get("status"), "ok", "Second heartbeat failed")

        # 8. 查询日志
        logs_result = self.client.get_logs(probe_id=self.probe_id)
        self.assertIsNotNone(logs_result, "Log query failed")

        # 9. 获取探针详情
        probe_detail = self.client.get_probe_detail(self.probe_id)
        self.assertIsNotNone(probe_detail, "Probe detail query failed")


def run_tests():
    """运行所有测试"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # 添加所有测试类
    suite.addTests(loader.loadTestsFromTestCase(TestHealthCheck))
    suite.addTests(loader.loadTestsFromTestCase(TestProbeRegistration))
    suite.addTests(loader.loadTestsFromTestCase(TestHeartbeat))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleManagement))
    suite.addTests(loader.loadTestsFromTestCase(TestLogUpload))
    suite.addTests(loader.loadTestsFromTestCase(TestLogQuery))
    suite.addTests(loader.loadTestsFromTestCase(TestProbeManagement))
    suite.addTests(loader.loadTestsFromTestCase(TestUnknownCommand))
    suite.addTests(loader.loadTestsFromTestCase(TestFullWorkflow))

    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
