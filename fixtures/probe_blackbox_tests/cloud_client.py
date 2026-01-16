#!/usr/bin/env python3
"""
Cloud API Client - 模拟 Probe Manager 与云端的 HTTP 通信

云端通信命令码 (CloudCommand):
- LOG_UPLOAD = 10
- LOG_UPLOAD_RESPONSE = 11
- HEARTBEAT = 20
- HEARTBEAT_RESPONSE = 21
- REGISTER = 30
- REGISTER_RESPONSE = 31
- RULE_DOWNLOAD = 40
- RULE_DOWNLOAD_RESPONSE = 41

所有请求通过统一入口: POST /api/v1/probe
请求格式: {"cmd": <命令码>, "data": {...}}
响应格式: {"cmd": <响应命令码>, "data": {...}}
"""

import requests
import json
import time
import logging
from typing import Optional, Any
from dataclasses import dataclass
from enum import IntEnum


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('CloudClient')


class CloudCommand(IntEnum):
    """云端通信命令码"""
    LOG_UPLOAD = 10
    LOG_UPLOAD_RESPONSE = 11
    HEARTBEAT = 20
    HEARTBEAT_RESPONSE = 21
    REGISTER = 30
    REGISTER_RESPONSE = 31
    RULE_DOWNLOAD = 40
    RULE_DOWNLOAD_RESPONSE = 41


@dataclass
class CloudResponse:
    """云端响应"""
    success: bool
    cmd: int
    data: dict
    http_status: int
    raw_response: Optional[dict] = None
    error_message: Optional[str] = None


class CloudAPIClient:
    """
    云端 API 客户端 - 模拟 Probe Manager 与云端的通信
    """

    def __init__(self, base_url: str = "http://localhost", timeout: float = 10.0):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def _send_request(self, cmd: int, data: dict) -> CloudResponse:
        """发送请求到云端统一入口"""
        url = f"{self.base_url}/api/v1/probe"
        payload = {"cmd": cmd, "data": data}

        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)
            result = response.json()

            return CloudResponse(
                success=result.get('data', {}).get('status') != 'error',
                cmd=result.get('cmd', cmd + 1),
                data=result.get('data', {}),
                http_status=response.status_code,
                raw_response=result
            )
        except requests.exceptions.Timeout:
            return CloudResponse(
                success=False,
                cmd=cmd + 1,
                data={},
                http_status=0,
                error_message="Request timeout"
            )
        except requests.exceptions.ConnectionError as e:
            return CloudResponse(
                success=False,
                cmd=cmd + 1,
                data={},
                http_status=0,
                error_message=f"Connection error: {e}"
            )
        except json.JSONDecodeError as e:
            return CloudResponse(
                success=False,
                cmd=cmd + 1,
                data={},
                http_status=response.status_code if response else 0,
                error_message=f"JSON decode error: {e}"
            )
        except Exception as e:
            return CloudResponse(
                success=False,
                cmd=cmd + 1,
                data={},
                http_status=0,
                error_message=f"Unknown error: {e}"
            )

    # ==================== 探针通信 API ====================

    def register_probe(
        self,
        probe_id: str,
        name: str,
        ip: str,
        probe_types: list[str]
    ) -> CloudResponse:
        """
        探针注册 (cmd=30)

        请求:
            probe_id: 探针唯一标识
            name: 探针名称
            ip: 探针 IP 地址
            probe_types: 支持的探针类型列表

        响应 (cmd=31):
            status: "ok" | "error"
            probe_id: 探针 ID
            message: 消息
        """
        data = {
            "probe_id": probe_id,
            "name": name,
            "ip": ip,
            "probe_types": probe_types
        }
        logger.info(f"Register probe: {probe_id}")
        return self._send_request(CloudCommand.REGISTER, data)

    def heartbeat(
        self,
        probe_id: str,
        rule_version: Optional[str],
        status: dict,
        probes: list[dict]
    ) -> CloudResponse:
        """
        心跳请求 (cmd=20)

        请求:
            probe_id: 探针 ID
            rule_version: 当前规则版本
            status: 系统状态 (cpu_usage, memory_usage, uptime 等)
            probes: 探针实例列表

        响应 (cmd=21):
            status: "ok" | "error"
            latest_rule_version: 最新规则版本
            server_time: 服务器时间
        """
        data = {
            "probe_id": probe_id,
            "rule_version": rule_version,
            "status": status,
            "probes": probes
        }
        logger.info(f"Heartbeat: {probe_id}")
        return self._send_request(CloudCommand.HEARTBEAT, data)

    def download_rules(self, probe_id: str, version: str) -> CloudResponse:
        """
        规则下载 (cmd=40)

        请求:
            probe_id: 探针 ID
            version: 要下载的规则版本

        响应 (cmd=41):
            status: "ok" | "error"
            version: 规则版本
            content: 规则内容
            checksum: 校验和
        """
        data = {
            "probe_id": probe_id,
            "version": version
        }
        logger.info(f"Download rules: {probe_id}, version={version}")
        return self._send_request(CloudCommand.RULE_DOWNLOAD, data)

    def upload_logs(self, probe_id: str, logs: list[dict]) -> CloudResponse:
        """
        日志上报 (cmd=10)

        请求:
            probe_id: 探针 ID
            logs: 日志列表

        响应 (cmd=11):
            status: "ok" | "error"
            received: 接收的日志数量
            message: 消息
        """
        data = {
            "probe_id": probe_id,
            "logs": logs
        }
        logger.info(f"Upload logs: {probe_id}, count={len(logs)}")
        return self._send_request(CloudCommand.LOG_UPLOAD, data)

    # ==================== 前端 API ====================

    def health_check(self) -> bool:
        """健康检查"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=self.timeout)
            return response.status_code == 200
        except:
            return False

    def get_rules_list(self, limit: int = 20) -> Optional[dict]:
        """获取规则版本列表"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/rules",
                params={"limit": limit},
                timeout=self.timeout
            )
            return response.json() if response.status_code == 200 else None
        except:
            return None

    def create_rule(self, content: str, description: str = "", timeout: Optional[float] = None) -> Optional[dict]:
        """创建新规则版本"""
        try:
            # 对于大规则使用更长的超时时间
            request_timeout = timeout or max(self.timeout, 30.0)
            response = self.session.post(
                f"{self.base_url}/api/v1/rules",
                json={"content": content, "description": description},
                timeout=request_timeout
            )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            logger.warning(f"Create rule failed: {e}")
            return None

    def get_rule_by_version(self, version: str) -> Optional[dict]:
        """获取指定版本规则"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/rules/{version}",
                timeout=self.timeout
            )
            return response.json() if response.status_code == 200 else None
        except:
            return None

    def get_latest_rule(self) -> Optional[dict]:
        """获取最新规则"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/rules/latest",
                timeout=self.timeout
            )
            return response.json() if response.status_code == 200 else None
        except:
            return None

    def get_logs(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        probe_id: Optional[str] = None,
        severity: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Optional[dict]:
        """查询告警日志"""
        params = {"limit": limit, "offset": offset}
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
        if probe_id:
            params["probe_id"] = probe_id
        if severity is not None:
            params["severity"] = severity

        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/logs",
                params=params,
                timeout=self.timeout
            )
            return response.json() if response.status_code == 200 else None
        except:
            return None

    def get_log_stats(self, hours: int = 24) -> Optional[dict]:
        """获取日志统计"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/logs/stats",
                params={"hours": hours},
                timeout=self.timeout
            )
            return response.json() if response.status_code == 200 else None
        except:
            return None

    def get_probes_list(self) -> Optional[dict]:
        """获取探针列表"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/probes",
                timeout=self.timeout
            )
            return response.json() if response.status_code == 200 else None
        except:
            return None

    def get_probe_detail(self, probe_id: str) -> Optional[dict]:
        """获取探针详情"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/probes/{probe_id}",
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "not_found"}
            return None
        except:
            return None


def generate_test_log(
    probe_id: str = "test-probe",
    instance_id: str = "test-instance",
    probe_type: str = "nids"
) -> dict:
    """生成测试日志"""
    import random
    return {
        "probe_type": probe_type,
        "instance_id": instance_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f", time.gmtime())[:-3] + "Z",
        "src_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "dest_ip": f"10.0.{random.randint(0, 254)}.{random.randint(1, 254)}",
        "src_port": random.randint(1024, 65535),
        "dest_port": random.choice([80, 443, 22, 3389, 8080]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "alert": {
            "signature": f"Test Signature {random.randint(1, 100)}",
            "signature_id": random.randint(1000000, 9999999),
            "severity": random.randint(1, 3),
            "category": random.choice(["malware", "exploit", "policy", "misc"])
        },
        "raw": '{"test": "raw_log"}'
    }


def generate_test_rule(rule_id: int = 1) -> str:
    """生成测试规则"""
    return f"""# Suricata Test Rules - Generated
alert tcp any any -> any any (msg:"Test Rule {rule_id}"; sid:{1000000 + rule_id}; rev:1;)
alert udp any any -> any 53 (msg:"DNS Query Test {rule_id}"; sid:{1000100 + rule_id}; rev:1;)
"""


if __name__ == "__main__":
    # 简单测试
    client = CloudAPIClient("http://localhost")

    # 健康检查
    if client.health_check():
        print("Health check: OK")

        # 探针注册
        resp = client.register_probe(
            probe_id="test-probe-001",
            name="Test Probe 1",
            ip="192.168.1.100",
            probe_types=["nids"]
        )
        print(f"Register: {resp}")

        # 心跳
        resp = client.heartbeat(
            probe_id="test-probe-001",
            rule_version=None,
            status={"cpu_usage": 25.5, "memory_usage": 512},
            probes=[{"type": "nids", "id": "nids-001", "status": "running"}]
        )
        print(f"Heartbeat: {resp}")

        # 创建规则
        rule_result = client.create_rule(
            content=generate_test_rule(1),
            description="Test rule version"
        )
        print(f"Create rule: {rule_result}")

        # 上报日志
        logs = [generate_test_log() for _ in range(5)]
        resp = client.upload_logs("test-probe-001", logs)
        print(f"Upload logs: {resp}")

    else:
        print("Health check: FAILED - Server not available")
