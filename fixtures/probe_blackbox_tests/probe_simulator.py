#!/usr/bin/env python3
"""
Probe Simulator - 模拟探针与 Probe Manager 的 TCP Socket 通信

协议格式:
- Header: 4 字节 (uint32_t length, 网络字节序 big-endian)
- Payload: JSON 字符串

Manager -> 探针 命令 (Command):
- CMD_START = 1
- CMD_STOP = 2
- CMD_RELOAD_RULES = 3
- CMD_GET_STATUS = 4
- CMD_SHUTDOWN = 5

探针 -> Manager 事件 (Event):
- EVT_ALERT = 1
- EVT_STATUS = 2
- EVT_ERROR = 3
- EVT_ACK = 4
"""

import socket
import struct
import json
import time
import threading
import logging
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from enum import IntEnum
from queue import Queue, Empty


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ProbeSimulator')


class Command(IntEnum):
    """Manager -> 探针 命令"""
    CMD_START = 1
    CMD_STOP = 2
    CMD_RELOAD_RULES = 3
    CMD_GET_STATUS = 4
    CMD_SHUTDOWN = 5


class Event(IntEnum):
    """探针 -> Manager 事件"""
    EVT_ALERT = 1
    EVT_STATUS = 2
    EVT_ERROR = 3
    EVT_ACK = 4


HEADER_SIZE = 4  # uint32_t


@dataclass
class ProbeInfo:
    """探针信息"""
    probe_id: str
    probe_type: str = "nids"
    interface: str = "eth0"
    status: str = "stopped"
    metrics: dict = field(default_factory=dict)


class ProbeSimulator:
    """
    探针模拟器 - 模拟单个探针与 Probe Manager 的通信
    """

    def __init__(
        self,
        probe_info: ProbeInfo,
        manager_host: str = "127.0.0.1",
        manager_port: int = 9010
    ):
        self.probe_info = probe_info
        self.manager_host = manager_host
        self.manager_port = manager_port

        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.running = False

        # 接收消息队列
        self.received_messages: Queue = Queue()

        # 回调函数
        self.command_handlers: dict[int, Callable] = {}

        # 接收线程
        self._recv_thread: Optional[threading.Thread] = None

        # 读取缓冲区
        self._read_buffer = b''

    def connect(self, timeout: float = 5.0) -> bool:
        """连接到 Probe Manager"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            self.socket.connect((self.manager_host, self.manager_port))
            self.connected = True
            logger.info(f"Connected to Manager at {self.manager_host}:{self.manager_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False

    def disconnect(self):
        """断开连接"""
        self.running = False
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        logger.info("Disconnected from Manager")

    def start_receiving(self):
        """启动接收线程"""
        self.running = True
        self._recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self._recv_thread.start()

    def stop_receiving(self):
        """停止接收线程"""
        self.running = False
        if self._recv_thread:
            self._recv_thread.join(timeout=2.0)

    def _receive_loop(self):
        """接收消息循环"""
        while self.running and self.connected:
            try:
                msg = self._read_message(timeout=0.5)
                if msg is not None:
                    self.received_messages.put(msg)
                    self._handle_message(msg)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Receive error: {e}")
                break

    def _read_message(self, timeout: float = 5.0) -> Optional[dict]:
        """读取一条消息"""
        if not self.socket:
            return None

        self.socket.settimeout(timeout)

        # 读取头部
        while len(self._read_buffer) < HEADER_SIZE:
            try:
                data = self.socket.recv(4096)
                if not data:
                    self.connected = False
                    return None
                self._read_buffer += data
            except socket.timeout:
                return None

        # 解析长度
        length = struct.unpack('!I', self._read_buffer[:HEADER_SIZE])[0]

        # 读取 payload
        while len(self._read_buffer) < HEADER_SIZE + length:
            try:
                data = self.socket.recv(4096)
                if not data:
                    self.connected = False
                    return None
                self._read_buffer += data
            except socket.timeout:
                return None

        # 解析 JSON
        payload = self._read_buffer[HEADER_SIZE:HEADER_SIZE + length]
        self._read_buffer = self._read_buffer[HEADER_SIZE + length:]

        try:
            return json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return None

    def _send_message(self, msg: dict) -> bool:
        """发送一条消息"""
        if not self.socket or not self.connected:
            return False

        try:
            payload = json.dumps(msg).encode('utf-8')
            length = struct.pack('!I', len(payload))
            self.socket.sendall(length + payload)
            return True
        except Exception as e:
            logger.error(f"Send error: {e}")
            self.connected = False
            return False

    def _handle_message(self, msg: dict):
        """处理收到的消息"""
        cmd = msg.get('cmd') or msg.get('command')
        if cmd and cmd in self.command_handlers:
            self.command_handlers[cmd](msg)

    def register_command_handler(self, cmd: int, handler: Callable):
        """注册命令处理器"""
        self.command_handlers[cmd] = handler

    # ==================== 探针行为模拟 ====================

    def send_event(self, event: Event, data: dict) -> bool:
        """发送事件到 Manager"""
        msg = {
            "event": event.name,
            "probe_id": self.probe_info.probe_id,
            "probe_type": self.probe_info.probe_type,
            "data": data
        }
        return self._send_message(msg)

    def send_register(self) -> bool:
        """发送探针注册消息"""
        data = {
            "probe_id": self.probe_info.probe_id,
            "probe_type": self.probe_info.probe_type,
            "interface": self.probe_info.interface,
            "capabilities": ["nids", "flow_analysis"]
        }
        return self.send_event(Event.EVT_STATUS, data)

    def send_status(self) -> bool:
        """发送状态更新"""
        data = {
            "status": self.probe_info.status,
            "metrics": self.probe_info.metrics,
            "uptime": int(time.time()),
            "cpu_usage": 25.5,
            "memory_usage": 512 * 1024 * 1024
        }
        return self.send_event(Event.EVT_STATUS, data)

    def send_alert(
        self,
        src_ip: str,
        dest_ip: str,
        src_port: int,
        dest_port: int,
        protocol: str,
        signature: str,
        signature_id: int,
        severity: int = 2,
        category: str = "misc"
    ) -> bool:
        """发送告警日志"""
        data = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": src_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "alert": {
                "signature": signature,
                "signature_id": signature_id,
                "severity": severity,
                "category": category
            }
        }
        return self.send_event(Event.EVT_ALERT, data)

    def send_ack(self, cmd: int, success: bool = True, message: str = "") -> bool:
        """发送命令确认"""
        data = {
            "cmd": cmd,
            "success": success,
            "message": message
        }
        return self.send_event(Event.EVT_ACK, data)

    def send_error(self, error_code: int, error_msg: str) -> bool:
        """发送错误消息"""
        data = {
            "error_code": error_code,
            "error_msg": error_msg
        }
        return self.send_event(Event.EVT_ERROR, data)

    def wait_for_message(self, timeout: float = 5.0) -> Optional[dict]:
        """等待接收一条消息"""
        try:
            return self.received_messages.get(timeout=timeout)
        except Empty:
            return None

    def get_all_messages(self) -> list:
        """获取所有已接收的消息"""
        messages = []
        while True:
            try:
                msg = self.received_messages.get_nowait()
                messages.append(msg)
            except Empty:
                break
        return messages


class SmartProbeSimulator(ProbeSimulator):
    """
    智能探针模拟器 - 自动响应 Manager 的命令
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._setup_default_handlers()

    def _setup_default_handlers(self):
        """设置默认命令处理器"""
        self.register_command_handler(Command.CMD_START, self._handle_start)
        self.register_command_handler(Command.CMD_STOP, self._handle_stop)
        self.register_command_handler(Command.CMD_RELOAD_RULES, self._handle_reload_rules)
        self.register_command_handler(Command.CMD_GET_STATUS, self._handle_get_status)
        self.register_command_handler(Command.CMD_SHUTDOWN, self._handle_shutdown)

    def _handle_start(self, msg: dict):
        """处理启动命令"""
        logger.info(f"Received START command")
        self.probe_info.status = "running"
        self.send_ack(Command.CMD_START, True, "Probe started")

    def _handle_stop(self, msg: dict):
        """处理停止命令"""
        logger.info(f"Received STOP command")
        self.probe_info.status = "stopped"
        self.send_ack(Command.CMD_STOP, True, "Probe stopped")

    def _handle_reload_rules(self, msg: dict):
        """处理规则重载命令"""
        logger.info(f"Received RELOAD_RULES command")
        rules_version = msg.get('data', {}).get('version', 'unknown')
        self.send_ack(Command.CMD_RELOAD_RULES, True, f"Rules reloaded: {rules_version}")

    def _handle_get_status(self, msg: dict):
        """处理获取状态命令"""
        logger.info(f"Received GET_STATUS command")
        self.send_status()

    def _handle_shutdown(self, msg: dict):
        """处理关闭命令"""
        logger.info(f"Received SHUTDOWN command")
        self.send_ack(Command.CMD_SHUTDOWN, True, "Shutting down")
        self.disconnect()


def send_raw_message(host: str, port: int, data: bytes, timeout: float = 5.0) -> Optional[bytes]:
    """发送原始字节数据（用于测试协议边界情况）"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(data)
            return sock.recv(4096)
    except Exception as e:
        logger.error(f"Raw send error: {e}")
        return None


def send_malformed_header(host: str, port: int) -> Optional[bytes]:
    """发送格式错误的头部"""
    # 发送一个声称有 1GB 数据但实际没有的消息
    header = struct.pack('!I', 1024 * 1024 * 1024)
    return send_raw_message(host, port, header + b'{}', timeout=2.0)


def send_partial_message(host: str, port: int) -> bool:
    """发送不完整的消息"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect((host, port))
            # 只发送头部，不发送 payload
            header = struct.pack('!I', 100)
            sock.sendall(header)
            time.sleep(1)
            # 然后断开
            return True
    except Exception as e:
        logger.error(f"Partial send error: {e}")
        return False


if __name__ == "__main__":
    # 简单测试
    probe = SmartProbeSimulator(
        probe_info=ProbeInfo(probe_id="test-probe-001"),
        manager_host="127.0.0.1",
        manager_port=9010
    )

    if probe.connect():
        probe.start_receiving()
        probe.send_register()
        probe.send_status()

        # 发送一些测试告警
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

        time.sleep(5)
        probe.disconnect()
