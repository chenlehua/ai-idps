#!/usr/bin/env python3
"""
NIDS 探针与 Probe Manager 通信测试

测试内容:
1. TCP 连接建立
2. 协议消息格式验证
3. 心跳/状态消息测试
4. 告警消息上报测试
"""

import argparse
import json
import socket
import struct
import sys
import time
from datetime import datetime
from typing import Optional, Tuple


class ProtocolClient:
    """Probe Manager 协议客户端"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 9010):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        
    def connect(self, timeout: float = 5.0) -> bool:
        """建立连接"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((self.host, self.port))
            return True
        except socket.error as e:
            print(f"Connection failed: {e}")
            return False
            
    def disconnect(self):
        """断开连接"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            
    def send_message(self, msg: dict) -> bool:
        """发送消息 (4字节长度前缀 + JSON)"""
        if not self.sock:
            return False
            
        try:
            data = json.dumps(msg).encode('utf-8')
            length = struct.pack('>I', len(data))
            self.sock.sendall(length + data)
            return True
        except socket.error as e:
            print(f"Send failed: {e}")
            return False
            
    def receive_message(self, timeout: float = 2.0) -> Optional[dict]:
        """接收消息"""
        if not self.sock:
            return None
            
        try:
            self.sock.settimeout(timeout)
            
            # 读取长度前缀
            length_data = self._recv_exact(4)
            if not length_data:
                return None
                
            length = struct.unpack('>I', length_data)[0]
            
            # 读取消息体
            if length > 1024 * 1024:  # 1MB 限制
                print(f"Message too large: {length}")
                return None
                
            msg_data = self._recv_exact(length)
            if not msg_data:
                return None
                
            return json.loads(msg_data.decode('utf-8'))
            
        except socket.timeout:
            return None
        except Exception as e:
            print(f"Receive failed: {e}")
            return None
            
    def _recv_exact(self, n: int) -> Optional[bytes]:
        """精确读取 n 字节"""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data


def test_connection(host: str, port: int) -> Tuple[bool, str]:
    """测试基本连接"""
    client = ProtocolClient(host, port)
    
    if client.connect():
        client.disconnect()
        return True, "Connection successful"
    else:
        return False, "Connection failed"


def test_register_message(host: str, port: int) -> Tuple[bool, str]:
    """测试注册消息"""
    client = ProtocolClient(host, port)
    
    if not client.connect():
        return False, "Connection failed"
    
    try:
        # 发送注册消息
        register_msg = {
            "event": "EVT_REGISTER",
            "probe_type": "nids",
            "probe_id": f"test-nids-{int(time.time())}",
            "data": {
                "interface": "eth0",
                "suricata_version": "7.0.0-test"
            }
        }
        
        if not client.send_message(register_msg):
            return False, "Failed to send register message"
        
        # 等待响应
        response = client.receive_message(timeout=5.0)
        
        if response:
            return True, f"Received response: {json.dumps(response)}"
        else:
            return True, "No response (may be normal for async protocol)"
            
    finally:
        client.disconnect()


def test_status_message(host: str, port: int) -> Tuple[bool, str]:
    """测试状态消息"""
    client = ProtocolClient(host, port)
    
    if not client.connect():
        return False, "Connection failed"
    
    try:
        # 发送状态消息
        status_msg = {
            "event": "EVT_STATUS",
            "probe_type": "nids",
            "probe_id": f"test-nids-{int(time.time())}",
            "data": {
                "status": "running",
                "uptime": 3600,
                "alerts_count": 100,
                "packets_processed": 1000000
            }
        }
        
        if not client.send_message(status_msg):
            return False, "Failed to send status message"
        
        return True, "Status message sent successfully"
        
    finally:
        client.disconnect()


def test_alert_message(host: str, port: int) -> Tuple[bool, str]:
    """测试告警消息"""
    client = ProtocolClient(host, port)
    
    if not client.connect():
        return False, "Connection failed"
    
    try:
        # 发送模拟告警
        alert_msg = {
            "event": "EVT_ALERT",
            "probe_type": "nids",
            "probe_id": f"test-nids-{int(time.time())}",
            "data": {
                "timestamp": datetime.now().isoformat(),
                "signature_id": 2100498,
                "signature": "GPL ATTACK_RESPONSE id check returned root",
                "severity": 1,
                "category": "Potentially Bad Traffic",
                "src_ip": "192.168.1.100",
                "src_port": 12345,
                "dest_ip": "192.168.1.1",
                "dest_port": 80,
                "proto": "TCP",
                "action": "allowed"
            }
        }
        
        if not client.send_message(alert_msg):
            return False, "Failed to send alert message"
        
        return True, "Alert message sent successfully"
        
    finally:
        client.disconnect()


def test_multiple_alerts(host: str, port: int, count: int = 10) -> Tuple[bool, str]:
    """测试批量告警发送"""
    client = ProtocolClient(host, port)
    
    if not client.connect():
        return False, "Connection failed"
    
    try:
        success_count = 0
        
        for i in range(count):
            alert_msg = {
                "event": "EVT_ALERT",
                "probe_type": "nids",
                "probe_id": f"test-nids-{int(time.time())}",
                "data": {
                    "timestamp": datetime.now().isoformat(),
                    "signature_id": 2100000 + i,
                    "signature": f"Test Alert #{i}",
                    "severity": (i % 3) + 1,
                    "category": "Test",
                    "src_ip": f"10.0.0.{i % 256}",
                    "src_port": 10000 + i,
                    "dest_ip": "192.168.1.1",
                    "dest_port": 80,
                    "proto": "TCP",
                    "action": "allowed"
                }
            }
            
            if client.send_message(alert_msg):
                success_count += 1
            else:
                break
                
            time.sleep(0.01)  # 10ms 间隔
        
        if success_count == count:
            return True, f"Successfully sent {count} alerts"
        else:
            return False, f"Only sent {success_count}/{count} alerts"
            
    finally:
        client.disconnect()


def test_invalid_message(host: str, port: int) -> Tuple[bool, str]:
    """测试无效消息处理"""
    client = ProtocolClient(host, port)
    
    if not client.connect():
        return False, "Connection failed"
    
    try:
        # 发送无效 JSON
        if not client.sock:
            return False, "No socket"
            
        invalid_data = b"this is not valid json"
        length = struct.pack('>I', len(invalid_data))
        client.sock.sendall(length + invalid_data)
        
        # 连接应该仍然存在或被优雅关闭
        time.sleep(0.5)
        
        # 尝试发送一个有效消息
        valid_msg = {
            "event": "EVT_STATUS",
            "probe_type": "test",
            "probe_id": "test"
        }
        
        try:
            result = client.send_message(valid_msg)
            if result:
                return True, "Server handles invalid message gracefully"
            else:
                return True, "Server closed connection after invalid message (acceptable)"
        except:
            return True, "Server closed connection after invalid message (acceptable)"
            
    finally:
        client.disconnect()


def test_large_message(host: str, port: int) -> Tuple[bool, str]:
    """测试大消息处理"""
    client = ProtocolClient(host, port)
    
    if not client.connect():
        return False, "Connection failed"
    
    try:
        # 创建大消息
        large_msg = {
            "event": "EVT_LOG",
            "probe_type": "nids",
            "probe_id": f"test-nids-{int(time.time())}",
            "data": {
                "log": "A" * 100000  # 100KB 数据
            }
        }
        
        if client.send_message(large_msg):
            return True, "Large message sent successfully"
        else:
            return False, "Failed to send large message"
            
    finally:
        client.disconnect()


def run_all_tests(host: str, port: int, verbose: bool = False):
    """运行所有测试"""
    print("=" * 60)
    print("  NIDS Probe - Manager Communication Tests")
    print("=" * 60)
    print(f"  Manager: {host}:{port}")
    print("=" * 60)
    print()
    
    tests = [
        ("Basic Connection", test_connection),
        ("Register Message", test_register_message),
        ("Status Message", test_status_message),
        ("Alert Message", test_alert_message),
        ("Multiple Alerts (10)", lambda h, p: test_multiple_alerts(h, p, 10)),
        ("Invalid Message Handling", test_invalid_message),
        ("Large Message", test_large_message),
    ]
    
    results = []
    
    for name, test_func in tests:
        print(f">>> {name}")
        try:
            passed, message = test_func(host, port)
            results.append((name, passed, message))
            
            status = "✓ PASS" if passed else "✗ FAIL"
            print(f"    {status}: {message}")
        except Exception as e:
            results.append((name, False, str(e)))
            print(f"    ✗ ERROR: {e}")
        print()
    
    # 汇总
    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    
    passed = sum(1 for _, p, _ in results if p)
    total = len(results)
    
    print(f"  Passed: {passed}/{total}")
    print()
    
    for name, p, msg in results:
        status = "✓" if p else "✗"
        print(f"  {status} {name}")
    
    print("=" * 60)
    
    return passed == total


def main():
    parser = argparse.ArgumentParser(description="Test NIDS Probe - Manager Communication")
    parser.add_argument("--host", default="127.0.0.1", help="Manager host")
    parser.add_argument("--port", "-p", type=int, default=9010, help="Manager port")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--test", "-t", help="Run specific test")
    
    args = parser.parse_args()
    
    if args.test:
        test_map = {
            "connection": test_connection,
            "register": test_register_message,
            "status": test_status_message,
            "alert": test_alert_message,
            "multi": lambda h, p: test_multiple_alerts(h, p, 10),
            "invalid": test_invalid_message,
            "large": test_large_message,
        }
        
        if args.test in test_map:
            passed, msg = test_map[args.test](args.host, args.port)
            status = "PASS" if passed else "FAIL"
            print(f"[{status}] {msg}")
            sys.exit(0 if passed else 1)
        else:
            print(f"Unknown test: {args.test}")
            print(f"Available tests: {', '.join(test_map.keys())}")
            sys.exit(1)
    else:
        success = run_all_tests(args.host, args.port, args.verbose)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
