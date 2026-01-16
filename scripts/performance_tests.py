#!/usr/bin/env python3
"""
AI-IDPS 性能测试脚本
===================

测试系统性能指标：
1. 日志写入性能 (目标: 1000条/秒)
2. API 响应时间 (目标: <500ms)
3. WebSocket 推送性能 (目标: 支持100并发连接)
4. 探针连接性能 (目标: 支持10个并发探针)

使用方法:
    python scripts/performance_tests.py [options]

    # 日志写入测试
    python scripts/performance_tests.py --log-write --rate 1000 --duration 60

    # API 压力测试
    python scripts/performance_tests.py --api-stress --concurrency 50

    # WebSocket 连接测试
    python scripts/performance_tests.py --ws-connections 100

    # 运行所有测试
    python scripts/performance_tests.py --all
"""

import sys
import json
import time
import asyncio
import argparse
import threading
import statistics
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue

try:
    import requests
    import websockets
except ImportError:
    print("请先安装依赖: pip install requests websockets")
    sys.exit(1)


@dataclass
class PerformanceMetrics:
    """性能指标"""
    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    duration: float
    avg_latency: float
    min_latency: float
    max_latency: float
    p50_latency: float
    p95_latency: float
    p99_latency: float
    throughput: float  # 请求/秒

    def __str__(self):
        return f"""
{self.test_name}
{'=' * 50}
总请求数:       {self.total_requests}
成功:           {self.successful_requests}
失败:           {self.failed_requests}
成功率:         {(self.successful_requests / self.total_requests * 100):.2f}%
总耗时:         {self.duration:.2f}s
吞吐量:         {self.throughput:.2f} req/s
平均延迟:       {self.avg_latency:.2f}ms
最小延迟:       {self.min_latency:.2f}ms
最大延迟:       {self.max_latency:.2f}ms
P50 延迟:       {self.p50_latency:.2f}ms
P95 延迟:       {self.p95_latency:.2f}ms
P99 延迟:       {self.p99_latency:.2f}ms
"""


class PerformanceTest:
    """性能测试类"""

    def __init__(self, base_url: str = "http://localhost"):
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/api/v1"
        self.test_probe_id = f"perf-test-{int(time.time())}"

    def calculate_metrics(self, test_name: str, latencies: List[float],
                          total: int, success: int, duration: float) -> PerformanceMetrics:
        """计算性能指标"""
        if not latencies:
            latencies = [0]

        sorted_latencies = sorted(latencies)
        n = len(sorted_latencies)

        return PerformanceMetrics(
            test_name=test_name,
            total_requests=total,
            successful_requests=success,
            failed_requests=total - success,
            duration=duration,
            avg_latency=statistics.mean(latencies) * 1000,
            min_latency=min(latencies) * 1000,
            max_latency=max(latencies) * 1000,
            p50_latency=sorted_latencies[int(n * 0.5)] * 1000,
            p95_latency=sorted_latencies[int(n * 0.95)] * 1000,
            p99_latency=sorted_latencies[int(n * 0.99)] * 1000,
            throughput=success / duration if duration > 0 else 0
        )

    # ================== 日志写入性能测试 ==================

    def test_log_write_performance(self, rate: int = 1000, duration: int = 60,
                                   batch_size: int = 100) -> PerformanceMetrics:
        """
        日志写入性能测试

        Args:
            rate: 目标每秒写入条数
            duration: 测试持续时间(秒)
            batch_size: 批量写入大小
        """
        print(f"\n{'='*60}")
        print("日志写入性能测试")
        print(f"{'='*60}")
        print(f"目标速率: {rate} 条/秒")
        print(f"测试时长: {duration} 秒")
        print(f"批量大小: {batch_size}")
        print("-" * 60)

        # 注册测试探针
        self._register_probe()

        latencies = []
        total_logs = 0
        success_logs = 0
        start_time = time.time()
        interval = batch_size / rate  # 每批次间隔

        while time.time() - start_time < duration:
            batch_start = time.time()

            # 生成批量日志
            logs = self._generate_logs(batch_size)
            payload = {
                "cmd": 10,
                "data": {
                    "probe_id": self.test_probe_id,
                    "logs": logs
                }
            }

            try:
                req_start = time.time()
                resp = requests.post(f"{self.api_url}/probe", json=payload, timeout=30)
                latency = time.time() - req_start
                latencies.append(latency)

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("data", {}).get("status") == "ok":
                        success_logs += batch_size
                total_logs += batch_size

            except Exception as e:
                total_logs += batch_size
                print(f"  写入错误: {e}")

            # 控制速率
            elapsed = time.time() - batch_start
            if elapsed < interval:
                time.sleep(interval - elapsed)

            # 进度显示
            elapsed_total = time.time() - start_time
            current_rate = total_logs / elapsed_total if elapsed_total > 0 else 0
            print(f"\r  进度: {elapsed_total:.1f}s / {duration}s | "
                  f"已写入: {total_logs} | 速率: {current_rate:.1f} 条/秒", end="")

        print()
        total_duration = time.time() - start_time

        metrics = self.calculate_metrics(
            "日志写入性能测试",
            latencies,
            total_logs // batch_size,
            success_logs // batch_size,
            total_duration
        )
        metrics.total_requests = total_logs
        metrics.successful_requests = success_logs
        metrics.failed_requests = total_logs - success_logs
        metrics.throughput = success_logs / total_duration

        return metrics

    def _generate_logs(self, count: int) -> List[Dict]:
        """生成测试日志"""
        logs = []
        timestamp = datetime.utcnow().isoformat() + "Z"
        for i in range(count):
            logs.append({
                "probe_type": "nids",
                "instance_id": f"{self.test_probe_id}-nids",
                "timestamp": timestamp,
                "src_ip": f"192.168.{i % 256}.{i % 256}",
                "dest_ip": "10.0.0.1",
                "src_port": 50000 + (i % 10000),
                "dest_port": 80,
                "protocol": "TCP",
                "alert": {
                    "signature": f"Performance Test Alert {i}",
                    "signature_id": 9900000 + i,
                    "severity": (i % 3) + 1,
                    "category": "performance-test"
                },
                "raw": json.dumps({"test": True, "batch_index": i})
            })
        return logs

    def _register_probe(self):
        """注册测试探针"""
        payload = {
            "cmd": 30,
            "data": {
                "probe_id": self.test_probe_id,
                "name": "性能测试探针",
                "ip": "192.168.200.1",
                "probe_types": ["nids"]
            }
        }
        try:
            requests.post(f"{self.api_url}/probe", json=payload, timeout=10)
        except:
            pass

    # ================== API 响应时间测试 ==================

    def test_api_latency(self, concurrency: int = 50, requests_count: int = 1000) -> PerformanceMetrics:
        """
        API 响应时间测试

        Args:
            concurrency: 并发数
            requests_count: 总请求数
        """
        print(f"\n{'='*60}")
        print("API 响应时间测试")
        print(f"{'='*60}")
        print(f"并发数: {concurrency}")
        print(f"请求数: {requests_count}")
        print("-" * 60)

        latencies = []
        success_count = 0
        failed_count = 0
        lock = threading.Lock()

        def make_request():
            nonlocal success_count, failed_count
            try:
                start = time.time()
                resp = requests.get(f"{self.api_url}/probes", timeout=10)
                latency = time.time() - start

                with lock:
                    latencies.append(latency)
                    if resp.status_code == 200:
                        success_count += 1
                    else:
                        failed_count += 1
                return latency
            except Exception as e:
                with lock:
                    failed_count += 1
                return None

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(make_request) for _ in range(requests_count)]

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 100 == 0:
                    print(f"\r  进度: {completed}/{requests_count}", end="")

        print()
        duration = time.time() - start_time

        return self.calculate_metrics(
            "API 响应时间测试",
            latencies,
            requests_count,
            success_count,
            duration
        )

    # ================== WebSocket 连接测试 ==================

    async def test_websocket_connections(self, connections: int = 100,
                                          duration: int = 30) -> PerformanceMetrics:
        """
        WebSocket 并发连接测试

        Args:
            connections: 并发连接数
            duration: 测试持续时间
        """
        print(f"\n{'='*60}")
        print("WebSocket 连接测试")
        print(f"{'='*60}")
        print(f"并发连接数: {connections}")
        print(f"持续时间: {duration} 秒")
        print("-" * 60)

        ws_url = self.base_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = f"{ws_url}/api/v1/ws/logs"

        connected = 0
        messages_received = 0
        errors = 0
        latencies = []
        lock = asyncio.Lock()

        async def client(client_id: int):
            nonlocal connected, messages_received, errors
            try:
                start = time.time()
                async with websockets.connect(ws_url, timeout=10) as ws:
                    connect_latency = time.time() - start

                    async with lock:
                        connected += 1
                        latencies.append(connect_latency)

                    # 订阅
                    await ws.send(json.dumps({"action": "subscribe", "filters": {}}))
                    await ws.recv()

                    # 保持连接
                    end_time = time.time() + duration
                    while time.time() < end_time:
                        try:
                            # 发送ping
                            ping_start = time.time()
                            await ws.send(json.dumps({"action": "ping"}))
                            await asyncio.wait_for(ws.recv(), timeout=5)
                            ping_latency = time.time() - ping_start

                            async with lock:
                                latencies.append(ping_latency)
                                messages_received += 1

                            await asyncio.sleep(1)
                        except asyncio.TimeoutError:
                            break
                        except:
                            break

            except Exception as e:
                async with lock:
                    errors += 1

        start_time = time.time()

        # 创建所有客户端任务
        tasks = [client(i) for i in range(connections)]

        # 显示进度
        async def show_progress():
            while True:
                await asyncio.sleep(1)
                elapsed = time.time() - start_time
                print(f"\r  连接: {connected}/{connections} | "
                      f"消息: {messages_received} | "
                      f"错误: {errors} | "
                      f"时间: {elapsed:.1f}s", end="")

        progress_task = asyncio.create_task(show_progress())

        try:
            await asyncio.gather(*tasks)
        except:
            pass
        finally:
            progress_task.cancel()

        print()
        total_duration = time.time() - start_time

        return PerformanceMetrics(
            test_name="WebSocket 连接测试",
            total_requests=connections,
            successful_requests=connected,
            failed_requests=errors,
            duration=total_duration,
            avg_latency=statistics.mean(latencies) * 1000 if latencies else 0,
            min_latency=min(latencies) * 1000 if latencies else 0,
            max_latency=max(latencies) * 1000 if latencies else 0,
            p50_latency=sorted(latencies)[len(latencies)//2] * 1000 if latencies else 0,
            p95_latency=sorted(latencies)[int(len(latencies)*0.95)] * 1000 if latencies else 0,
            p99_latency=sorted(latencies)[int(len(latencies)*0.99)] * 1000 if latencies else 0,
            throughput=messages_received / total_duration if total_duration > 0 else 0
        )

    # ================== 探针并发连接测试 ==================

    def test_probe_connections(self, probe_count: int = 10,
                                heartbeat_interval: int = 5,
                                duration: int = 60) -> PerformanceMetrics:
        """
        探针并发连接测试

        Args:
            probe_count: 探针数量
            heartbeat_interval: 心跳间隔(秒)
            duration: 测试持续时间(秒)
        """
        print(f"\n{'='*60}")
        print("探针并发连接测试")
        print(f"{'='*60}")
        print(f"探针数量: {probe_count}")
        print(f"心跳间隔: {heartbeat_interval} 秒")
        print(f"持续时间: {duration} 秒")
        print("-" * 60)

        latencies = []
        success_count = 0
        failed_count = 0
        lock = threading.Lock()

        def simulate_probe(probe_id: int):
            nonlocal success_count, failed_count
            probe_name = f"perf-probe-{probe_id}"

            # 注册
            payload = {
                "cmd": 30,
                "data": {
                    "probe_id": probe_name,
                    "name": f"性能测试探针{probe_id}",
                    "ip": f"192.168.{probe_id}.1",
                    "probe_types": ["nids"]
                }
            }
            try:
                start = time.time()
                resp = requests.post(f"{self.api_url}/probe", json=payload, timeout=10)
                latency = time.time() - start
                with lock:
                    latencies.append(latency)
                    if resp.status_code == 200:
                        success_count += 1
                    else:
                        failed_count += 1
            except:
                with lock:
                    failed_count += 1

            # 持续发送心跳
            end_time = time.time() + duration
            while time.time() < end_time:
                payload = {
                    "cmd": 20,
                    "data": {
                        "probe_id": probe_name,
                        "rule_version": None,
                        "status": {"cpu": 10 + probe_id, "memory": 256},
                        "probes": []
                    }
                }
                try:
                    start = time.time()
                    resp = requests.post(f"{self.api_url}/probe", json=payload, timeout=10)
                    latency = time.time() - start
                    with lock:
                        latencies.append(latency)
                        if resp.status_code == 200:
                            success_count += 1
                        else:
                            failed_count += 1
                except:
                    with lock:
                        failed_count += 1

                time.sleep(heartbeat_interval)

        start_time = time.time()

        # 启动所有探针线程
        threads = []
        for i in range(probe_count):
            t = threading.Thread(target=simulate_probe, args=(i,))
            t.start()
            threads.append(t)

        # 显示进度
        while any(t.is_alive() for t in threads):
            elapsed = time.time() - start_time
            print(f"\r  时间: {elapsed:.1f}s | 成功: {success_count} | 失败: {failed_count}", end="")
            time.sleep(1)

        for t in threads:
            t.join()

        print()
        total_duration = time.time() - start_time

        return self.calculate_metrics(
            "探针并发连接测试",
            latencies,
            success_count + failed_count,
            success_count,
            total_duration
        )


def main():
    parser = argparse.ArgumentParser(description="AI-IDPS 性能测试")
    parser.add_argument("--base-url", default="http://localhost",
                        help="API 基础 URL (默认: http://localhost)")

    # 测试选项
    parser.add_argument("--all", action="store_true", help="运行所有测试")
    parser.add_argument("--log-write", action="store_true", help="日志写入测试")
    parser.add_argument("--api-stress", action="store_true", help="API 压力测试")
    parser.add_argument("--ws-test", action="store_true", help="WebSocket 测试")
    parser.add_argument("--probe-test", action="store_true", help="探针连接测试")

    # 参数
    parser.add_argument("--rate", type=int, default=100, help="日志写入速率(条/秒)")
    parser.add_argument("--duration", type=int, default=30, help="测试持续时间(秒)")
    parser.add_argument("--concurrency", type=int, default=20, help="并发数")
    parser.add_argument("--connections", type=int, default=50, help="WebSocket连接数")
    parser.add_argument("--probes", type=int, default=5, help="探针数量")

    args = parser.parse_args()

    test = PerformanceTest(args.base_url)
    results = []

    print("\n" + "=" * 60)
    print("AI-IDPS 性能测试")
    print("=" * 60)
    print(f"目标: {args.base_url}")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    run_all = args.all or not any([args.log_write, args.api_stress, args.ws_test, args.probe_test])

    try:
        if args.log_write or run_all:
            metrics = test.test_log_write_performance(
                rate=args.rate,
                duration=args.duration,
                batch_size=min(100, args.rate)
            )
            results.append(metrics)
            print(metrics)

        if args.api_stress or run_all:
            metrics = test.test_api_latency(
                concurrency=args.concurrency,
                requests_count=args.concurrency * 20
            )
            results.append(metrics)
            print(metrics)

        if args.ws_test or run_all:
            loop = asyncio.get_event_loop()
            metrics = loop.run_until_complete(
                test.test_websocket_connections(
                    connections=args.connections,
                    duration=min(args.duration, 30)
                )
            )
            results.append(metrics)
            print(metrics)

        if args.probe_test or run_all:
            metrics = test.test_probe_connections(
                probe_count=args.probes,
                heartbeat_interval=5,
                duration=min(args.duration, 30)
            )
            results.append(metrics)
            print(metrics)

    except KeyboardInterrupt:
        print("\n\n测试被用户中断")

    # 打印汇总
    print("\n" + "=" * 60)
    print("性能测试汇总")
    print("=" * 60)

    for metrics in results:
        status = "通过" if metrics.successful_requests / max(metrics.total_requests, 1) > 0.95 else "警告"
        color = "\033[92m" if status == "通过" else "\033[93m"
        print(f"{color}{metrics.test_name}: {status}\033[0m")
        print(f"  吞吐量: {metrics.throughput:.2f}/s, P95延迟: {metrics.p95_latency:.2f}ms")

    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
