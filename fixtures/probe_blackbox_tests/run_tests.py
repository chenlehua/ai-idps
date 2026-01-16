#!/usr/bin/env python3
"""
Phase 3 Black Box Test Runner
=============================

运行 Probe Manager 的所有黑盒测试。

使用方法:
    # 运行所有测试
    python run_tests.py

    # 只运行探针连接测试
    python run_tests.py --probe

    # 只运行云端通信测试
    python run_tests.py --cloud

    # 只运行压力测试
    python run_tests.py --stress

    # 快速测试（跳过压力测试）
    python run_tests.py --quick

    # 指定服务器地址
    python run_tests.py --manager-host 192.168.1.100 --manager-port 9010 --cloud-url http://192.168.1.100

配置:
    默认 Manager 地址: 127.0.0.1:9010
    默认 Cloud 地址: http://localhost
"""

import sys
import os
import argparse
import unittest
import time
from datetime import datetime

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def configure_test_env(args):
    """配置测试环境变量"""
    # 导入测试模块并设置配置
    import test_probe_connection
    import test_cloud_communication
    import test_stress

    test_probe_connection.MANAGER_HOST = args.manager_host
    test_probe_connection.MANAGER_PORT = args.manager_port
    test_cloud_communication.CLOUD_BASE_URL = args.cloud_url
    test_stress.MANAGER_HOST = args.manager_host
    test_stress.MANAGER_PORT = args.manager_port
    test_stress.CLOUD_BASE_URL = args.cloud_url


def run_probe_tests() -> bool:
    """运行探针连接测试"""
    print("\n" + "=" * 60)
    print("Running Probe Connection Tests")
    print("=" * 60)

    from test_probe_connection import run_tests
    return run_tests()


def run_cloud_tests() -> bool:
    """运行云端通信测试"""
    print("\n" + "=" * 60)
    print("Running Cloud Communication Tests")
    print("=" * 60)

    from test_cloud_communication import run_tests
    return run_tests()


def run_stress_tests() -> bool:
    """运行压力测试"""
    print("\n" + "=" * 60)
    print("Running Stress Tests")
    print("=" * 60)

    from test_stress import run_tests
    return run_tests()


def check_connectivity(args) -> dict:
    """检查服务连接性"""
    import socket
    import requests

    results = {
        "manager": False,
        "cloud": False
    }

    # 检查 Manager 连接
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((args.manager_host, args.manager_port))
        sock.close()
        results["manager"] = True
    except:
        pass

    # 检查 Cloud 连接
    try:
        response = requests.get(f"{args.cloud_url}/health", timeout=5)
        results["cloud"] = response.status_code == 200
    except:
        pass

    return results


def print_banner():
    """打印测试横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║             AI-IDPS Phase 3 Black Box Tests                  ║
║                  Probe Manager Testing                       ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_summary(results: dict, duration: float):
    """打印测试摘要"""
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed

    for name, success in results.items():
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"  {name}: {status}")

    print("-" * 60)
    print(f"Total: {total} | Passed: {passed} | Failed: {failed}")
    print(f"Duration: {duration:.2f} seconds")
    print("=" * 60)

    if failed == 0:
        print("\n🎉 All tests passed!")
    else:
        print(f"\n❌ {failed} test suite(s) failed")


def main():
    parser = argparse.ArgumentParser(
        description="Phase 3 Black Box Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # 测试选择
    parser.add_argument("--probe", action="store_true",
                       help="Run only probe connection tests")
    parser.add_argument("--cloud", action="store_true",
                       help="Run only cloud communication tests")
    parser.add_argument("--stress", action="store_true",
                       help="Run only stress tests")
    parser.add_argument("--quick", action="store_true",
                       help="Quick mode (skip stress tests)")

    # 服务器配置
    parser.add_argument("--manager-host", default="127.0.0.1",
                       help="Probe Manager host (default: 127.0.0.1)")
    parser.add_argument("--manager-port", type=int, default=9010,
                       help="Probe Manager port (default: 9010)")
    parser.add_argument("--cloud-url", default="http://localhost",
                       help="Cloud API URL (default: http://localhost)")

    # 其他选项
    parser.add_argument("--skip-connectivity-check", action="store_true",
                       help="Skip initial connectivity check")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")

    args = parser.parse_args()

    print_banner()

    print(f"Configuration:")
    print(f"  Manager: {args.manager_host}:{args.manager_port}")
    print(f"  Cloud:   {args.cloud_url}")
    print()

    # 连接性检查
    if not args.skip_connectivity_check:
        print("Checking connectivity...")
        connectivity = check_connectivity(args)

        print(f"  Manager ({args.manager_host}:{args.manager_port}): " +
              ("✓ OK" if connectivity["manager"] else "✗ Not available"))
        print(f"  Cloud ({args.cloud_url}): " +
              ("✓ OK" if connectivity["cloud"] else "✗ Not available"))
        print()

        if not connectivity["manager"] and not connectivity["cloud"]:
            print("ERROR: Neither Manager nor Cloud is available.")
            print("Please start the services before running tests.")
            print("\nTo start services:")
            print("  1. Start cloud: cd cloud && make up")
            print("  2. Start manager: ./probe/manager/probe_manager")
            return 1

    # 配置测试环境
    configure_test_env(args)

    # 确定要运行的测试
    run_all = not (args.probe or args.cloud or args.stress)

    results = {}
    start_time = time.time()

    try:
        if args.probe or run_all:
            results["Probe Connection"] = run_probe_tests()

        if args.cloud or run_all:
            results["Cloud Communication"] = run_cloud_tests()

        if args.stress or (run_all and not args.quick):
            results["Stress Tests"] = run_stress_tests()

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        return 130

    duration = time.time() - start_time
    print_summary(results, duration)

    # 返回码
    all_passed = all(results.values())
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
