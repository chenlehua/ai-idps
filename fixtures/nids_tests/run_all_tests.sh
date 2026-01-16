#!/bin/bash
# NIDS 探针完整测试套件
# 用法: ./run_all_tests.sh [target_ip] [manager_port]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-127.0.0.1}"
MANAGER_PORT="${2:-9010}"
LOG_DIR="${3:-/var/log/suricata}"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                   NIDS Probe Blackbox Test Suite                 ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  Target IP:     $TARGET                                         "
echo "║  Manager Port:  $MANAGER_PORT                                   "
echo "║  Suricata Log:  $LOG_DIR                                        "
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# 测试结果统计
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

run_test() {
    local name="$1"
    local cmd="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  TEST: $name"
    echo "════════════════════════════════════════════════════════════════"
    
    if eval "$cmd"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}[PASS]${NC} $name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "${RED}[FAIL]${NC} $name"
    fi
}

skip_test() {
    local name="$1"
    local reason="$2"
    
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    echo -e "${YELLOW}[SKIP]${NC} $name - $reason"
}

# 环境检查
echo ""
echo "=== Environment Check ==="

# 检查 NIDS 探针
if pgrep -x "nids-probe" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} NIDS Probe is running"
    NIDS_RUNNING=true
else
    echo -e "${YELLOW}!${NC} NIDS Probe is not running"
    NIDS_RUNNING=false
fi

# 检查 Suricata (使用 pgrep -f 来匹配进程参数，因为 Suricata 可能由其他进程启动)
if pgrep -f "suricata" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Suricata is running"
    SURICATA_RUNNING=true
elif pgrep -x "Suricata-Main" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Suricata is running (Suricata-Main)"
    SURICATA_RUNNING=true
else
    echo -e "${YELLOW}!${NC} Suricata is not running"
    SURICATA_RUNNING=false
fi

# 检查 Probe Manager
if command -v nc &> /dev/null && nc -z 127.0.0.1 $MANAGER_PORT 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Probe Manager is listening on port $MANAGER_PORT"
    MANAGER_RUNNING=true
elif timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$MANAGER_PORT" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Probe Manager is listening on port $MANAGER_PORT"
    MANAGER_RUNNING=true
elif pgrep -x "probe-manager" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Probe Manager is running (process found)"
    MANAGER_RUNNING=true
else
    echo -e "${YELLOW}!${NC} Probe Manager is not listening on port $MANAGER_PORT"
    MANAGER_RUNNING=false
fi

# 检查 eve.json
if [ -f "$LOG_DIR/eve.json" ]; then
    echo -e "${GREEN}✓${NC} eve.json exists at $LOG_DIR"
    EVE_EXISTS=true
else
    echo -e "${YELLOW}!${NC} eve.json not found at $LOG_DIR"
    EVE_EXISTS=false
fi

# 检查 Suricata 规则是否加载
RULES_DIR="/var/lib/suricata/rules"
RULES_COUNT=$(ls -1 "$RULES_DIR"/*.rules 2>/dev/null | wc -l)
if [ "$RULES_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} Suricata rules loaded ($RULES_COUNT rule files)"
    RULES_LOADED=true
else
    echo -e "${RED}✗${NC} No Suricata rules found in $RULES_DIR"
    echo -e "${YELLOW}  Run 'make download-rules' to download ET Open rules${NC}"
    RULES_LOADED=false
fi

# 检查必要工具
echo ""
echo "=== Tool Check ==="

check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1"
        return 0
    else
        echo -e "${YELLOW}✗${NC} $1 (not installed)"
        return 1
    fi
}

if check_tool nmap; then HAVE_NMAP=true; else HAVE_NMAP=false; fi
if check_tool curl; then HAVE_CURL=true; else HAVE_CURL=false; fi
if check_tool nc; then HAVE_NC=true; else HAVE_NC=false; fi
if check_tool python3; then HAVE_PYTHON=true; else HAVE_PYTHON=false; fi

echo ""

# 运行测试

# 1. Manager 通信测试
if [ "$MANAGER_RUNNING" = true ] && [ "$HAVE_PYTHON" = true ]; then
    run_test "Manager Communication" "python3 $SCRIPT_DIR/test_manager_comm.py --host 127.0.0.1 --port $MANAGER_PORT"
else
    skip_test "Manager Communication" "Manager not running or Python not available"
fi

# 2. 端口扫描测试
if [ "$HAVE_NMAP" = true ] && [ "$SURICATA_RUNNING" = true ]; then
    run_test "Port Scan Detection" "bash $SCRIPT_DIR/test_port_scan.sh $TARGET $LOG_DIR"
else
    skip_test "Port Scan Detection" "nmap not installed or Suricata not running"
fi

# 3. Web 攻击测试
if [ "$HAVE_CURL" = true ] && [ "$SURICATA_RUNNING" = true ]; then
    run_test "Web Attack Detection" "bash $SCRIPT_DIR/test_web_attacks.sh http://$TARGET $LOG_DIR"
else
    skip_test "Web Attack Detection" "curl not installed or Suricata not running"
fi

# 4. 协议异常测试
if [ "$HAVE_NC" = true ] && [ "$SURICATA_RUNNING" = true ]; then
    run_test "Protocol Anomaly Detection" "bash $SCRIPT_DIR/test_protocol_anomaly.sh $TARGET 80 $LOG_DIR"
else
    skip_test "Protocol Anomaly Detection" "nc not installed or Suricata not running"
fi

# 5. 恶意流量测试
if [ "$HAVE_CURL" = true ] && [ "$SURICATA_RUNNING" = true ]; then
    run_test "Malware Traffic Detection" "bash $SCRIPT_DIR/test_malware_traffic.sh $LOG_DIR"
else
    skip_test "Malware Traffic Detection" "curl not installed or Suricata not running"
fi

# 6. Python 测试套件
if [ "$HAVE_PYTHON" = true ]; then
    run_test "Python Test Suite" "python3 $SCRIPT_DIR/run_nids_tests.py --target $TARGET --manager-port $MANAGER_PORT --eve-log $LOG_DIR/eve.json --quick"
else
    skip_test "Python Test Suite" "Python not available"
fi

# 最终报告
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                          Test Summary                            ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  Total Tests:   $TESTS_RUN                                       "
echo "║  Passed:        $TESTS_PASSED                                    "
echo "║  Failed:        $TESTS_FAILED                                    "
echo "║  Skipped:       $TESTS_SKIPPED                                   "
echo "╚══════════════════════════════════════════════════════════════════╝"

# 告警统计
if [ "$EVE_EXISTS" = true ]; then
    echo ""
    echo "=== Alert Statistics ==="
    TOTAL_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null | tr -d '\n' || echo "0")
    TOTAL_ALERTS=${TOTAL_ALERTS:-0}
    echo "Total alerts in eve.json: $TOTAL_ALERTS"

    if [ "$TOTAL_ALERTS" -gt 0 ] 2>/dev/null; then
        echo ""
        echo "Recent alerts (last 5):"
        tail -100 "$LOG_DIR/eve.json" 2>/dev/null | \
            grep '"event_type":"alert"' | \
            tail -5 | \
            python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        sig = e.get('alert', {}).get('signature', 'N/A')
        cat = e.get('alert', {}).get('category', 'N/A')
        print(f'  - [{cat}] {sig}')
    except:
        pass
" 2>/dev/null || echo "  (error reading alerts)"
    fi
fi

echo ""

# 返回适当的退出码
if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
