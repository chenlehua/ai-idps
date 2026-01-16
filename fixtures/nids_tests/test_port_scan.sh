#!/bin/bash
# NIDS 端口扫描检测测试
# 用法: ./test_port_scan.sh <target_ip>

set -e

TARGET="${1:-127.0.0.1}"
LOG_DIR="${2:-/var/log/suricata}"

echo "=================================================="
echo "  NIDS Port Scan Detection Tests"
echo "=================================================="
echo "Target: $TARGET"
echo "Log Dir: $LOG_DIR"
echo ""

# 检查 nmap 是否安装
if ! command -v nmap &> /dev/null; then
    echo "Error: nmap is not installed"
    echo "Install with: sudo apt-get install -y nmap"
    exit 1
fi

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo "Warning: Some scans require root privileges"
    echo "Consider running with sudo for full functionality"
fi

# 记录初始告警数
if [ -f "$LOG_DIR/eve.json" ]; then
    INITIAL_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
else
    INITIAL_ALERTS=0
fi
echo "Initial alerts: $INITIAL_ALERTS"
echo ""

run_scan() {
    local name="$1"
    shift
    echo ">>> $name"
    echo "Command: nmap $@"
    
    if timeout 60 nmap "$@" > /dev/null 2>&1; then
        echo "Scan completed"
    else
        echo "Scan failed or timed out"
    fi
    
    sleep 2
    
    if [ -f "$LOG_DIR/eve.json" ]; then
        CURRENT_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
        NEW_ALERTS=$((CURRENT_ALERTS - INITIAL_ALERTS))
        echo "New alerts: $NEW_ALERTS"
        INITIAL_ALERTS=$CURRENT_ALERTS
    fi
    echo ""
}

echo "=== 1. TCP SYN Scan (半开放扫描) ==="
run_scan "TCP SYN Scan" -sS -p 22,80,443 --max-retries 1 -T4 $TARGET

echo "=== 2. TCP Connect Scan (全连接扫描) ==="
run_scan "TCP Connect Scan" -sT -p 22,80,443 --max-retries 1 -T4 $TARGET

echo "=== 3. Service Version Detection ==="
run_scan "Version Scan" -sV -p 22,80 --max-retries 1 $TARGET

echo "=== 4. OS Detection ==="
run_scan "OS Detection" -O --osscan-limit $TARGET

echo "=== 5. NULL Scan (隐蔽扫描) ==="
run_scan "NULL Scan" -sN -p 22,80,443 $TARGET

echo "=== 6. FIN Scan ==="
run_scan "FIN Scan" -sF -p 22,80,443 $TARGET

echo "=== 7. XMAS Scan (FIN+PSH+URG) ==="
run_scan "XMAS Scan" -sX -p 22,80,443 $TARGET

echo "=== 8. ACK Scan (防火墙探测) ==="
run_scan "ACK Scan" -sA -p 22,80,443 $TARGET

# 最终统计
echo "=================================================="
echo "  Test Summary"
echo "=================================================="
if [ -f "$LOG_DIR/eve.json" ]; then
    FINAL_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
    echo "Total alerts in eve.json: $FINAL_ALERTS"
    
    echo ""
    echo "Recent scan-related alerts:"
    tail -100 "$LOG_DIR/eve.json" 2>/dev/null | grep '"event_type":"alert"' | \
        grep -iE 'scan|probe|nmap' | tail -5 | \
        python3 -c "import sys,json; [print(f\"  - {json.loads(l).get('alert',{}).get('signature','N/A')}\") for l in sys.stdin]" 2>/dev/null || echo "  (none or error reading)"
else
    echo "eve.json not found at $LOG_DIR/eve.json"
fi
echo "=================================================="
