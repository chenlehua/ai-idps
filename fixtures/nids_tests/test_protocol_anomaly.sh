#!/bin/bash
# NIDS 协议异常检测测试
# 用法: ./test_protocol_anomaly.sh <target_ip>

set -e

TARGET="${1:-127.0.0.1}"
TARGET_PORT="${2:-80}"
LOG_DIR="${3:-/var/log/suricata}"

echo "=================================================="
echo "  NIDS Protocol Anomaly Detection Tests"
echo "=================================================="
echo "Target: $TARGET:$TARGET_PORT"
echo "Log Dir: $LOG_DIR"
echo ""

# 检查必要工具
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Warning: $1 is not installed"
        return 1
    fi
    return 0
}

# 记录初始告警数
if [ -f "$LOG_DIR/eve.json" ]; then
    INITIAL_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
else
    INITIAL_ALERTS=0
fi
echo "Initial alerts: $INITIAL_ALERTS"
echo ""

check_alerts() {
    if [ -f "$LOG_DIR/eve.json" ]; then
        CURRENT_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
        NEW_ALERTS=$((CURRENT_ALERTS - INITIAL_ALERTS))
        echo "New alerts: $NEW_ALERTS"
        INITIAL_ALERTS=$CURRENT_ALERTS
    fi
    echo ""
}

echo "=== 1. Malformed HTTP Requests ==="

if check_tool nc; then
    echo ">>> Invalid HTTP Version"
    echo -e "GET / HTTP/9.9\r\nHost: test\r\n\r\n" | timeout 5 nc $TARGET $TARGET_PORT 2>/dev/null || true
    sleep 1
    check_alerts
    
    echo ">>> Very Long URI"
    LONG_URI=$(python3 -c "print('A'*5000)")
    echo -e "GET /$LONG_URI HTTP/1.1\r\nHost: test\r\n\r\n" | timeout 5 nc $TARGET $TARGET_PORT 2>/dev/null || true
    sleep 1
    check_alerts
    
    echo ">>> Invalid HTTP Method"
    echo -e "HACK / HTTP/1.1\r\nHost: test\r\n\r\n" | timeout 5 nc $TARGET $TARGET_PORT 2>/dev/null || true
    sleep 1
    check_alerts
    
    echo ">>> Missing Host Header"
    echo -e "GET / HTTP/1.1\r\n\r\n" | timeout 5 nc $TARGET $TARGET_PORT 2>/dev/null || true
    sleep 1
    check_alerts
    
    echo ">>> Invalid Content-Length"
    echo -e "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 999999999\r\n\r\ndata" | timeout 5 nc $TARGET $TARGET_PORT 2>/dev/null || true
    sleep 1
    check_alerts
else
    echo "Skipping HTTP tests - nc not installed"
fi

echo "=== 2. ICMP Anomaly Tests ==="

if check_tool ping; then
    echo ">>> Normal Ping"
    ping -c 3 $TARGET 2>/dev/null || true
    sleep 1
    check_alerts
    
    echo ">>> Large ICMP Packet"
    # 发送大 ICMP 包 (需要 root)
    if [ "$EUID" -eq 0 ]; then
        ping -c 1 -s 10000 $TARGET 2>/dev/null || true
    else
        echo "Skipping large ICMP test (requires root)"
    fi
    sleep 1
    check_alerts
fi

echo "=== 3. DNS Anomaly Tests ==="

if check_tool dig; then
    echo ">>> Normal DNS Query"
    dig @$TARGET example.com A 2>/dev/null || true
    sleep 1
    check_alerts
    
    echo ">>> DNS ANY Query (Amplification)"
    dig @$TARGET -t ANY example.com 2>/dev/null || true
    sleep 1
    check_alerts
    
    echo ">>> Long DNS Name"
    LONG_NAME=$(python3 -c "print('a'*60 + '.example.com')")
    dig @$TARGET $LONG_NAME 2>/dev/null || true
    sleep 1
    check_alerts
else
    echo "Skipping DNS tests - dig not installed"
fi

echo "=== 4. TCP Anomaly Tests ==="

if check_tool hping3; then
    if [ "$EUID" -eq 0 ]; then
        echo ">>> TCP with all flags set"
        hping3 -c 3 -S -F -P -U -R -A $TARGET -p $TARGET_PORT 2>/dev/null || true
        sleep 1
        check_alerts
        
        echo ">>> TCP with no flags"
        hping3 -c 3 $TARGET -p $TARGET_PORT 2>/dev/null || true
        sleep 1
        check_alerts
        
        echo ">>> TCP urgent pointer"
        hping3 -c 3 -U $TARGET -p $TARGET_PORT 2>/dev/null || true
        sleep 1
        check_alerts
    else
        echo "Skipping TCP anomaly tests (requires root)"
    fi
else
    echo "Skipping TCP anomaly tests - hping3 not installed"
fi

echo "=== 5. Fragmentation Tests ==="

if check_tool hping3 && [ "$EUID" -eq 0 ]; then
    echo ">>> Fragmented Packets"
    hping3 -c 3 -f $TARGET -p $TARGET_PORT 2>/dev/null || true
    sleep 1
    check_alerts
else
    echo "Skipping fragmentation tests (requires hping3 and root)"
fi

# 最终统计
echo "=================================================="
echo "  Test Summary"
echo "=================================================="
if [ -f "$LOG_DIR/eve.json" ]; then
    FINAL_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
    echo "Total alerts in eve.json: $FINAL_ALERTS"
    
    echo ""
    echo "Recent protocol anomaly alerts:"
    tail -100 "$LOG_DIR/eve.json" 2>/dev/null | grep '"event_type":"alert"' | \
        grep -iE 'protocol|malform|invalid|anomal' | tail -5 | \
        python3 -c "import sys,json; [print(f\"  - {json.loads(l).get('alert',{}).get('signature','N/A')}\") for l in sys.stdin]" 2>/dev/null || echo "  (none or error reading)"
else
    echo "eve.json not found at $LOG_DIR/eve.json"
fi
echo "=================================================="
