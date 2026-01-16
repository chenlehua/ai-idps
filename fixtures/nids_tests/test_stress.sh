#!/bin/bash
# NIDS 探针压力测试
# 用法: ./test_stress.sh <target_ip> [duration_seconds]

set -e

TARGET="${1:-127.0.0.1}"
DURATION="${2:-30}"
LOG_DIR="${3:-/var/log/suricata}"

echo "=================================================="
echo "  NIDS Probe Stress Tests"
echo "=================================================="
echo "Target: $TARGET"
echo "Duration: ${DURATION}s"
echo "Log Dir: $LOG_DIR"
echo ""
echo "WARNING: This test generates high volume traffic!"
echo ""

# 检查必要工具
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Warning: $1 is not installed"
        return 1
    fi
    return 0
}

# 记录初始状态
if [ -f "$LOG_DIR/eve.json" ]; then
    INITIAL_LINES=$(wc -l < "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
else
    INITIAL_LINES=0
fi
echo "Initial eve.json lines: $INITIAL_LINES"

# 记录初始时间
START_TIME=$(date +%s)

echo ""
echo "=== 1. HTTP Stress Test (curl) ==="

if check_tool curl; then
    echo "Sending rapid HTTP requests for ${DURATION}s..."
    
    REQUEST_COUNT=0
    END_TIME=$((START_TIME + DURATION / 3))
    
    while [ $(date +%s) -lt $END_TIME ]; do
        curl -s -o /dev/null --max-time 1 "http://$TARGET/" 2>/dev/null &
        REQUEST_COUNT=$((REQUEST_COUNT + 1))
        
        # 限制并发
        if [ $((REQUEST_COUNT % 50)) -eq 0 ]; then
            wait
        fi
    done
    
    wait
    echo "Sent $REQUEST_COUNT HTTP requests"
fi

echo ""
echo "=== 2. Connection Stress Test (netcat) ==="

if check_tool nc; then
    echo "Opening rapid TCP connections for ${DURATION}s..."
    
    CONN_COUNT=0
    END_TIME=$((START_TIME + DURATION * 2 / 3))
    
    while [ $(date +%s) -lt $END_TIME ]; do
        timeout 0.5 nc -z $TARGET 80 2>/dev/null &
        CONN_COUNT=$((CONN_COUNT + 1))
        
        if [ $((CONN_COUNT % 50)) -eq 0 ]; then
            wait
        fi
    done
    
    wait
    echo "Attempted $CONN_COUNT connections"
fi

echo ""
echo "=== 3. ICMP Flood Test (ping) ==="

if check_tool ping; then
    echo "Sending rapid ICMP packets..."
    
    # 使用 ping -f 需要 root，否则使用普通 ping
    if [ "$EUID" -eq 0 ]; then
        timeout $((DURATION / 3)) ping -f -c 1000 $TARGET 2>/dev/null || true
    else
        ping -c 100 -i 0.1 $TARGET 2>/dev/null || true
    fi
    
    echo "ICMP flood completed"
fi

echo ""
echo "=== 4. Mixed Traffic Test ==="

echo "Generating mixed traffic patterns..."

# 后台生成各种流量
for i in $(seq 1 10); do
    (
        for j in $(seq 1 10); do
            curl -s -o /dev/null --max-time 1 "http://$TARGET/?id=$i-$j" 2>/dev/null || true
            curl -s -o /dev/null --max-time 1 "http://$TARGET/search?q=test$i$j" 2>/dev/null || true
        done
    ) &
done

wait
echo "Mixed traffic completed"

# 等待处理
echo ""
echo "Waiting for NIDS to process traffic..."
sleep 5

# 最终统计
echo ""
echo "=================================================="
echo "  Test Results"
echo "=================================================="

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "Test duration: ${ELAPSED}s"

if [ -f "$LOG_DIR/eve.json" ]; then
    FINAL_LINES=$(wc -l < "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
    NEW_LINES=$((FINAL_LINES - INITIAL_LINES))
    
    echo "New eve.json entries: $NEW_LINES"
    
    if [ $NEW_LINES -gt 0 ]; then
        ALERT_COUNT=$(tail -$NEW_LINES "$LOG_DIR/eve.json" 2>/dev/null | grep -c '"event_type":"alert"' || echo 0)
        FLOW_COUNT=$(tail -$NEW_LINES "$LOG_DIR/eve.json" 2>/dev/null | grep -c '"event_type":"flow"' || echo 0)
        HTTP_COUNT=$(tail -$NEW_LINES "$LOG_DIR/eve.json" 2>/dev/null | grep -c '"event_type":"http"' || echo 0)
        
        echo ""
        echo "Event breakdown:"
        echo "  - Alerts: $ALERT_COUNT"
        echo "  - Flows: $FLOW_COUNT"
        echo "  - HTTP: $HTTP_COUNT"
        
        if [ $ELAPSED -gt 0 ]; then
            RATE=$((NEW_LINES / ELAPSED))
            echo ""
            echo "Processing rate: ~${RATE} events/second"
        fi
    fi
else
    echo "eve.json not found at $LOG_DIR/eve.json"
fi

# 检查 NIDS 探针状态
echo ""
echo "NIDS Probe Status:"
if pgrep -x "nids-probe" > /dev/null 2>&1; then
    PID=$(pgrep -x "nids-probe")
    MEM=$(ps -o rss= -p $PID 2>/dev/null || echo "N/A")
    CPU=$(ps -o %cpu= -p $PID 2>/dev/null || echo "N/A")
    echo "  ✓ Running (PID: $PID)"
    echo "    Memory: ${MEM}KB"
    echo "    CPU: ${CPU}%"
else
    echo "  ✗ Not running"
fi

# 检查 Suricata 状态
echo ""
echo "Suricata Status:"
if pgrep -x "suricata" > /dev/null 2>&1; then
    PID=$(pgrep -x "suricata" | head -1)
    MEM=$(ps -o rss= -p $PID 2>/dev/null || echo "N/A")
    CPU=$(ps -o %cpu= -p $PID 2>/dev/null || echo "N/A")
    echo "  ✓ Running (PID: $PID)"
    echo "    Memory: ${MEM}KB"
    echo "    CPU: ${CPU}%"
else
    echo "  ✗ Not running"
fi

echo ""
echo "=================================================="
