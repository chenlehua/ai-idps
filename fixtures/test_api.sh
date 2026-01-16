#!/bin/bash

# NIDS Backend API 测试脚本
# 使用方法: ./test_api.sh [BASE_URL]
# 默认 BASE_URL: http://localhost

BASE_URL="${1:-http://localhost}"
PASSED=0
FAILED=0

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================"
echo "NIDS Backend API 测试"
echo "Base URL: $BASE_URL"
echo "======================================"
echo ""

# 测试函数
test_api() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local data="$4"
    local expected_status="$5"

    echo -n "测试: $name ... "

    if [ "$method" == "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}${endpoint}")
    else
        response=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}${endpoint}" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi

    # 获取状态码（最后一行）
    http_code=$(echo "$response" | tail -n1)
    # 获取响应体（除了最后一行）
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" == "$expected_status" ]; then
        echo -e "${GREEN}通过${NC} (HTTP $http_code)"
        PASSED=$((PASSED + 1))
        # 显示响应的前100个字符
        echo "  响应: $(echo "$body" | head -c 200)..."
    else
        echo -e "${RED}失败${NC} (期望 $expected_status, 实际 $http_code)"
        FAILED=$((FAILED + 1))
        echo "  响应: $body"
    fi
    echo ""
}

# 1. 健康检查
test_api "健康检查" "GET" "/health" "" "200"

# 2. 探针注册
test_api "探针注册 (cmd=30)" "POST" "/api/v1/probe" '{
    "cmd": 30,
    "data": {
        "probe_id": "probe-test-001",
        "name": "测试探针1",
        "ip": "192.168.1.100",
        "probe_types": ["nids"]
    }
}' "200"

# 3. 心跳请求
test_api "心跳请求 (cmd=20)" "POST" "/api/v1/probe" '{
    "cmd": 20,
    "data": {
        "probe_id": "probe-test-001",
        "rule_version": null,
        "status": {
            "cpu_usage": 25.5,
            "memory_usage": 512,
            "uptime": 3600
        },
        "probes": [
            {
                "type": "nids",
                "id": "probe-test-001-nids",
                "status": "running",
                "interface": "eth0"
            }
        ]
    }
}' "200"

# 4. 获取规则列表（空）
test_api "获取规则列表" "GET" "/api/v1/rules" "" "200"

# 5. 创建规则版本
test_api "创建规则版本" "POST" "/api/v1/rules" '{
    "content": "# Suricata Rules\nalert tcp any any -> any any (msg:\"Test Rule\"; sid:1000001; rev:1;)",
    "description": "测试规则版本"
}' "200"

# 6. 获取最新规则
test_api "获取最新规则" "GET" "/api/v1/rules/latest" "" "200"

# 7. 日志上报
test_api "日志上报 (cmd=10)" "POST" "/api/v1/probe" '{
    "cmd": 10,
    "data": {
        "probe_id": "probe-test-001",
        "logs": [
            {
                "probe_type": "nids",
                "instance_id": "probe-test-001-nids",
                "timestamp": "2024-01-15T10:30:00.123Z",
                "src_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "src_port": 54321,
                "dest_port": 80,
                "protocol": "TCP",
                "alert": {
                    "signature": "ET MALWARE Suspicious User-Agent",
                    "signature_id": 2000001,
                    "severity": 1,
                    "category": "malware"
                },
                "raw": "{\"original\":\"log\"}"
            }
        ]
    }
}' "200"

# 8. 查询日志
test_api "查询告警日志" "GET" "/api/v1/logs?limit=10" "" "200"

# 9. 日志统计
test_api "日志统计" "GET" "/api/v1/logs/stats?hours=24" "" "200"

# 10. 获取探针列表
test_api "获取探针列表" "GET" "/api/v1/probes" "" "200"

# 11. 获取探针详情
test_api "获取探针详情" "GET" "/api/v1/probes/probe-test-001" "" "200"

# 12. 获取不存在的探针（应返回 404）
test_api "获取不存在的探针" "GET" "/api/v1/probes/nonexistent" "" "404"

# 13. 规则下载（获取刚创建的规则版本）
# 先获取最新版本号
LATEST_VERSION=$(curl -s "${BASE_URL}/api/v1/rules/latest" | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -n "$LATEST_VERSION" ]; then
    test_api "规则下载 (cmd=40)" "POST" "/api/v1/probe" "{
        \"cmd\": 40,
        \"data\": {
            \"probe_id\": \"probe-test-001\",
            \"version\": \"$LATEST_VERSION\"
        }
    }" "200"
fi

# 14. 未知命令测试
test_api "未知命令 (cmd=99)" "POST" "/api/v1/probe" '{
    "cmd": 99,
    "data": {}
}' "200"

echo "======================================"
echo "测试结果汇总"
echo "======================================"
echo -e "通过: ${GREEN}$PASSED${NC}"
echo -e "失败: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}所有测试通过!${NC}"
    exit 0
else
    echo -e "${RED}有 $FAILED 个测试失败${NC}"
    exit 1
fi
