# NIDS 探针黑盒测试

本目录包含用于测试 NIDS 探针检测能力的黑盒测试用例。

## 测试环境要求

- NIDS 探针已启动并连接到 Probe Manager
- Suricata 已安装并正常运行
- ET Open 规则已加载
- 测试目标网络可达

## 测试工具依赖

```bash
# 基础工具
sudo apt-get install -y nmap netcat curl hping3

# 可选高级工具
sudo apt-get install -y nikto hydra tcpreplay

# Python 依赖
pip3 install scapy requests
```

## 测试分类

### 1. 端口扫描检测 (test_port_scan.sh)
- TCP SYN 扫描
- TCP Connect 扫描
- UDP 扫描
- 隐蔽扫描 (NULL/FIN/XMAS)

### 2. Web 攻击检测 (test_web_attacks.sh)
- SQL 注入
- XSS 攻击
- 路径遍历
- 命令注入

### 3. 协议异常检测 (test_protocol_anomaly.sh)
- 畸形 HTTP 请求
- DNS 异常
- ICMP 异常

### 4. 恶意流量模拟 (test_malware_traffic.sh)
- 恶意域名访问
- C&C 通信特征
- 恶意 User-Agent

### 5. Manager 通信测试 (test_manager_comm.py)
- TCP 连接测试
- 协议消息测试
- 告警上报验证

## 运行测试

```bash
# 运行所有测试
make test-nids

# 运行单个测试
./test_port_scan.sh <target_ip>
./test_web_attacks.sh <target_url>

# 运行 Python 测试
python3 run_nids_tests.py --target <target_ip> --manager-port 9010
```

## 验证告警

```bash
# 查看 Suricata 告警
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# 查看 NIDS 探针日志
make logs SERVICE=nids-probe

# 查看 Probe Manager 日志
make logs SERVICE=probe-manager
```

## 测试矩阵

| 测试类型 | 工具 | 预期告警 |
|:---------|:-----|:---------|
| TCP SYN 扫描 | nmap -sS | ET SCAN 系列规则 |
| UDP 扫描 | nmap -sU | ET SCAN UDP 规则 |
| SQL 注入 | curl/sqlmap | ET WEB_SERVER SQL Injection |
| XSS 攻击 | curl | ET WEB_CLIENT XSS |
| 路径遍历 | curl | ET WEB_SERVER Directory Traversal |
| 暴力破解 | hydra | ET SCAN SSH Brute Force |
| 恶意软件域名 | curl | ET MALWARE 系列规则 |

## 注意事项

1. 请在隔离的测试环境中运行测试
2. 部分测试需要 root 权限
3. 测试可能会触发防火墙或 IDS 告警
4. 确保已获得测试目标的授权
