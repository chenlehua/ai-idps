#pragma once

#include <string>
#include <memory>
#include <atomic>
#include "json.hpp"
#include "suricata_manager.h"
#include "eve_parser.h"
#include "socket_client.h"

using json = nlohmann::json;

/**
 * NIDS探针主类
 * 负责协调Suricata管理、日志解析、与Manager通信
 */
class NidsProbe {
public:
    struct Config {
        std::string manager_host = "127.0.0.1";
        int manager_port = 9000;
        std::string interface = "eth0";
        std::string suricata_config = "/etc/suricata/suricata.yaml";
        std::string rules_path;
        std::string log_dir = "/var/log/suricata";
        std::string probe_id;  // 如果为空，自动生成
    };
    
    explicit NidsProbe(const Config& config);
    ~NidsProbe();
    
    // 启动探针
    void start();
    
    // 停止探针
    void stop();
    
    // 是否正在运行
    bool is_running() const { return running_; }
    
    // 获取探针ID
    const std::string& probe_id() const { return probe_id_; }
    
    // 处理Manager命令
    void handle_command(const json& cmd);
    
private:
    // 告警回调
    void on_alert(const json& alert);
    
    // 发送告警到Manager
    void send_alert(const json& alert);
    
    // 发送状态到Manager
    void send_status();
    
    // 发送ACK
    void send_ack(const std::string& cmd, bool success, const std::string& message = "");
    
    // 生成探针ID
    std::string generate_probe_id();
    
private:
    Config config_;
    std::string probe_id_;
    std::string interface_;
    
    std::unique_ptr<SuricataManager> suricata_;
    std::unique_ptr<EveParser> eve_parser_;
    std::unique_ptr<SocketClient> manager_client_;
    
    std::atomic<bool> running_;
    std::atomic<uint64_t> alert_count_;
};
