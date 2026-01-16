#include "nids_probe.h"
#include "protocol.h"
#include "logger.h"

#include <unistd.h>
#include <ctime>
#include <sstream>
#include <iomanip>

NidsProbe::NidsProbe(const Config& config)
    : config_(config)
    , running_(false)
    , alert_count_(0)
{
    // 生成或使用指定的探针ID
    if (config_.probe_id.empty()) {
        probe_id_ = generate_probe_id();
    } else {
        probe_id_ = config_.probe_id;
    }
    
    interface_ = config_.interface;
    
    LOG_INFO("Initializing NIDS probe: {}", probe_id_);
    LOG_INFO("  Interface: {}", interface_);
    LOG_INFO("  Manager: {}:{}", config_.manager_host, config_.manager_port);
    LOG_INFO("  Suricata config: {}", config_.suricata_config);
    if (!config_.rules_path.empty()) {
        LOG_INFO("  Rules path: {}", config_.rules_path);
    }
}

NidsProbe::~NidsProbe() {
    stop();
}

std::string NidsProbe::generate_probe_id() {
    std::ostringstream oss;
    oss << "nids-" << config_.interface;
    
    // 添加主机名
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        oss << "-" << hostname;
    }
    
    return oss.str();
}

void NidsProbe::start() {
    if (running_) {
        LOG_WARN("Probe is already running");
        return;
    }
    
    LOG_INFO("Starting NIDS probe {}...", probe_id_);
    
    // 创建Manager客户端
    manager_client_ = std::make_unique<SocketClient>(
        config_.manager_host, config_.manager_port);
    
    // 连接到Manager
    int connect_attempts = 0;
    while (!manager_client_->connect()) {
        connect_attempts++;
        if (connect_attempts >= 10) {
            throw std::runtime_error("Failed to connect to Manager after 10 attempts");
        }
        LOG_WARN("Failed to connect to Manager, retrying in 5 seconds... ({}/10)", 
                 connect_attempts);
        sleep(5);
    }
    
    // 设置命令回调
    manager_client_->set_message_callback([this](const json& msg) {
        handle_command(msg);
    });
    
    // 创建Suricata管理器
    suricata_ = std::make_unique<SuricataManager>(
        config_.suricata_config,
        config_.interface,
        config_.rules_path,
        config_.log_dir);
    
    // 启动Suricata
    if (!suricata_->start()) {
        throw std::runtime_error("Failed to start Suricata");
    }
    
    // 创建eve.json解析器
    eve_parser_ = std::make_unique<EveParser>(suricata_->eve_log_path());
    eve_parser_->set_alert_callback([this](const json& alert) {
        on_alert(alert);
    });
    
    // 启动解析器
    eve_parser_->start();
    
    running_ = true;
    LOG_INFO("NIDS probe started successfully");
    
    // 发送初始状态
    send_status();
    
    // 主循环
    while (running_) {
        // 轮询Manager消息
        manager_client_->poll();
        
        // 检查Suricata状态
        if (!suricata_->is_running()) {
            LOG_ERROR("Suricata process died, attempting restart...");
            
            // 停止解析器
            eve_parser_->stop();
            
            // 重启Suricata
            sleep(2);
            if (suricata_->start()) {
                // 重启解析器
                eve_parser_ = std::make_unique<EveParser>(suricata_->eve_log_path());
                eve_parser_->set_alert_callback([this](const json& alert) {
                    on_alert(alert);
                });
                eve_parser_->start();
                LOG_INFO("Suricata restarted successfully");
            } else {
                LOG_ERROR("Failed to restart Suricata");
                sleep(10);
            }
        }
        
        // 短暂休眠
        usleep(100000);  // 100ms
    }
}

void NidsProbe::stop() {
    if (!running_) {
        return;
    }
    
    LOG_INFO("Stopping NIDS probe {}...", probe_id_);
    running_ = false;
    
    // 停止eve解析器
    if (eve_parser_) {
        eve_parser_->stop();
        eve_parser_.reset();
    }
    
    // 停止Suricata
    if (suricata_) {
        suricata_->stop();
        suricata_.reset();
    }
    
    // 断开Manager连接
    if (manager_client_) {
        manager_client_->disconnect();
        manager_client_.reset();
    }
    
    LOG_INFO("NIDS probe stopped, processed {} alerts", alert_count_.load());
}

void NidsProbe::handle_command(const json& msg) {
    if (!msg.contains("cmd")) {
        LOG_WARN("Received message without cmd field");
        return;
    }
    
    std::string cmd = msg["cmd"].get<std::string>();
    LOG_DEBUG("Received command: {}", cmd);
    
    if (cmd == "CMD_RELOAD_RULES") {
        // 热更新规则
        std::string rules_path;
        if (msg.contains("data") && msg["data"].contains("rules_path")) {
            rules_path = msg["data"]["rules_path"].get<std::string>();
        }
        
        if (!rules_path.empty()) {
            suricata_->set_rules_path(rules_path);
        }
        
        bool success = suricata_->reload_rules();
        send_ack(cmd, success, success ? "Rules reloaded" : "Failed to reload rules");
        
    } else if (cmd == "CMD_GET_STATUS") {
        send_status();
        
    } else if (cmd == "CMD_STOP") {
        LOG_INFO("Received STOP command");
        send_ack(cmd, true, "Stopping Suricata");
        suricata_->stop();
        
    } else if (cmd == "CMD_START") {
        LOG_INFO("Received START command");
        bool success = suricata_->start();
        send_ack(cmd, success, success ? "Suricata started" : "Failed to start Suricata");
        
    } else if (cmd == "CMD_SHUTDOWN") {
        LOG_INFO("Received SHUTDOWN command");
        send_ack(cmd, true, "Shutting down");
        stop();
        
    } else {
        LOG_WARN("Unknown command: {}", cmd);
        send_ack(cmd, false, "Unknown command");
    }
}

void NidsProbe::on_alert(const json& alert) {
    alert_count_++;
    
    // 转换为标准格式
    json log;
    log["probe_type"] = "nids";
    log["instance_id"] = probe_id_;
    log["timestamp"] = alert.value("timestamp", "");
    log["src_ip"] = alert.value("src_ip", "0.0.0.0");
    log["dest_ip"] = alert.value("dest_ip", "0.0.0.0");
    log["src_port"] = alert.value("src_port", 0);
    log["dest_port"] = alert.value("dest_port", 0);
    log["protocol"] = alert.value("proto", "");
    
    // 提取alert信息
    if (alert.contains("alert")) {
        const auto& alert_info = alert["alert"];
        log["alert"] = {
            {"signature", alert_info.value("signature", "")},
            {"signature_id", alert_info.value("signature_id", 0)},
            {"severity", alert_info.value("severity", 0)},
            {"category", alert_info.value("category", "")}
        };
    } else {
        log["alert"] = {
            {"signature", ""},
            {"signature_id", 0},
            {"severity", 0},
            {"category", ""}
        };
    }
    
    log["raw"] = alert.dump();
    
    send_alert(log);
}

void NidsProbe::send_alert(const json& alert) {
    if (!manager_client_ || !manager_client_->is_connected()) {
        return;
    }
    
    json msg = {
        {"event", "EVT_ALERT"},
        {"probe_type", "nids"},
        {"probe_id", probe_id_},
        {"data", alert}
    };
    
    manager_client_->send(msg);
}

void NidsProbe::send_status() {
    if (!manager_client_ || !manager_client_->is_connected()) {
        return;
    }
    
    json status = {
        {"event", "EVT_STATUS"},
        {"probe_type", "nids"},
        {"probe_id", probe_id_},
        {"data", {
            {"running", suricata_ ? suricata_->is_running() : false},
            {"interface", interface_},
            {"suricata_pid", suricata_ ? suricata_->pid() : -1},
            {"alert_count", alert_count_.load()},
            {"eve_path", suricata_ ? suricata_->eve_log_path() : ""},
            {"rules_path", suricata_ ? suricata_->rules_path() : ""}
        }}
    };
    
    manager_client_->send(status);
    LOG_DEBUG("Sent status to Manager");
}

void NidsProbe::send_ack(const std::string& cmd, bool success, const std::string& message) {
    if (!manager_client_ || !manager_client_->is_connected()) {
        return;
    }
    
    json ack = {
        {"event", "EVT_ACK"},
        {"probe_type", "nids"},
        {"probe_id", probe_id_},
        {"data", {
            {"cmd", cmd},
            {"success", success},
            {"message", message}
        }}
    };
    
    manager_client_->send(ack);
}
