#include "config.h"
#include "cloud_client.h"
#include "epoll_server.h"
#include "log_aggregator.h"
#include "logger.h"
#include "rule_manager.h"
#include "protocol.h"

#include <signal.h>
#include <unistd.h>
#include <map>
#include <ctime>
#include <sys/stat.h>

static EpollServer* g_server = nullptr;

void signal_handler(int sig) {
    LOG_INFO("Received signal ", sig, ", shutting down...");
    if (g_server) {
        g_server->stop();
    }
}

// 获取系统状态
json get_system_status() {
    json status;
    
    // CPU 使用率（简化实现）
    status["cpu_usage"] = 0.0;
    
    // 内存使用
    status["memory_usage"] = 0;
    
    // 运行时间
    static time_t start_time = time(nullptr);
    status["uptime"] = static_cast<int>(time(nullptr) - start_time);
    
    return status;
}

int main(int argc, char* argv[]) {
    LOG_INFO("=== Probe Manager Starting ===");

    // 加载配置
    Config config;
    config.load(argc > 1 ? argv[1] : "/etc/probe-manager/config.json");

    // 创建规则目录
    mkdir(config.rules_dir.c_str(), 0755);

    // 初始化组件
    CloudClient cloud(config.cloud_url);
    RuleManager rules(config.rules_dir);
    LogAggregator logs(config.log_batch_size, config.log_flush_interval * 1000);

    // 探针连接映射: fd -> probe_info
    std::map<int, json> probe_map;

    // 创建 epoll 服务器
    EpollServer server(config.listen_port);
    g_server = &server;

    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);  // 忽略 SIGPIPE

    // 设置消息回调
    server.set_message_callback([&](int fd, const json& msg) {
        std::string event_str;
        
        if (msg.contains("event")) {
            event_str = msg["event"].get<std::string>();
        } else if (msg.contains("cmd")) {
            // 处理来自探针的命令
            event_str = "CMD";
        }

        LOG_DEBUG("Received message from fd=", fd, ": event=", event_str);

        if (event_str == "EVT_ALERT") {
            // 收到告警日志，添加到聚合器
            if (msg.contains("data")) {
                logs.add_log(msg["data"]);
            }
        } else if (event_str == "EVT_STATUS") {
            // 更新探针状态
            if (msg.contains("data")) {
                probe_map[fd]["status"] = msg["data"];
            }
            if (msg.contains("probe_id")) {
                probe_map[fd]["probe_id"] = msg["probe_id"];
            }
            if (msg.contains("probe_type")) {
                probe_map[fd]["probe_type"] = msg["probe_type"];
            }
        } else if (event_str == "EVT_ACK") {
            LOG_DEBUG("Received ACK from probe fd=", fd);
        } else if (event_str == "EVT_ERROR") {
            LOG_WARN("Received error from probe fd=", fd);
            if (msg.contains("data")) {
                LOG_WARN("  Error: ", msg["data"].dump());
            }
        }
    });

    // 设置连接回调
    server.set_connect_callback([&](int fd) {
        probe_map[fd] = {
            {"fd", fd},
            {"connected_at", static_cast<int>(time(nullptr))}
        };
        LOG_INFO("Probe connected: fd=", fd, ", total connections: ", probe_map.size());
    });

    server.set_disconnect_callback([&](int fd) {
        if (probe_map.find(fd) != probe_map.end()) {
            LOG_INFO("Probe disconnected: fd=", fd);
            probe_map.erase(fd);
        }
    });

    // 向云端注册
    LOG_INFO("Registering with cloud...");
    auto reg_response = cloud.register_probe(
        config.probe_id,
        config.probe_name,
        config.probe_ip,
        config.probe_types
    );

    if (reg_response.contains("data") && 
        reg_response["data"].contains("status") &&
        reg_response["data"]["status"] == "ok") {
        LOG_INFO("Probe registered successfully with cloud");
    } else {
        LOG_WARN("Failed to register with cloud, will retry on heartbeat");
        if (reg_response.contains("data")) {
            LOG_WARN("  Response: ", reg_response["data"].dump());
        }
    }

    // 设置定时器: 心跳和规则检查
    server.add_timer(config.heartbeat_interval * 1000, [&]() {
        LOG_DEBUG("Heartbeat timer triggered");

        // 构建探针状态信息
        json status = get_system_status();
        json probes_info = json::array();
        
        for (const auto& [fd, info] : probe_map) {
            json probe_info = info;
            probe_info["fd"] = fd;
            probes_info.push_back(probe_info);
        }

        // 发送心跳
        auto response = cloud.heartbeat(
            config.probe_id,
            rules.current_version(),
            status,
            probes_info
        );

        // 检查是否有新规则
        if (response.contains("data") && 
            response["data"].contains("status") &&
            response["data"]["status"] == "ok") {
            
            if (response["data"].contains("latest_rule_version") &&
                !response["data"]["latest_rule_version"].is_null()) {
                
                std::string latest = response["data"]["latest_rule_version"].get<std::string>();
                
                if (!latest.empty() && latest != rules.current_version()) {
                    LOG_INFO("New rule version available: ", latest, " (current: ", rules.current_version(), ")");

                    // 下载新规则
                    auto rule_response = cloud.download_rules(config.probe_id, latest);
                    
                    if (rule_response.contains("data") &&
                        rule_response["data"].contains("status") &&
                        rule_response["data"]["status"] == "ok") {
                        
                        std::string version = rule_response["data"]["version"].get<std::string>();
                        std::string content = rule_response["data"]["content"].get<std::string>();
                        
                        rules.update(version, content);

                        // 通知所有探针重载规则
                        json reload_cmd = {
                            {"cmd", "CMD_RELOAD_RULES"},
                            {"data", {{"rules_path", rules.rules_path()}}}
                        };
                        
                        LOG_INFO("Broadcasting rule reload to ", probe_map.size(), " probes");
                        server.broadcast(reload_cmd);
                    }
                }
            }
        }

        // 检查并上报日志
        if (logs.should_flush()) {
            auto batch = logs.flush();
            if (!batch.empty()) {
                LOG_INFO("Uploading ", batch.size(), " logs to cloud");
                cloud.upload_logs(config.probe_id, batch);
            }
        }
    });

    LOG_INFO("Probe Manager started successfully");
    LOG_INFO("  Listening for probes on port ", config.listen_port);
    LOG_INFO("  Heartbeat interval: ", config.heartbeat_interval, "s");

    // 启动事件循环
    server.run();

    LOG_INFO("=== Probe Manager Stopped ===");
    return 0;
}
