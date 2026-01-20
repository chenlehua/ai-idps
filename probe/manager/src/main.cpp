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
#include <queue>
#include <ctime>
#include <sys/stat.h>
#include <sys/wait.h>

static EpollServer* g_server = nullptr;

// 攻击任务队列
static std::queue<json> g_attack_tasks;
static pid_t g_attack_tool_pid = 0;

void signal_handler(int sig) {
    LOG_INFO("Received signal {}, shutting down...", sig);
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

    // 攻击工具状态
    status["attack_tool_running"] = (g_attack_tool_pid > 0);
    status["pending_attack_tasks"] = g_attack_tasks.size();

    return status;
}

// 启动攻击工具进程
bool start_attack_tool(const std::string& attack_tool_path) {
    if (g_attack_tool_pid > 0) {
        // 检查进程是否还在运行
        int status;
        pid_t result = waitpid(g_attack_tool_pid, &status, WNOHANG);
        if (result == 0) {
            // 进程仍在运行
            return true;
        }
        // 进程已结束
        g_attack_tool_pid = 0;
    }

    LOG_INFO("Starting attack tool: {}", attack_tool_path);

    pid_t pid = fork();
    if (pid == 0) {
        // 子进程
        execl(attack_tool_path.c_str(), attack_tool_path.c_str(), nullptr);
        LOG_ERROR("Failed to exec attack tool");
        _exit(1);
    } else if (pid > 0) {
        g_attack_tool_pid = pid;
        LOG_INFO("Attack tool started with PID: {}", pid);
        return true;
    } else {
        LOG_ERROR("Failed to fork attack tool process");
        return false;
    }
}

// 停止攻击工具进程
void stop_attack_tool() {
    if (g_attack_tool_pid > 0) {
        LOG_INFO("Stopping attack tool PID: {}", g_attack_tool_pid);
        kill(g_attack_tool_pid, SIGTERM);

        // 等待进程结束
        int status;
        waitpid(g_attack_tool_pid, &status, 0);
        g_attack_tool_pid = 0;
    }
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

        LOG_DEBUG("Received message from fd={}: event={}", fd, event_str);

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
            LOG_DEBUG("Received ACK from probe fd={}", fd);
        } else if (event_str == "EVT_ERROR") {
            LOG_WARN("Received error from probe fd={}", fd);
            if (msg.contains("data")) {
                LOG_WARN("  Error: {}", msg["data"].dump());
            }
        } else if (event_str == "EVT_ATTACK_RESULT") {
            // 攻击测试结果
            if (msg.contains("data")) {
                json result = msg["data"];
                std::string task_id = result.value("task_id", "");
                bool success = result.value("success", false);
                int response_time_ms = result.value("response_time_ms", 0);
                std::string error = result.value("error", "");

                LOG_INFO("Attack result received: task_id={} success={}", task_id, success);

                // 上报结果到云端
                cloud.report_task_result(task_id, success, result.value("data", json()), error, response_time_ms);
            }
        }
    });

    // 设置连接回调
    server.set_connect_callback([&](int fd) {
        probe_map[fd] = {
            {"fd", fd},
            {"connected_at", static_cast<int>(time(nullptr))}
        };
        LOG_INFO("Probe connected: fd={}, total connections: {}", fd, probe_map.size());
    });

    server.set_disconnect_callback([&](int fd) {
        if (probe_map.find(fd) != probe_map.end()) {
            LOG_INFO("Probe disconnected: fd={}", fd);
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
            LOG_WARN("  Response: {}", reg_response["data"].dump());
        }
    }

    // 定时器: 规则版本检查 (Pull 模式，每 5 分钟)
    server.add_timer(300 * 1000, [&]() {
        LOG_DEBUG("Rule sync timer triggered");

        // 使用 Pull 模式检查规则版本
        auto version_response = cloud.check_rule_version(config.probe_id, rules.current_version());

        if (!version_response.contains("error") && version_response.contains("needs_update")) {
            if (version_response["needs_update"].get<bool>()) {
                std::string latest = version_response.value("latest_version", "");
                LOG_INFO("New rule version available: {} (current: {})", latest, rules.current_version());

                // 下载新规则 (Pull 模式)
                auto rule_response = cloud.download_rules_pull(config.probe_id, latest);

                if (!rule_response.contains("error") && rule_response.contains("content")) {
                    std::string version = rule_response["version"].get<std::string>();
                    std::string content = rule_response["content"].get<std::string>();

                    rules.update(version, content);

                    // 通知所有探针重载规则
                    json reload_cmd = {
                        {"cmd", "CMD_RELOAD_RULES"},
                        {"data", {{"rules_path", rules.rules_path()}}}
                    };

                    LOG_INFO("Broadcasting rule reload to {} probes", probe_map.size());
                    server.broadcast(reload_cmd);
                }
            }
        }
    });

    // 定时器: 心跳 (每 5 分钟)
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

        // 检查并上报日志
        if (logs.should_flush()) {
            auto batch = logs.flush();
            if (!batch.empty()) {
                LOG_INFO("Uploading {} logs to cloud", batch.size());
                cloud.upload_logs(config.probe_id, batch);
            }
        }
    });

    // 定时器: 攻击任务轮询 (Pull 模式，每 5 秒)
    server.add_timer(5 * 1000, [&]() {
        // 轮询攻击任务
        auto tasks_response = cloud.poll_attack_tasks(config.probe_id, 10);

        if (!tasks_response.contains("error") && tasks_response.contains("tasks")) {
            auto tasks = tasks_response["tasks"];

            for (const auto& task : tasks) {
                std::string task_id = task.value("task_id", "");
                std::string task_type = task.value("task_type", "");

                LOG_INFO("Received attack task: {} type={}", task_id, task_type);

                // 标记任务开始
                cloud.start_attack_task(task_id);

                // 将任务加入队列
                g_attack_tasks.push(task);

                // 向连接的探针发送攻击命令
                json attack_cmd = {
                    {"cmd", "CMD_ATTACK_EXECUTE"},
                    {"data", task["payload"]}
                };

                // 广播给所有探针（实际应该根据任务类型选择合适的探针）
                server.broadcast(attack_cmd);
            }
        }
    });

    LOG_INFO("Probe Manager started successfully");
    LOG_INFO("  Listening for probes on port {}", config.listen_port);
    LOG_INFO("  Heartbeat interval: {}s", config.heartbeat_interval);
    LOG_INFO("  Rule sync interval: 300s (Pull mode)");
    LOG_INFO("  Task poll interval: 5s");

    // 启动事件循环
    server.run();

    // 清理
    stop_attack_tool();

    LOG_INFO("=== Probe Manager Stopped ===");
    return 0;
}
