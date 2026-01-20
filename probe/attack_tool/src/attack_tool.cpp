#include "attack_tool.h"
#include "logger.h"

#include <chrono>
#include <thread>

AttackTool::AttackTool(const Config& config)
    : config_(config)
    , running_(false)
    , tasks_executed_(0)
    , tasks_successful_(0)
    , tasks_failed_(0)
{
}

AttackTool::~AttackTool() {
    stop();
}

int AttackTool::run() {
    initialize();

    running_ = true;
    start_time_ = std::chrono::steady_clock::now();

    // Connect to manager
    while (running_ && !connect_to_manager()) {
        LOG_WARN("Failed to connect to Manager, retrying in 5 seconds...");
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    if (!running_) {
        return 1;
    }

    // Register with manager
    register_probe();

    // Main loop
    main_loop();

    return 0;
}

void AttackTool::stop() {
    running_ = false;
    if (socket_client_) {
        socket_client_->disconnect();
    }
}

void AttackTool::initialize() {
    LOG_INFO("Initializing Attack Tool components...");

    // Create socket client
    socket_client_ = std::make_unique<SocketClient>(
        config_.manager_host,
        config_.manager_port
    );

    // Set message callback
    socket_client_->set_message_callback([this](const json& msg) {
        handle_command(msg);
    });

    // Create task executor
    task_executor_ = std::make_unique<TaskExecutor>();
    task_executor_->set_default_target(
        config_.default_target_host,
        config_.default_target_port
    );
    task_executor_->set_timeout(config_.request_timeout_ms);

    last_heartbeat_ = std::chrono::steady_clock::now();

    LOG_INFO("Attack Tool initialized");
}

bool AttackTool::connect_to_manager() {
    LOG_INFO("Connecting to Manager at {}:{}...",
             config_.manager_host, config_.manager_port);

    return socket_client_->connect();
}

void AttackTool::register_probe() {
    LOG_INFO("Registering with Manager...");

    json reg_msg;
    reg_msg["event"] = "EVT_STATUS";
    reg_msg["probe_id"] = config_.probe_id;
    reg_msg["probe_type"] = config_.probe_type;
    reg_msg["data"] = {
        {"status", "online"},
        {"capabilities", {"http", "tcp", "udp"}},
        {"version", "1.0.0"}
    };

    socket_client_->send(reg_msg);
}

void AttackTool::main_loop() {
    LOG_INFO("Entering main loop...");

    while (running_) {
        // Poll for messages
        socket_client_->poll();

        // Check if we need to send heartbeat
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_heartbeat_
        ).count();

        if (elapsed >= config_.heartbeat_interval_ms) {
            send_heartbeat();
            last_heartbeat_ = now;
        }

        // Small sleep to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void AttackTool::handle_command(const json& msg) {
    std::string cmd;

    if (msg.contains("cmd")) {
        cmd = msg["cmd"].get<std::string>();
    } else {
        LOG_DEBUG("Received message without cmd field");
        return;
    }

    LOG_DEBUG("Received command: {}", cmd);

    if (cmd == "CMD_ATTACK_EXECUTE") {
        if (msg.contains("data")) {
            handle_attack_execute(msg["data"]);
        }
    } else if (cmd == "CMD_ATTACK_CANCEL") {
        if (msg.contains("data")) {
            handle_attack_cancel(msg["data"]);
        }
    } else if (cmd == "CMD_GET_STATUS" || cmd == "CMD_ATTACK_STATUS") {
        handle_status_request();
    } else if (cmd == "CMD_SHUTDOWN") {
        LOG_INFO("Received shutdown command");
        stop();
    } else {
        LOG_WARN("Unknown command: {}", cmd);
    }
}

void AttackTool::handle_attack_execute(const json& data) {
    std::string task_id = data.value("task_id", "");

    LOG_INFO("Executing attack task: {}", task_id);

    // Execute attack
    AttackResult result = task_executor_->execute(data);
    result.task_id = task_id;

    // Update statistics
    tasks_executed_++;
    if (result.success) {
        tasks_successful_++;
    } else {
        tasks_failed_++;
    }

    // Send result
    send_attack_result(result);
}

void AttackTool::handle_attack_cancel(const json& data) {
    std::string task_id = data.value("task_id", "");

    LOG_INFO("Cancelling attack task: {}", task_id);

    task_executor_->cancel(task_id);

    // Send acknowledgment
    send_event("EVT_ACK", {{"task_id", task_id}, {"action", "cancel"}});
}

void AttackTool::handle_status_request() {
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        now - start_time_
    ).count();

    json status;
    status["probe_id"] = config_.probe_id;
    status["probe_type"] = config_.probe_type;
    status["status"] = "online";
    status["uptime_seconds"] = uptime;
    status["tasks_executed"] = tasks_executed_;
    status["tasks_successful"] = tasks_successful_;
    status["tasks_failed"] = tasks_failed_;

    send_event("EVT_STATUS", status);
}

void AttackTool::send_heartbeat() {
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        now - start_time_
    ).count();

    json status;
    status["status"] = "online";
    status["uptime_seconds"] = uptime;
    status["tasks_executed"] = tasks_executed_;

    send_event("EVT_STATUS", status);
}

void AttackTool::send_event(const std::string& event_type, const json& data) {
    json msg;
    msg["event"] = event_type;
    msg["probe_id"] = config_.probe_id;
    msg["probe_type"] = config_.probe_type;
    msg["data"] = data;

    if (!socket_client_->send(msg)) {
        LOG_WARN("Failed to send event: {}", event_type);
    }
}

void AttackTool::send_attack_result(const AttackResult& result) {
    json msg;
    msg["event"] = "EVT_ATTACK_RESULT";
    msg["probe_id"] = config_.probe_id;
    msg["probe_type"] = config_.probe_type;
    msg["data"] = result.to_json();

    if (!socket_client_->send(msg)) {
        LOG_WARN("Failed to send attack result for task: {}", result.task_id);
    } else {
        LOG_INFO("Attack result sent: task_id={} success={}",
                 result.task_id, result.success);
    }
}
