#pragma once

#include <atomic>
#include <memory>
#include <thread>
#include "config.h"
#include "socket_client.h"
#include "task_executor.h"
#include "json.hpp"

using json = nlohmann::json;

/**
 * Attack Tool main class
 * Connects to Probe Manager, receives attack commands, executes them
 */
class AttackTool {
public:
    explicit AttackTool(const Config& config);
    ~AttackTool();

    // Run main loop (blocking)
    int run();

    // Stop the tool
    void stop();

private:
    // Initialize components
    void initialize();

    // Connect to Probe Manager
    bool connect_to_manager();

    // Register with manager
    void register_probe();

    // Main event loop
    void main_loop();

    // Handle incoming command
    void handle_command(const json& cmd);

    // Handle attack execute command
    void handle_attack_execute(const json& data);

    // Handle attack cancel command
    void handle_attack_cancel(const json& data);

    // Handle status request
    void handle_status_request();

    // Send heartbeat
    void send_heartbeat();

    // Send event to manager
    void send_event(const std::string& event_type, const json& data);

    // Send attack result
    void send_attack_result(const AttackResult& result);

private:
    Config config_;
    std::unique_ptr<SocketClient> socket_client_;
    std::unique_ptr<TaskExecutor> task_executor_;
    std::atomic<bool> running_;

    // Statistics
    int tasks_executed_;
    int tasks_successful_;
    int tasks_failed_;

    // Timing
    std::chrono::steady_clock::time_point last_heartbeat_;
    std::chrono::steady_clock::time_point start_time_;
};
