#pragma once

#include <string>
#include <memory>
#include <chrono>
#include "json.hpp"
#include "generators/http_generator.h"
#include "generators/tcp_generator.h"
#include "generators/udp_generator.h"

using json = nlohmann::json;

/**
 * Attack result structure
 */
struct AttackResult {
    std::string task_id;
    std::string test_id;
    int rule_sid = 0;
    bool success = false;
    int response_time_ms = 0;
    std::string error;
    json data;

    json to_json() const {
        json j;
        j["task_id"] = task_id;
        if (!test_id.empty()) j["test_id"] = test_id;
        if (rule_sid > 0) j["rule_sid"] = rule_sid;
        j["success"] = success;
        j["response_time_ms"] = response_time_ms;
        if (!error.empty()) j["error"] = error;
        if (!data.is_null()) j["data"] = data;
        return j;
    }
};

/**
 * Task executor - executes attack tasks
 */
class TaskExecutor {
public:
    TaskExecutor();
    ~TaskExecutor();

    // Execute attack task
    AttackResult execute(const json& command);

    // Cancel task (by task_id)
    void cancel(const std::string& task_id);

    // Set default target
    void set_default_target(const std::string& host, int port);

    // Set request timeout
    void set_timeout(int timeout_ms);

private:
    // Execute different attack types
    AttackResult execute_http_attack(const json& payload, const json& target);
    AttackResult execute_tcp_attack(const json& payload, const json& target);
    AttackResult execute_udp_attack(const json& payload, const json& target);

    // Send HTTP request using libcurl
    AttackResult send_http_request(
        const std::string& method,
        const std::string& url,
        const std::map<std::string, std::string>& headers,
        const std::string& body = ""
    );

    // Send raw TCP data
    AttackResult send_tcp_data(
        const std::string& host,
        int port,
        const std::string& data
    );

    // Send raw UDP data
    AttackResult send_udp_data(
        const std::string& host,
        int port,
        const std::string& data
    );

private:
    std::unique_ptr<HTTPGenerator> http_generator_;
    std::unique_ptr<TCPGenerator> tcp_generator_;
    std::unique_ptr<UDPGenerator> udp_generator_;

    std::string default_host_;
    int default_port_;
    int timeout_ms_;
};
