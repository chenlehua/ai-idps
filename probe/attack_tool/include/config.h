#pragma once

#include <string>
#include <fstream>
#include "json.hpp"

using json = nlohmann::json;

struct Config {
    // Manager connection
    std::string manager_host = "127.0.0.1";
    int manager_port = 9001;

    // Attack tool identity
    std::string probe_id;
    std::string probe_type = "attack_tool";

    // Target settings (default target for attacks)
    std::string default_target_host = "127.0.0.1";
    int default_target_port = 80;

    // Timeouts
    int connect_timeout_ms = 5000;
    int request_timeout_ms = 30000;
    int heartbeat_interval_ms = 30000;

    // Retry settings
    int max_reconnect_attempts = 10;
    int reconnect_interval_ms = 5000;

    void load(const std::string& path) {
        std::ifstream f(path);
        if (!f.is_open()) {
            return;  // Use defaults
        }

        try {
            json j = json::parse(f);

            if (j.contains("manager_host")) manager_host = j["manager_host"];
            if (j.contains("manager_port")) manager_port = j["manager_port"];
            if (j.contains("probe_id")) probe_id = j["probe_id"];
            if (j.contains("probe_type")) probe_type = j["probe_type"];
            if (j.contains("default_target_host")) default_target_host = j["default_target_host"];
            if (j.contains("default_target_port")) default_target_port = j["default_target_port"];
            if (j.contains("connect_timeout_ms")) connect_timeout_ms = j["connect_timeout_ms"];
            if (j.contains("request_timeout_ms")) request_timeout_ms = j["request_timeout_ms"];
            if (j.contains("heartbeat_interval_ms")) heartbeat_interval_ms = j["heartbeat_interval_ms"];
            if (j.contains("max_reconnect_attempts")) max_reconnect_attempts = j["max_reconnect_attempts"];
            if (j.contains("reconnect_interval_ms")) reconnect_interval_ms = j["reconnect_interval_ms"];

        } catch (const std::exception& e) {
            // Use defaults on parse error
        }
    }
};
