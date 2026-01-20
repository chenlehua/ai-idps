#include "config.h"
#include "logger.h"
#include "json.hpp"

#include <fstream>
#include <cstdlib>

using json = nlohmann::json;

void Config::load(const std::string& path) {
    // 首先尝试从配置文件读取
    std::ifstream file(path);
    if (file.is_open()) {
        try {
            json config = json::parse(file);

            if (config.contains("probe_id")) {
                probe_id = config["probe_id"].get<std::string>();
            }
            if (config.contains("probe_name")) {
                probe_name = config["probe_name"].get<std::string>();
            }
            if (config.contains("probe_ip")) {
                probe_ip = config["probe_ip"].get<std::string>();
            }
            if (config.contains("probe_types") && config["probe_types"].is_array()) {
                probe_types.clear();
                for (const auto& t : config["probe_types"]) {
                    probe_types.push_back(t.get<std::string>());
                }
            }
            if (config.contains("cloud_url")) {
                cloud_url = config["cloud_url"].get<std::string>();
            }
            if (config.contains("listen_port")) {
                listen_port = config["listen_port"].get<int>();
            }
            if (config.contains("rules_dir")) {
                rules_dir = config["rules_dir"].get<std::string>();
            }
            if (config.contains("heartbeat_interval")) {
                heartbeat_interval = config["heartbeat_interval"].get<int>();
            }
            if (config.contains("log_batch_size")) {
                log_batch_size = config["log_batch_size"].get<int>();
            }
            if (config.contains("log_flush_interval")) {
                log_flush_interval = config["log_flush_interval"].get<int>();
            }

            LOG_INFO("Config loaded from: {}", path);
        } catch (const json::exception& e) {
            LOG_ERROR("Failed to parse config file: {}", e.what());
        }
    } else {
        LOG_WARN("Config file not found: {}, using defaults/env", path);
    }

    // 环境变量优先级最高，覆盖配置文件
    if (const char* env = std::getenv("PROBE_ID")) {
        probe_id = env;
    }
    if (const char* env = std::getenv("PROBE_NAME")) {
        probe_name = env;
    }
    if (const char* env = std::getenv("PROBE_IP")) {
        probe_ip = env;
    }
    if (const char* env = std::getenv("CLOUD_URL")) {
        cloud_url = env;
    }
    if (const char* env = std::getenv("LISTEN_PORT")) {
        listen_port = std::atoi(env);
    }
    if (const char* env = std::getenv("RULES_DIR")) {
        rules_dir = env;
    }
    if (const char* env = std::getenv("HEARTBEAT_INTERVAL")) {
        heartbeat_interval = std::atoi(env);
    }

    // 打印配置
    LOG_INFO("Configuration:");
    LOG_INFO("  probe_id: {}", probe_id);
    LOG_INFO("  probe_name: {}", probe_name);
    LOG_INFO("  probe_ip: {}", probe_ip);
    LOG_INFO("  cloud_url: {}", cloud_url);
    LOG_INFO("  listen_port: {}", listen_port);
    LOG_INFO("  rules_dir: {}", rules_dir);
    LOG_INFO("  heartbeat_interval: {}s", heartbeat_interval);
}
