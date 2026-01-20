#pragma once

#include <string>
#include <vector>

struct Config {
    std::string probe_id = "probe-001";
    std::string probe_name = "default-probe";
    std::string probe_ip = "127.0.0.1";
    std::vector<std::string> probe_types = {"nids"};

    std::string cloud_url = "http://localhost:8000";
    int listen_port = 9010;
    std::string rules_dir = "/var/lib/nids/rules";

    int heartbeat_interval = 300;
    int log_batch_size = 100;
    int log_flush_interval = 10;

    void load(const std::string& path);
};
