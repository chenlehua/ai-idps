#pragma once

#include <chrono>
#include <mutex>
#include <vector>
#include "json.hpp"

using json = nlohmann::json;

class LogAggregator {
public:
    LogAggregator(size_t batch_size = 100, int flush_interval_ms = 10000);

    void add_log(const json& log);
    std::vector<json> flush();
    bool should_flush() const;

private:
    std::vector<json> logs_;
    mutable std::mutex mutex_;
    size_t batch_size_;
    int flush_interval_ms_;
    std::chrono::steady_clock::time_point last_flush_;
};
