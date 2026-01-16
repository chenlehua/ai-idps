#include "log_aggregator.h"

LogAggregator::LogAggregator(size_t batch_size, int flush_interval_ms)
    : batch_size_(batch_size)
    , flush_interval_ms_(flush_interval_ms)
    , last_flush_(std::chrono::steady_clock::now()) {
}

void LogAggregator::add_log(const json& log) {
    std::lock_guard<std::mutex> lock(mutex_);
    logs_.push_back(log);
}

std::vector<json> LogAggregator::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto batch = logs_;
    logs_.clear();
    last_flush_ = std::chrono::steady_clock::now();
    return batch;
}

bool LogAggregator::should_flush() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (logs_.size() >= batch_size_) {
        return true;
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - last_flush_
    );
    return !logs_.empty() && elapsed.count() >= flush_interval_ms_;
}
