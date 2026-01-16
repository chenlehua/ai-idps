#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <fstream>
#include "json.hpp"

using json = nlohmann::json;

/**
 * eve.json解析器
 * 使用inotify监听文件变化，实时解析Suricata输出的日志
 */
class EveParser {
public:
    using AlertCallback = std::function<void(const json& alert)>;
    
    explicit EveParser(const std::string& eve_path);
    ~EveParser();
    
    // 设置告警回调
    void set_alert_callback(AlertCallback cb) { alert_callback_ = cb; }
    
    // 开始监听
    void start();
    
    // 停止监听
    void stop();
    
    // 是否正在运行
    bool is_running() const { return running_; }
    
    // 获取已处理的告警数量
    size_t alert_count() const { return alert_count_; }
    
private:
    // 监听循环
    void watch_loop();
    
    // 处理一行日志
    void process_line(const std::string& line);
    
    // 等待文件创建
    bool wait_for_file(int timeout_seconds = 60);
    
private:
    std::string eve_path_;
    std::atomic<bool> running_;
    std::thread watch_thread_;
    AlertCallback alert_callback_;
    
    int inotify_fd_;
    int watch_fd_;
    std::streampos file_pos_;
    std::atomic<size_t> alert_count_;
};
