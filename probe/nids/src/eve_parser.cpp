#include "eve_parser.h"
#include "logger.h"

#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#include <filesystem>

namespace fs = std::filesystem;

constexpr size_t EVENT_BUF_SIZE = 4096;

EveParser::EveParser(const std::string& eve_path)
    : eve_path_(eve_path)
    , running_(false)
    , inotify_fd_(-1)
    , watch_fd_(-1)
    , file_pos_(0)
    , alert_count_(0)
{
}

EveParser::~EveParser() {
    stop();
}

void EveParser::start() {
    if (running_) {
        return;
    }
    
    // 初始化 inotify
    inotify_fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd_ < 0) {
        LOG_ERROR("Failed to init inotify: {}", strerror(errno));
        throw std::runtime_error("Failed to init inotify");
    }
    
    running_ = true;
    watch_thread_ = std::thread(&EveParser::watch_loop, this);
    
    LOG_INFO("Started watching {}", eve_path_);
}

void EveParser::stop() {
    running_ = false;
    
    if (watch_thread_.joinable()) {
        watch_thread_.join();
    }
    
    if (watch_fd_ >= 0) {
        inotify_rm_watch(inotify_fd_, watch_fd_);
        watch_fd_ = -1;
    }
    
    if (inotify_fd_ >= 0) {
        close(inotify_fd_);
        inotify_fd_ = -1;
    }
    
    LOG_INFO("Stopped watching eve.json, processed {} alerts", alert_count_.load());
}

bool EveParser::wait_for_file(int timeout_seconds) {
    LOG_INFO("Waiting for eve.json to be created...");
    
    // 监听目录的创建事件
    std::string dir_path = fs::path(eve_path_).parent_path();
    
    // 确保目录存在
    if (!fs::exists(dir_path)) {
        try {
            fs::create_directories(dir_path);
        } catch (const std::exception& e) {
            LOG_WARN("Failed to create directory {}: {}", dir_path, e.what());
        }
    }
    
    // 添加目录监听
    int dir_watch = inotify_add_watch(inotify_fd_, dir_path.c_str(), 
                                       IN_CREATE | IN_MOVED_TO);
    if (dir_watch < 0) {
        LOG_WARN("Failed to watch directory {}: {}", dir_path, strerror(errno));
    }
    
    for (int i = 0; i < timeout_seconds && running_; i++) {
        if (fs::exists(eve_path_)) {
            if (dir_watch >= 0) {
                inotify_rm_watch(inotify_fd_, dir_watch);
            }
            return true;
        }
        
        // 等待目录事件
        pollfd pfd{inotify_fd_, POLLIN, 0};
        int ret = poll(&pfd, 1, 1000);
        
        if (ret > 0) {
            // 读取并丢弃事件
            char buf[EVENT_BUF_SIZE];
            read(inotify_fd_, buf, EVENT_BUF_SIZE);
        }
    }
    
    if (dir_watch >= 0) {
        inotify_rm_watch(inotify_fd_, dir_watch);
    }
    
    return fs::exists(eve_path_);
}

void EveParser::watch_loop() {
    // 等待文件创建
    if (!fs::exists(eve_path_)) {
        if (!wait_for_file(120)) {  // 等待最多2分钟
            LOG_ERROR("eve.json not created within timeout");
            return;
        }
    }
    
    LOG_INFO("eve.json found, starting to parse...");
    
    // 添加文件监听
    watch_fd_ = inotify_add_watch(inotify_fd_, eve_path_.c_str(), 
                                   IN_MODIFY | IN_CREATE | IN_MOVED_TO);
    if (watch_fd_ < 0) {
        LOG_ERROR("Failed to add watch for {}: {}", eve_path_, strerror(errno));
        return;
    }
    
    // 定位到文件末尾（跳过旧日志）
    {
        std::ifstream file(eve_path_);
        if (file) {
            file.seekg(0, std::ios::end);
            file_pos_ = file.tellg();
            LOG_INFO("Positioned at byte {} in eve.json", static_cast<long>(file_pos_));
        }
    }
    
    char event_buf[EVENT_BUF_SIZE];
    
    while (running_) {
        // 轮询事件
        pollfd pfd{inotify_fd_, POLLIN, 0};
        int ret = poll(&pfd, 1, 500);  // 500ms超时
        
        if (ret < 0) {
            if (errno != EINTR) {
                LOG_ERROR("Poll error: {}", strerror(errno));
            }
            continue;
        }
        
        bool should_read = false;
        
        if (ret > 0 && (pfd.revents & POLLIN)) {
            // 读取inotify事件
            ssize_t len = read(inotify_fd_, event_buf, EVENT_BUF_SIZE);
            if (len > 0) {
                should_read = true;
            }
        }
        
        // 即使没有inotify事件，也定期检查文件（防止遗漏）
        static auto last_check = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_check).count() >= 1) {
            should_read = true;
            last_check = now;
        }
        
        if (!should_read) {
            continue;
        }
        
        // 检查文件是否存在
        if (!fs::exists(eve_path_)) {
            LOG_WARN("eve.json disappeared, waiting for recreation...");
            file_pos_ = 0;
            
            // 重新添加目录监听
            if (watch_fd_ >= 0) {
                inotify_rm_watch(inotify_fd_, watch_fd_);
                watch_fd_ = -1;
            }
            
            if (wait_for_file(60)) {
                watch_fd_ = inotify_add_watch(inotify_fd_, eve_path_.c_str(), 
                                               IN_MODIFY | IN_CREATE);
                LOG_INFO("eve.json recreated, resuming parsing");
            }
            continue;
        }
        
        // 读取新内容
        std::ifstream file(eve_path_);
        if (!file) {
            continue;
        }
        
        // 检查文件大小
        file.seekg(0, std::ios::end);
        std::streampos file_size = file.tellg();
        
        // 如果文件变小了（被截断），从头开始
        if (file_size < file_pos_) {
            LOG_INFO("eve.json was truncated, restarting from beginning");
            file_pos_ = 0;
        }
        
        if (file_size == file_pos_) {
            continue;  // 没有新内容
        }
        
        // 定位到上次读取的位置
        file.seekg(file_pos_);
        
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                process_line(line);
            }
        }
        
        // 更新位置
        file.clear();  // 清除EOF标志
        file_pos_ = file.tellg();
    }
}

void EveParser::process_line(const std::string& line) {
    try {
        json event = json::parse(line);
        
        // 只处理 alert 类型的事件
        if (event.contains("event_type") && event["event_type"] == "alert") {
            alert_count_++;
            
            if (alert_callback_) {
                alert_callback_(event);
            }
            
            // 每1000条告警输出一次统计
            if (alert_count_ % 1000 == 0) {
                LOG_INFO("Processed {} alerts", alert_count_.load());
            }
        }
    } catch (const json::exception& e) {
        // 忽略解析错误（可能是不完整的行）
        LOG_DEBUG("Failed to parse eve.json line: {}", e.what());
    }
}
