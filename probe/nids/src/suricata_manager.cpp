#include "suricata_manager.h"
#include "logger.h"

#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <cstring>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

SuricataManager::SuricataManager(const std::string& config_path,
                                 const std::string& interface,
                                 const std::string& rules_path,
                                 const std::string& log_dir)
    : config_path_(config_path)
    , interface_(interface)
    , rules_path_(rules_path)
    , log_dir_(log_dir)
    , pid_(-1)
{
    eve_log_path_ = log_dir_ + "/eve.json";
    pid_file_ = "/var/run/suricata-" + interface_ + ".pid";
    
    ensure_directories();
}

SuricataManager::~SuricataManager() {
    stop();
}

void SuricataManager::ensure_directories() {
    try {
        // 创建日志目录
        if (!fs::exists(log_dir_)) {
            fs::create_directories(log_dir_);
            LOG_INFO("Created log directory: {}", log_dir_);
        }
        
        // 创建PID目录
        std::string pid_dir = fs::path(pid_file_).parent_path();
        if (!fs::exists(pid_dir)) {
            fs::create_directories(pid_dir);
        }
    } catch (const std::exception& e) {
        LOG_WARN("Failed to create directories: {}", e.what());
    }
}

bool SuricataManager::start() {
    // 检查是否已在运行
    if (is_running()) {
        LOG_WARN("Suricata is already running (PID {})", pid_.load());
        return true;
    }
    
    // 检查配置文件
    if (!fs::exists(config_path_)) {
        LOG_ERROR("Suricata config file not found: {}", config_path_);
        return false;
    }
    
    // 删除旧的eve.json，从头开始
    if (fs::exists(eve_log_path_)) {
        try {
            fs::remove(eve_log_path_);
            LOG_INFO("Removed old eve.json");
        } catch (const std::exception& e) {
            LOG_WARN("Failed to remove old eve.json: {}", e.what());
        }
    }
    
    pid_t child = fork();
    
    if (child < 0) {
        LOG_ERROR("Failed to fork: {}", strerror(errno));
        return false;
    }
    
    if (child == 0) {
        // 子进程: 执行 Suricata
        
        // 构建命令行参数
        std::vector<const char*> args;
        args.push_back("suricata");
        args.push_back("-c");
        args.push_back(config_path_.c_str());
        args.push_back("-i");
        args.push_back(interface_.c_str());
        args.push_back("--pidfile");
        args.push_back(pid_file_.c_str());
        args.push_back("-l");
        args.push_back(log_dir_.c_str());
        
        // 如果指定了规则文件，使用 -S 参数
        if (!rules_path_.empty() && fs::exists(rules_path_)) {
            args.push_back("-S");
            args.push_back(rules_path_.c_str());
        }
        
        // 不使用守护进程模式，便于管理
        // args.push_back("-D");
        
        args.push_back(nullptr);
        
        // 重定向输出
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        
        execvp("suricata", const_cast<char**>(args.data()));
        
        // execvp 失败
        // 使用 _exit 而不是 exit，避免调用 atexit 处理器
        _exit(127);
    }
    
    // 父进程
    pid_ = child;
    LOG_INFO("Started Suricata with PID {} on interface {}", child, interface_);
    
    // 等待一段时间，确保进程启动
    usleep(500000);  // 0.5秒
    
    // 检查进程是否仍在运行
    if (!is_running()) {
        LOG_ERROR("Suricata process exited immediately");
        pid_ = -1;
        return false;
    }
    
    LOG_INFO("Suricata is running, eve.json path: {}", eve_log_path_);
    return true;
}

void SuricataManager::stop() {
    pid_t current_pid = pid_.load();
    if (current_pid <= 0) {
        return;
    }
    
    if (!is_running()) {
        pid_ = -1;
        return;
    }
    
    LOG_INFO("Stopping Suricata (PID {})...", current_pid);
    
    // 发送 SIGTERM
    if (kill(current_pid, SIGTERM) == 0) {
        // 等待进程退出（最多10秒）
        for (int i = 0; i < 100; i++) {
            if (!is_running()) {
                LOG_INFO("Suricata stopped gracefully");
                break;
            }
            usleep(100000);  // 100ms
        }
        
        // 如果还在运行，强制杀死
        if (is_running()) {
            LOG_WARN("Suricata did not stop gracefully, sending SIGKILL");
            kill(current_pid, SIGKILL);
            usleep(500000);
        }
    }
    
    // 等待子进程，避免僵尸进程
    int status;
    waitpid(current_pid, &status, WNOHANG);
    
    pid_ = -1;
    
    // 删除PID文件
    if (fs::exists(pid_file_)) {
        try {
            fs::remove(pid_file_);
        } catch (...) {}
    }
    
    LOG_INFO("Suricata stopped");
}

bool SuricataManager::reload_rules() {
    pid_t current_pid = pid_.load();
    
    if (!is_running()) {
        LOG_ERROR("Cannot reload rules: Suricata is not running");
        return false;
    }
    
    LOG_INFO("Reloading Suricata rules (PID {})...", current_pid);
    
    if (kill(current_pid, SIGUSR2) == 0) {
        LOG_INFO("Sent SIGUSR2 to Suricata for rule reload");
        return true;
    }
    
    LOG_ERROR("Failed to send SIGUSR2: {}", strerror(errno));
    return false;
}

bool SuricataManager::is_running() const {
    pid_t current_pid = pid_.load();
    if (current_pid <= 0) {
        return false;
    }
    
    // 检查进程是否存在
    if (kill(current_pid, 0) == 0) {
        return true;
    }
    
    // 进程不存在
    return false;
}

int SuricataManager::wait() {
    pid_t current_pid = pid_.load();
    if (current_pid <= 0) {
        return -1;
    }
    
    int status;
    pid_t result = waitpid(current_pid, &status, 0);
    
    if (result > 0) {
        pid_ = -1;
        
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        }
    }
    
    return -1;
}

pid_t SuricataManager::read_pid_file() {
    if (!fs::exists(pid_file_)) {
        return -1;
    }
    
    std::ifstream file(pid_file_);
    if (!file) {
        return -1;
    }
    
    pid_t pid;
    file >> pid;
    
    return pid;
}
