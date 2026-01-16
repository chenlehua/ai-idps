#pragma once

#include <string>
#include <sys/types.h>
#include <atomic>

/**
 * Suricata进程管理器
 * 负责启动、停止、热更新Suricata进程
 * 通过fork/exec和信号与Suricata通信，确保GPL合规
 */
class SuricataManager {
public:
    SuricataManager(const std::string& config_path, 
                    const std::string& interface,
                    const std::string& rules_path = "",
                    const std::string& log_dir = "/var/log/suricata");
    ~SuricataManager();
    
    // 启动Suricata
    bool start();
    
    // 停止Suricata
    void stop();
    
    // 热更新规则 (SIGUSR2)
    bool reload_rules();
    
    // 检查进程状态
    bool is_running() const;
    
    // 等待进程结束
    int wait();
    
    // 获取PID
    pid_t pid() const { return pid_; }
    
    // 获取eve.json路径
    const std::string& eve_log_path() const { return eve_log_path_; }
    
    // 获取规则文件路径
    const std::string& rules_path() const { return rules_path_; }
    
    // 设置规则文件路径
    void set_rules_path(const std::string& path) { rules_path_ = path; }
    
    // 获取接口名称
    const std::string& interface() const { return interface_; }
    
private:
    // 创建必要的目录
    void ensure_directories();
    
    // 读取PID文件
    pid_t read_pid_file();
    
private:
    std::string config_path_;
    std::string interface_;
    std::string rules_path_;
    std::string log_dir_;
    std::string eve_log_path_;
    std::string pid_file_;
    std::atomic<pid_t> pid_;
};
