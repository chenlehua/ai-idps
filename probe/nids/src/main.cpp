#include "nids_probe.h"
#include "logger.h"

#include <signal.h>
#include <getopt.h>
#include <cstdlib>
#include <cstring>
#include <iostream>

// 全局探针指针，用于信号处理
NidsProbe* g_probe = nullptr;

void signal_handler(int sig) {
    LOG_INFO("Received signal {}", sig);
    if (g_probe) {
        g_probe->stop();
    }
}

void print_usage(const char* prog) {
    std::cout << "NIDS Probe - Network Intrusion Detection System Probe\n";
    std::cout << "\n";
    std::cout << "Usage: " << prog << " [options]\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  -m, --manager <host:port>  Manager address (default: 127.0.0.1:9000)\n";
    std::cout << "  -i, --interface <name>     Network interface to monitor (default: eth0)\n";
    std::cout << "  -c, --config <path>        Suricata config file (default: /etc/suricata/suricata.yaml)\n";
    std::cout << "  -r, --rules <path>         Rules file path (optional)\n";
    std::cout << "  -l, --log-dir <path>       Suricata log directory (default: /var/log/suricata)\n";
    std::cout << "  -p, --probe-id <id>        Probe ID (default: auto-generated)\n";
    std::cout << "  -h, --help                 Show this help message\n";
    std::cout << "  -v, --version              Show version information\n";
    std::cout << "\n";
    std::cout << "Environment variables:\n";
    std::cout << "  MANAGER_HOST               Manager host (default: 127.0.0.1)\n";
    std::cout << "  MANAGER_PORT               Manager port (default: 9000)\n";
    std::cout << "  INTERFACE                  Network interface (default: eth0)\n";
    std::cout << "  SURICATA_CONFIG            Suricata config file\n";
    std::cout << "  RULES_PATH                 Rules file path\n";
    std::cout << "  LOG_DIR                    Log directory\n";
    std::cout << "  PROBE_ID                   Probe ID\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog << " -m 192.168.1.10:9000 -i eth0\n";
    std::cout << "  " << prog << " --manager localhost:9010 --interface ens33\n";
    std::cout << "\n";
}

void print_version() {
    std::cout << "NIDS Probe version 1.0.0\n";
    std::cout << "Part of AI-IDPS project\n";
}

int main(int argc, char* argv[]) {
    // 默认配置
    NidsProbe::Config config;
    
    // 从环境变量读取配置
    if (const char* env = std::getenv("MANAGER_HOST")) {
        config.manager_host = env;
    }
    if (const char* env = std::getenv("MANAGER_PORT")) {
        config.manager_port = std::atoi(env);
    }
    if (const char* env = std::getenv("INTERFACE")) {
        config.interface = env;
    }
    if (const char* env = std::getenv("SURICATA_CONFIG")) {
        config.suricata_config = env;
    }
    if (const char* env = std::getenv("RULES_PATH")) {
        config.rules_path = env;
    }
    if (const char* env = std::getenv("LOG_DIR")) {
        config.log_dir = env;
    }
    if (const char* env = std::getenv("PROBE_ID")) {
        config.probe_id = env;
    }
    
    // 命令行选项
    static struct option long_options[] = {
        {"manager",   required_argument, nullptr, 'm'},
        {"interface", required_argument, nullptr, 'i'},
        {"config",    required_argument, nullptr, 'c'},
        {"rules",     required_argument, nullptr, 'r'},
        {"log-dir",   required_argument, nullptr, 'l'},
        {"probe-id",  required_argument, nullptr, 'p'},
        {"help",      no_argument,       nullptr, 'h'},
        {"version",   no_argument,       nullptr, 'v'},
        {nullptr,     0,                 nullptr, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "m:i:c:r:l:p:hv", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'm': {
                std::string addr = optarg;
                auto pos = addr.find(':');
                if (pos != std::string::npos) {
                    config.manager_host = addr.substr(0, pos);
                    config.manager_port = std::stoi(addr.substr(pos + 1));
                } else {
                    config.manager_host = addr;
                }
                break;
            }
            case 'i':
                config.interface = optarg;
                break;
            case 'c':
                config.suricata_config = optarg;
                break;
            case 'r':
                config.rules_path = optarg;
                break;
            case 'l':
                config.log_dir = optarg;
                break;
            case 'p':
                config.probe_id = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // 打印启动信息
    LOG_INFO("===========================================");
    LOG_INFO("    NIDS Probe - Starting");
    LOG_INFO("===========================================");
    LOG_INFO("Configuration:");
    LOG_INFO("  Manager:      {}:{}", config.manager_host, config.manager_port);
    LOG_INFO("  Interface:    {}", config.interface);
    LOG_INFO("  Suricata:     {}", config.suricata_config);
    if (!config.rules_path.empty()) {
        LOG_INFO("  Rules:        {}", config.rules_path);
    }
    LOG_INFO("  Log dir:      {}", config.log_dir);
    if (!config.probe_id.empty()) {
        LOG_INFO("  Probe ID:     {}", config.probe_id);
    }
    
    // 注册信号处理
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    
    // 忽略SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    
    try {
        NidsProbe probe(config);
        g_probe = &probe;
        
        probe.start();
        
        g_probe = nullptr;
        LOG_INFO("NIDS Probe exited normally");
        
    } catch (const std::exception& e) {
        LOG_ERROR("Fatal error: {}", e.what());
        return 1;
    }
    
    return 0;
}
