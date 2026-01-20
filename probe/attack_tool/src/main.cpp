#include "attack_tool.h"
#include "logger.h"

#include <signal.h>
#include <unistd.h>
#include <cstring>

static AttackTool* g_attack_tool = nullptr;

void signal_handler(int sig) {
    LOG_INFO("Received signal {}, shutting down...", sig);
    if (g_attack_tool) {
        g_attack_tool->stop();
    }
}

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [config_file]" << std::endl;
    std::cout << std::endl;
    std::cout << "AI-IDPS Attack Tool - Executes attack tests for rule validation" << std::endl;
    std::cout << std::endl;
    std::cout << "Arguments:" << std::endl;
    std::cout << "  config_file   Path to configuration file (default: /etc/attack-tool/config.json)" << std::endl;
}

int main(int argc, char* argv[]) {
    // Parse arguments
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    std::string config_path = argc > 1 ? argv[1] : "/etc/attack-tool/config.json";

    LOG_INFO("=== Attack Tool Starting ===");

    // Load configuration
    Config config;
    config.load(config_path);

    // Generate probe ID if not set
    if (config.probe_id.empty()) {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            config.probe_id = std::string("attack-tool-") + hostname;
        } else {
            config.probe_id = "attack-tool-unknown";
        }
    }

    LOG_INFO("Probe ID: {}", config.probe_id);
    LOG_INFO("Manager: {}:{}", config.manager_host, config.manager_port);

    // Create attack tool
    AttackTool tool(config);
    g_attack_tool = &tool;

    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    // Run main loop
    int result = tool.run();

    LOG_INFO("=== Attack Tool Stopped ===");

    return result;
}
