#include "config.h"
#include "cloud_client.h"
#include "epoll_server.h"
#include "log_aggregator.h"
#include "logger.h"
#include "rule_manager.h"

#include <signal.h>

static EpollServer* g_server = nullptr;

void signal_handler(int sig) {
    (void)sig;
    if (g_server) {
        g_server->stop();
    }
}

int main(int argc, char* argv[]) {
    Config config;
    config.load(argc > 1 ? argv[1] : "/etc/probe-manager/config.json");

    CloudClient cloud(config.cloud_url);
    RuleManager rules(config.rules_dir);
    LogAggregator logs(config.log_batch_size, config.log_flush_interval * 1000);

    EpollServer server(config.listen_port);
    g_server = &server;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    server.add_timer(config.heartbeat_interval * 1000, [&]() {
        (void)cloud;
        (void)rules;
        (void)logs;
        LOG_DEBUG("Heartbeat placeholder executed");
    });

    LOG_INFO("Probe Manager starting on port ", config.listen_port);
    server.run();
    LOG_INFO("Probe Manager stopped");
    return 0;
}
