#include "epoll_server.h"
#include "logger.h"

#include <chrono>
#include <thread>

EpollServer::EpollServer(int port)
    : port_(port)
    , running_(false)
    , timer_interval_ms_(0) {
}

EpollServer::~EpollServer() {
    stop();
}

void EpollServer::run() {
    running_ = true;
    LOG_INFO("Epoll server placeholder started on port ", port_);

    auto last_tick = std::chrono::steady_clock::now();
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (timer_callback_ && timer_interval_ms_ > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_tick);
            if (elapsed.count() >= timer_interval_ms_) {
                last_tick = now;
                timer_callback_();
            }
        }
    }
}

void EpollServer::stop() {
    running_ = false;
}

void EpollServer::send_to_probe(int fd, const json& msg) {
    (void)fd;
    (void)msg;
    LOG_DEBUG("send_to_probe placeholder invoked");
}

void EpollServer::add_timer(int interval_ms, std::function<void()> callback) {
    timer_interval_ms_ = interval_ms;
    timer_callback_ = std::move(callback);
}
