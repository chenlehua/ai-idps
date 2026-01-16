#pragma once

#include <atomic>
#include <functional>
#include "json.hpp"

using json = nlohmann::json;

class EpollServer {
public:
    using MessageCallback = std::function<void(int fd, const json& msg)>;
    using ConnectionCallback = std::function<void(int fd)>;

    explicit EpollServer(int port);
    ~EpollServer();

    void run();
    void stop();

    void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
    void set_connect_callback(ConnectionCallback cb) { connect_callback_ = std::move(cb); }
    void set_disconnect_callback(ConnectionCallback cb) { disconnect_callback_ = std::move(cb); }

    void send_to_probe(int fd, const json& msg);
    void add_timer(int interval_ms, std::function<void()> callback);

private:
    int port_;
    std::atomic<bool> running_;
    int timer_interval_ms_;

    MessageCallback message_callback_;
    ConnectionCallback connect_callback_;
    ConnectionCallback disconnect_callback_;
    std::function<void()> timer_callback_;
};
