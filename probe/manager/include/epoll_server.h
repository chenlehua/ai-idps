#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include "json.hpp"

using json = nlohmann::json;

class ProbeConnection;

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

    // 广播消息到所有探针
    void broadcast(const json& msg);

    // 获取连接数
    size_t connection_count() const { return connections_.size(); }

private:
    void handle_accept();
    void handle_read(int fd);
    void handle_timer();

    void add_to_epoll(int fd, uint32_t events);
    void remove_from_epoll(int fd);

private:
    int port_;
    int epoll_fd_;
    int listen_fd_;
    int timer_fd_;
    std::atomic<bool> running_;

    std::map<int, std::unique_ptr<ProbeConnection>> connections_;

    MessageCallback message_callback_;
    ConnectionCallback connect_callback_;
    ConnectionCallback disconnect_callback_;
    std::function<void()> timer_callback_;
};
