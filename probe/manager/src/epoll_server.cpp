#include "epoll_server.h"
#include "probe_connection.h"
#include "protocol.h"
#include "logger.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <stdexcept>

constexpr int MAX_EVENTS = 64;

EpollServer::EpollServer(int port)
    : port_(port)
    , epoll_fd_(-1)
    , listen_fd_(-1)
    , timer_fd_(-1)
    , running_(false) {
    
    // 创建 epoll 实例
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        throw std::runtime_error("Failed to create epoll: " + std::string(strerror(errno)));
    }

    // 创建监听 socket
    listen_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listen_fd_ < 0) {
        close(epoll_fd_);
        throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
    }

    // 设置 SO_REUSEADDR
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 绑定地址
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listen_fd_);
        close(epoll_fd_);
        throw std::runtime_error("Failed to bind port " + std::to_string(port) + ": " + std::string(strerror(errno)));
    }

    // 开始监听
    if (listen(listen_fd_, SOMAXCONN) < 0) {
        close(listen_fd_);
        close(epoll_fd_);
        throw std::runtime_error("Failed to listen: " + std::string(strerror(errno)));
    }

    // 将监听 socket 加入 epoll
    add_to_epoll(listen_fd_, EPOLLIN);

    LOG_INFO("EpollServer listening on port ", port);
}

EpollServer::~EpollServer() {
    stop();
    
    // 关闭所有连接
    connections_.clear();
    
    if (timer_fd_ > 0) {
        close(timer_fd_);
    }
    if (listen_fd_ > 0) {
        close(listen_fd_);
    }
    if (epoll_fd_ > 0) {
        close(epoll_fd_);
    }
}

void EpollServer::add_timer(int interval_ms, std::function<void()> callback) {
    timer_callback_ = std::move(callback);

    timer_fd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd_ < 0) {
        LOG_ERROR("Failed to create timer: ", strerror(errno));
        return;
    }

    itimerspec spec{};
    spec.it_interval.tv_sec = interval_ms / 1000;
    spec.it_interval.tv_nsec = (interval_ms % 1000) * 1000000L;
    spec.it_value = spec.it_interval;

    if (timerfd_settime(timer_fd_, 0, &spec, nullptr) < 0) {
        LOG_ERROR("Failed to set timer: ", strerror(errno));
        close(timer_fd_);
        timer_fd_ = -1;
        return;
    }

    add_to_epoll(timer_fd_, EPOLLIN);
    LOG_INFO("Timer set with interval ", interval_ms, "ms");
}

void EpollServer::run() {
    running_ = true;
    epoll_event events[MAX_EVENTS];

    LOG_INFO("EpollServer event loop started");

    while (running_) {
        int n = epoll_wait(epoll_fd_, events, MAX_EVENTS, 1000);  // 1秒超时

        if (n < 0) {
            if (errno == EINTR) {
                continue;  // 被信号中断，继续
            }
            LOG_ERROR("epoll_wait failed: ", strerror(errno));
            break;
        }

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;

            if (fd == listen_fd_) {
                handle_accept();
            } else if (fd == timer_fd_) {
                handle_timer();
            } else if (ev & (EPOLLERR | EPOLLHUP)) {
                // 连接错误或关闭
                LOG_INFO("Connection error/hangup on fd=", fd);
                if (disconnect_callback_) {
                    disconnect_callback_(fd);
                }
                remove_from_epoll(fd);
                connections_.erase(fd);
            } else {
                // 先处理可写事件
                if (ev & EPOLLOUT) {
                    handle_write(fd);
                }
                // 再处理可读事件
                if (ev & EPOLLIN) {
                    handle_read(fd);
                }
            }
        }
    }

    LOG_INFO("EpollServer event loop stopped");
}

void EpollServer::stop() {
    running_ = false;
}

void EpollServer::handle_accept() {
    while (true) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);

        int fd = accept4(listen_fd_, (sockaddr*)&client_addr, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // 没有更多连接
            }
            LOG_ERROR("accept failed: ", strerror(errno));
            break;
        }

        // 获取客户端地址
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
        int port = ntohs(client_addr.sin_port);

        LOG_INFO("New probe connection: fd=", fd, " from ", ip_str, ":", port);

        // 创建连接对象
        connections_[fd] = std::make_unique<ProbeConnection>(fd);

        // 加入 epoll（使用边缘触发）
        add_to_epoll(fd, EPOLLIN | EPOLLET);

        if (connect_callback_) {
            connect_callback_(fd);
        }
    }
}

void EpollServer::handle_read(int fd) {
    auto it = connections_.find(fd);
    if (it == connections_.end()) {
        return;
    }

    auto& conn = it->second;

    while (true) {
        try {
            auto msg = conn->read_message();
            if (!msg.has_value()) {
                if (conn->is_closed()) {
                    LOG_INFO("Probe disconnected: fd=", fd);
                    if (disconnect_callback_) {
                        disconnect_callback_(fd);
                    }
                    remove_from_epoll(fd);
                    connections_.erase(fd);
                }
                break;
            }

            // 处理消息
            if (message_callback_) {
                message_callback_(fd, msg.value());
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Error handling message from fd=", fd, ": ", e.what());
            // 关闭连接
            if (disconnect_callback_) {
                disconnect_callback_(fd);
            }
            remove_from_epoll(fd);
            connections_.erase(fd);
            break;
        }
    }
}

void EpollServer::handle_timer() {
    // 读取定时器数据（必须读取以清除事件）
    uint64_t exp;
    ssize_t s = read(timer_fd_, &exp, sizeof(exp));
    (void)s;

    if (timer_callback_) {
        timer_callback_();
    }
}

void EpollServer::handle_write(int fd) {
    auto it = connections_.find(fd);
    if (it == connections_.end()) {
        return;
    }

    auto& conn = it->second;

    // 尝试发送缓冲区中的数据
    bool has_pending = conn->flush_write_buffer();

    if (conn->is_closed()) {
        LOG_INFO("Connection closed during write: fd=", fd);
        if (disconnect_callback_) {
            disconnect_callback_(fd);
        }
        remove_from_epoll(fd);
        connections_.erase(fd);
        return;
    }

    // 更新 epoll 事件
    update_write_interest(fd);
}

void EpollServer::send_to_probe(int fd, const json& msg) {
    auto it = connections_.find(fd);
    if (it != connections_.end()) {
        it->second->send_message(msg);
        // 发送后更新 epoll 事件
        update_write_interest(fd);
    }
}

void EpollServer::broadcast(const json& msg) {
    for (auto& [fd, conn] : connections_) {
        conn->send_message(msg);
    }
    // 更新所有连接的 epoll 事件
    for (auto& [fd, conn] : connections_) {
        update_write_interest(fd);
    }
}

void EpollServer::add_to_epoll(int fd, uint32_t events) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERROR("epoll_ctl ADD failed for fd=", fd, ": ", strerror(errno));
    }
}

void EpollServer::modify_epoll(int fd, uint32_t events) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0) {
        LOG_ERROR("epoll_ctl MOD failed for fd=", fd, ": ", strerror(errno));
    }
}

void EpollServer::remove_from_epoll(int fd) {
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) < 0) {
        // 可能已经被移除，忽略错误
    }
}

void EpollServer::update_write_interest(int fd) {
    auto it = connections_.find(fd);
    if (it == connections_.end()) {
        return;
    }

    auto& conn = it->second;

    // 基础事件：始终监听读事件，使用边缘触发
    uint32_t events = EPOLLIN | EPOLLET;

    // 如果有待发送数据，添加写事件监听
    if (conn->has_pending_write()) {
        events |= EPOLLOUT;
    }

    modify_epoll(fd, events);
}
