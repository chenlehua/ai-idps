#pragma once

#include <string>
#include <functional>
#include <vector>
#include <atomic>
#include <mutex>
#include <optional>
#include "json.hpp"

using json = nlohmann::json;

/**
 * Socket客户端 - 与Probe Manager通信
 * 使用长度前缀 + JSON协议
 */
class SocketClient {
public:
    using MessageCallback = std::function<void(const json&)>;
    
    SocketClient(const std::string& host, int port);
    ~SocketClient();
    
    // 连接到Manager
    bool connect();
    
    // 断开连接
    void disconnect();
    
    // 是否已连接
    bool is_connected() const { return connected_; }
    
    // 发送消息
    bool send(const json& msg);
    
    // 轮询接收消息(非阻塞)
    void poll();
    
    // 设置消息回调
    void set_message_callback(MessageCallback cb) { message_callback_ = cb; }
    
    // 获取文件描述符
    int fd() const { return sock_fd_; }
    
private:
    // 读取一条完整消息
    std::optional<json> read_message();
    
    // 尝试重连
    bool try_reconnect();
    
private:
    std::string host_;
    int port_;
    int sock_fd_;
    std::atomic<bool> connected_;
    
    // 接收缓冲区
    std::vector<uint8_t> recv_buffer_;
    
    MessageCallback message_callback_;
    std::mutex send_mutex_;
    
    // 重连相关
    int reconnect_attempts_;
    static constexpr int MAX_RECONNECT_ATTEMPTS = 10;
    static constexpr int RECONNECT_INTERVAL_MS = 5000;
};
