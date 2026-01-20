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
 * Socket client for communication with Probe Manager
 * Uses length-prefix + JSON protocol
 */
class SocketClient {
public:
    using MessageCallback = std::function<void(const json&)>;

    SocketClient(const std::string& host, int port);
    ~SocketClient();

    // Connect to Manager
    bool connect();

    // Disconnect
    void disconnect();

    // Check connection status
    bool is_connected() const { return connected_; }

    // Send message
    bool send(const json& msg);

    // Poll for messages (non-blocking)
    void poll();

    // Set message callback
    void set_message_callback(MessageCallback cb) { message_callback_ = cb; }

    // Get file descriptor
    int fd() const { return sock_fd_; }

private:
    // Read complete message
    std::optional<json> read_message();

    // Try to reconnect
    bool try_reconnect();

private:
    std::string host_;
    int port_;
    int sock_fd_;
    std::atomic<bool> connected_;

    // Receive buffer
    std::vector<uint8_t> recv_buffer_;

    MessageCallback message_callback_;
    std::mutex send_mutex_;

    // Reconnect settings
    int reconnect_attempts_;
    int max_reconnect_attempts_ = 10;
    int reconnect_interval_ms_ = 5000;
};
