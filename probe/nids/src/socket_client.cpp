#include "socket_client.h"
#include "protocol.h"
#include "logger.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <poll.h>

SocketClient::SocketClient(const std::string& host, int port)
    : host_(host)
    , port_(port)
    , sock_fd_(-1)
    , connected_(false)
    , reconnect_attempts_(0)
{
    recv_buffer_.reserve(65536);
}

SocketClient::~SocketClient() {
    disconnect();
}

bool SocketClient::connect() {
    if (connected_) {
        return true;
    }
    
    sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd_ < 0) {
        LOG_ERROR("Failed to create socket: {}", strerror(errno));
        return false;
    }
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    
    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
        LOG_ERROR("Invalid address: {}", host_);
        close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }
    
    if (::connect(sock_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("Failed to connect to {}:{}: {}", host_, port_, strerror(errno));
        close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }
    
    // 设置非阻塞模式
    int flags = fcntl(sock_fd_, F_GETFL, 0);
    fcntl(sock_fd_, F_SETFL, flags | O_NONBLOCK);
    
    connected_ = true;
    reconnect_attempts_ = 0;
    LOG_INFO("Connected to Manager at {}:{}", host_, port_);
    
    return true;
}

void SocketClient::disconnect() {
    if (sock_fd_ >= 0) {
        close(sock_fd_);
        sock_fd_ = -1;
    }
    connected_ = false;
    recv_buffer_.clear();
}

bool SocketClient::send(const json& msg) {
    if (!connected_) {
        LOG_WARN("Cannot send: not connected");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(send_mutex_);
    
    try {
        auto data = protocol::serialize(msg);
        
        size_t total_sent = 0;
        while (total_sent < data.size()) {
            ssize_t sent = ::send(sock_fd_, data.data() + total_sent, 
                                  data.size() - total_sent, MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // 等待可写
                    pollfd pfd{sock_fd_, POLLOUT, 0};
                    ::poll(&pfd, 1, 1000);
                    continue;
                }
                LOG_ERROR("Send failed: {}", strerror(errno));
                disconnect();
                return false;
            }
            total_sent += sent;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to serialize message: {}", e.what());
        return false;
    }
}

void SocketClient::poll() {
    if (!connected_) {
        // 尝试重连
        try_reconnect();
        return;
    }
    
    // 检查是否有数据可读
    pollfd pfd{sock_fd_, POLLIN, 0};
    int ret = ::poll(&pfd, 1, 0);
    
    if (ret < 0) {
        if (errno != EINTR) {
            LOG_ERROR("Poll error: {}", strerror(errno));
            disconnect();
        }
        return;
    }
    
    if (ret == 0) {
        return;  // 没有数据
    }
    
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        LOG_WARN("Connection closed by Manager");
        disconnect();
        return;
    }
    
    if (pfd.revents & POLLIN) {
        // 读取数据到缓冲区
        uint8_t buf[4096];
        ssize_t n = recv(sock_fd_, buf, sizeof(buf), 0);
        
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_ERROR("Recv error: {}", strerror(errno));
                disconnect();
            }
            return;
        }
        
        if (n == 0) {
            LOG_WARN("Connection closed by Manager");
            disconnect();
            return;
        }
        
        recv_buffer_.insert(recv_buffer_.end(), buf, buf + n);
        
        // 尝试解析消息
        while (true) {
            auto msg = read_message();
            if (!msg.has_value()) {
                break;
            }
            
            if (message_callback_) {
                try {
                    message_callback_(msg.value());
                } catch (const std::exception& e) {
                    LOG_ERROR("Message callback error: {}", e.what());
                }
            }
        }
    }
}

std::optional<json> SocketClient::read_message() {
    if (recv_buffer_.size() < protocol::HEADER_SIZE) {
        return std::nullopt;
    }
    
    // 读取消息长度
    uint32_t length;
    memcpy(&length, recv_buffer_.data(), sizeof(length));
    length = ntohl(length);
    
    if (length > 10 * 1024 * 1024) {  // 10MB 最大消息大小
        LOG_ERROR("Message too large: {} bytes", length);
        disconnect();
        return std::nullopt;
    }
    
    if (recv_buffer_.size() < protocol::HEADER_SIZE + length) {
        return std::nullopt;  // 消息不完整
    }
    
    // 解析消息
    try {
        auto msg = protocol::deserialize(
            recv_buffer_.data() + protocol::HEADER_SIZE, length);
        
        // 移除已处理的数据
        recv_buffer_.erase(recv_buffer_.begin(), 
                          recv_buffer_.begin() + protocol::HEADER_SIZE + length);
        
        return msg;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to parse message: {}", e.what());
        // 清空缓冲区，防止持续解析失败
        recv_buffer_.clear();
        return std::nullopt;
    }
}

bool SocketClient::try_reconnect() {
    if (connected_) {
        return true;
    }
    
    if (reconnect_attempts_ >= MAX_RECONNECT_ATTEMPTS) {
        // 重置计数，允许继续尝试
        static auto last_reset = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_reset).count() > 60) {
            reconnect_attempts_ = 0;
            last_reset = now;
        } else {
            return false;
        }
    }
    
    // 指数退避
    static auto last_attempt = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    int wait_time = RECONNECT_INTERVAL_MS * (1 << std::min(reconnect_attempts_, 5));
    
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_attempt).count() < wait_time) {
        return false;
    }
    
    last_attempt = now;
    reconnect_attempts_++;
    
    LOG_INFO("Reconnecting to Manager (attempt {}/{})", 
             reconnect_attempts_, MAX_RECONNECT_ATTEMPTS);
    
    return connect();
}
