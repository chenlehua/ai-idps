#include "probe_connection.h"
#include "protocol.h"
#include "logger.h"

#include <unistd.h>
#include <sys/socket.h>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>

ProbeConnection::ProbeConnection(int fd)
    : fd_(fd)
    , closed_(false) {
}

ProbeConnection::~ProbeConnection() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

std::optional<json> ProbeConnection::read_message() {
    if (closed_) {
        return std::nullopt;
    }

    // 读取数据到缓冲区
    uint8_t buf[4096];
    while (true) {
        ssize_t n = recv(fd_, buf, sizeof(buf), 0);
        if (n > 0) {
            read_buffer_.insert(read_buffer_.end(), buf, buf + n);
        } else if (n == 0) {
            // 连接关闭
            closed_ = true;
            return std::nullopt;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // 没有更多数据
            } else if (errno == EINTR) {
                continue;  // 被信号中断，重试
            } else {
                LOG_ERROR("recv error on fd=", fd_, ": ", strerror(errno));
                closed_ = true;
                return std::nullopt;
            }
        }
    }

    // 检查是否有完整的消息
    // 消息格式: 4字节长度(网络字节序) + JSON payload
    if (read_buffer_.size() < protocol::HEADER_SIZE) {
        return std::nullopt;
    }

    // 读取消息长度
    uint32_t msg_len;
    memcpy(&msg_len, read_buffer_.data(), sizeof(msg_len));
    msg_len = ntohl(msg_len);

    // 检查消息长度是否合理
    if (msg_len > 10 * 1024 * 1024) {  // 最大 10MB
        LOG_ERROR("Message too large: ", msg_len, " bytes");
        closed_ = true;
        return std::nullopt;
    }

    // 检查是否有完整的消息
    size_t total_len = protocol::HEADER_SIZE + msg_len;
    if (read_buffer_.size() < total_len) {
        return std::nullopt;
    }

    // 解析 JSON
    try {
        std::string json_str(
            read_buffer_.begin() + protocol::HEADER_SIZE,
            read_buffer_.begin() + total_len
        );
        
        // 移除已处理的数据
        read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + total_len);

        return json::parse(json_str);
    } catch (const json::exception& e) {
        LOG_ERROR("JSON parse error: ", e.what());
        // 移除已处理的数据
        read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + total_len);
        return std::nullopt;
    } catch (const std::exception& e) {
        LOG_ERROR("Error parsing message: ", e.what());
        // 移除已处理的数据
        read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + total_len);
        return std::nullopt;
    }
}

void ProbeConnection::send_message(const json& msg) {
    if (closed_ || fd_ < 0) {
        return;
    }

    try {
        std::string payload = msg.dump();
        uint32_t len = htonl(static_cast<uint32_t>(payload.size()));

        // 构造消息：4字节长度 + JSON payload
        std::vector<uint8_t> data;
        data.resize(protocol::HEADER_SIZE + payload.size());
        memcpy(data.data(), &len, sizeof(len));
        memcpy(data.data() + protocol::HEADER_SIZE, payload.data(), payload.size());

        // 将数据追加到写缓冲区
        write_buffer_.insert(write_buffer_.end(), data.begin(), data.end());

        // 尝试立即发送
        flush_write_buffer();
    } catch (const std::exception& e) {
        LOG_ERROR("send_message error: ", e.what());
    }
}

bool ProbeConnection::flush_write_buffer() {
    if (closed_ || fd_ < 0 || write_buffer_.empty()) {
        return false;
    }

    while (!write_buffer_.empty()) {
        ssize_t n = send(fd_, write_buffer_.data(), write_buffer_.size(), MSG_NOSIGNAL);
        if (n > 0) {
            // 移除已发送的数据
            write_buffer_.erase(write_buffer_.begin(), write_buffer_.begin() + n);
        } else if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 发送缓冲区已满，等待 EPOLLOUT 事件
                return true;  // 还有待发送数据
            } else if (errno == EINTR) {
                continue;  // 被信号中断，重试
            } else {
                LOG_ERROR("send error on fd=", fd_, ": ", strerror(errno));
                closed_ = true;
                return false;
            }
        } else {
            // n == 0，不应该发生
            break;
        }
    }

    return !write_buffer_.empty();
}
