#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include <string>
#include "json.hpp"

using json = nlohmann::json;

class ProbeConnection {
public:
    explicit ProbeConnection(int fd);
    ~ProbeConnection();

    // 读取消息，返回解析后的 JSON，如果没有完整消息则返回 nullopt
    std::optional<json> read_message();

    // 发送消息
    void send_message(const json& msg);

    // 检查连接是否已关闭
    bool is_closed() const { return closed_; }

    // 获取文件描述符
    int fd() const { return fd_; }

    // 获取探针信息
    const std::string& probe_id() const { return probe_id_; }
    const std::string& probe_type() const { return probe_type_; }

    // 设置探针信息
    void set_probe_info(const std::string& id, const std::string& type) {
        probe_id_ = id;
        probe_type_ = type;
    }

private:
    int fd_;
    bool closed_;
    std::vector<uint8_t> read_buffer_;
    std::string probe_id_;
    std::string probe_type_;
};
