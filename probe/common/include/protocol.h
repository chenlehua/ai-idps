#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include "json.hpp"

using json = nlohmann::json;

namespace protocol {

struct MessageHeader {
    uint32_t length;
};

constexpr size_t HEADER_SIZE = sizeof(MessageHeader);

enum class Command : int {
    CMD_START = 1,
    CMD_STOP = 2,
    CMD_RELOAD_RULES = 3,
    CMD_GET_STATUS = 4,
    CMD_SHUTDOWN = 5,
    // 攻击测试命令
    CMD_ATTACK_EXECUTE = 10,
    CMD_ATTACK_CANCEL = 11,
    CMD_ATTACK_STATUS = 12
};

enum class Event : int {
    EVT_ALERT = 1,
    EVT_STATUS = 2,
    EVT_ERROR = 3,
    EVT_ACK = 4,
    // 攻击测试事件
    EVT_ATTACK_RESULT = 10,
    EVT_ATTACK_PROGRESS = 11
};

enum class CloudCommand : int {
    LOG_UPLOAD = 10,
    LOG_UPLOAD_RESPONSE = 11,
    HEARTBEAT = 20,
    HEARTBEAT_RESPONSE = 21,
    REGISTER = 30,
    REGISTER_RESPONSE = 31,
    RULE_DOWNLOAD = 40,
    RULE_DOWNLOAD_RESPONSE = 41,
    // Pull 模式: 规则版本检查
    RULE_VERSION_CHECK = 50,
    RULE_VERSION_CHECK_RESPONSE = 51,
    // Pull 模式: 攻击任务
    ATTACK_TASK_POLL = 60,
    ATTACK_TASK_POLL_RESPONSE = 61,
    ATTACK_TASK_START = 62,
    ATTACK_TASK_START_RESPONSE = 63,
    ATTACK_TASK_RESULT = 64,
    ATTACK_TASK_RESULT_RESPONSE = 65
};

std::vector<uint8_t> serialize(const json& msg);
json deserialize(const uint8_t* data, size_t length);

}  // namespace protocol
