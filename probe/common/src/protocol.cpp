#include "protocol.h"

#include <arpa/inet.h>
#include <cstring>

namespace protocol {

std::vector<uint8_t> serialize(const json& msg) {
    std::string payload = msg.dump();
    uint32_t length = static_cast<uint32_t>(payload.size());
    uint32_t net_length = htonl(length);

    std::vector<uint8_t> buffer(HEADER_SIZE + payload.size());
    std::memcpy(buffer.data(), &net_length, HEADER_SIZE);
    std::memcpy(buffer.data() + HEADER_SIZE, payload.data(), payload.size());
    return buffer;
}

json deserialize(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return json();
    }
    std::string payload(reinterpret_cast<const char*>(data), length);
    return json::parse(payload);
}

}  // namespace protocol
