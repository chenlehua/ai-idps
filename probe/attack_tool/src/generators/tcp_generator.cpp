#include "generators/tcp_generator.h"
#include <sstream>
#include <algorithm>
#include <cctype>

TCPGenerator::TCPGenerator() {
}

std::string TCPGenerator::generate(const json& payload) {
    // Check for different payload types
    if (payload.contains("content")) {
        std::string content = payload["content"].get<std::string>();
        int offset = payload.value("offset", 0);
        int depth = payload.value("depth", 0);
        return generate_content_payload(content, offset, depth);
    }

    if (payload.contains("hex")) {
        return generate_hex_payload(payload["hex"].get<std::string>());
    }

    if (payload.contains("raw")) {
        // Raw bytes from JSON array
        std::vector<uint8_t> raw;
        for (const auto& b : payload["raw"]) {
            raw.push_back(static_cast<uint8_t>(b.get<int>()));
        }
        return generate_raw_payload(raw);
    }

    // Default: empty payload
    return "";
}

std::string TCPGenerator::generate_raw_payload(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

std::string TCPGenerator::generate_content_payload(
    const std::string& content,
    int offset,
    int depth
) {
    std::string result;

    // Add padding before content if offset specified
    if (offset > 0) {
        result.append(offset, 'X');
    }

    // Add the actual content
    result += content;

    // If depth is specified and we need more data, pad after
    if (depth > 0 && static_cast<int>(result.size()) < depth) {
        result.append(depth - result.size(), 'Y');
    }

    return result;
}

std::string TCPGenerator::generate_hex_payload(const std::string& hex_content) {
    auto bytes = hex_to_bytes(hex_content);
    return generate_raw_payload(bytes);
}

std::vector<uint8_t> TCPGenerator::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    // Remove spaces and pipes from hex string
    std::string clean_hex;
    for (char c : hex) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            clean_hex += c;
        }
    }

    // Convert pairs of hex digits to bytes
    for (size_t i = 0; i + 1 < clean_hex.size(); i += 2) {
        std::string byte_str = clean_hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}
