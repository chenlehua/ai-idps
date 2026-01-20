#include "generators/udp_generator.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <random>

UDPGenerator::UDPGenerator() {
}

std::string UDPGenerator::generate(const json& payload) {
    // Check for different payload types
    if (payload.contains("domain")) {
        uint16_t query_type = payload.value("query_type", 1);  // A record
        return generate_dns_payload(payload["domain"].get<std::string>(), query_type);
    }

    if (payload.contains("content")) {
        return generate_content_payload(payload["content"].get<std::string>());
    }

    if (payload.contains("hex")) {
        auto bytes = hex_to_bytes(payload["hex"].get<std::string>());
        return generate_raw_payload(bytes);
    }

    if (payload.contains("raw")) {
        std::vector<uint8_t> raw;
        for (const auto& b : payload["raw"]) {
            raw.push_back(static_cast<uint8_t>(b.get<int>()));
        }
        return generate_raw_payload(raw);
    }

    // Default: empty payload
    return "";
}

std::string UDPGenerator::generate_raw_payload(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

std::string UDPGenerator::generate_dns_payload(
    const std::string& domain,
    uint16_t query_type
) {
    std::vector<uint8_t> packet;

    // Generate random transaction ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dis(0, 65535);
    uint16_t transaction_id = dis(gen);

    // DNS header (12 bytes)
    // Transaction ID
    packet.push_back(static_cast<uint8_t>(transaction_id >> 8));
    packet.push_back(static_cast<uint8_t>(transaction_id & 0xFF));

    // Flags: Standard query (0x0100)
    packet.push_back(0x01);
    packet.push_back(0x00);

    // Questions: 1
    packet.push_back(0x00);
    packet.push_back(0x01);

    // Answer RRs: 0
    packet.push_back(0x00);
    packet.push_back(0x00);

    // Authority RRs: 0
    packet.push_back(0x00);
    packet.push_back(0x00);

    // Additional RRs: 0
    packet.push_back(0x00);
    packet.push_back(0x00);

    // Question section
    // Domain name in DNS format (labels)
    std::string current_domain = domain;
    size_t pos;
    while ((pos = current_domain.find('.')) != std::string::npos) {
        std::string label = current_domain.substr(0, pos);
        packet.push_back(static_cast<uint8_t>(label.size()));
        for (char c : label) {
            packet.push_back(static_cast<uint8_t>(c));
        }
        current_domain = current_domain.substr(pos + 1);
    }
    // Last label
    if (!current_domain.empty()) {
        packet.push_back(static_cast<uint8_t>(current_domain.size()));
        for (char c : current_domain) {
            packet.push_back(static_cast<uint8_t>(c));
        }
    }
    // Null terminator
    packet.push_back(0x00);

    // Query type (e.g., A = 1, AAAA = 28, MX = 15, TXT = 16)
    packet.push_back(static_cast<uint8_t>(query_type >> 8));
    packet.push_back(static_cast<uint8_t>(query_type & 0xFF));

    // Query class: IN (Internet) = 1
    packet.push_back(0x00);
    packet.push_back(0x01);

    return std::string(packet.begin(), packet.end());
}

std::string UDPGenerator::generate_content_payload(const std::string& content) {
    return content;
}

std::vector<uint8_t> UDPGenerator::hex_to_bytes(const std::string& hex) {
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
