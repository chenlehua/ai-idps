#pragma once

#include "attack_generator.h"
#include <string>
#include <vector>

/**
 * TCP attack generator
 * Generates raw TCP payloads for triggering detection rules
 */
class TCPGenerator : public AttackGenerator {
public:
    TCPGenerator();

    // Generate TCP payload
    std::string generate(const json& payload) override;

    std::string type_name() const override { return "tcp"; }

    // Generate raw data payload
    std::string generate_raw_payload(const std::vector<uint8_t>& data);

    // Generate payload with specific content patterns
    std::string generate_content_payload(
        const std::string& content,
        int offset = 0,
        int depth = 0
    );

    // Generate payload from hex string
    std::string generate_hex_payload(const std::string& hex_content);

private:
    std::vector<uint8_t> hex_to_bytes(const std::string& hex);
};
