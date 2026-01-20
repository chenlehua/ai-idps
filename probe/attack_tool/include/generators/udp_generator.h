#pragma once

#include "attack_generator.h"
#include <string>
#include <vector>

/**
 * UDP attack generator
 * Generates UDP payloads for triggering detection rules
 */
class UDPGenerator : public AttackGenerator {
public:
    UDPGenerator();

    // Generate UDP payload
    std::string generate(const json& payload) override;

    std::string type_name() const override { return "udp"; }

    // Generate raw data payload
    std::string generate_raw_payload(const std::vector<uint8_t>& data);

    // Generate DNS-like payload
    std::string generate_dns_payload(
        const std::string& domain,
        uint16_t query_type = 1  // A record
    );

    // Generate payload with content
    std::string generate_content_payload(const std::string& content);

private:
    std::vector<uint8_t> hex_to_bytes(const std::string& hex);
};
