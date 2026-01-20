#pragma once

#include "attack_generator.h"
#include <string>
#include <map>

/**
 * HTTP attack generator
 * Generates HTTP requests based on rule analysis
 */
class HTTPGenerator : public AttackGenerator {
public:
    HTTPGenerator();

    // Generate HTTP request string
    std::string generate(const json& payload) override;

    std::string type_name() const override { return "http"; }

    // Generate GET request
    std::string generate_get_request(
        const std::string& host,
        const std::string& path,
        const std::map<std::string, std::string>& headers,
        const std::map<std::string, std::string>& params = {}
    );

    // Generate POST request
    std::string generate_post_request(
        const std::string& host,
        const std::string& path,
        const std::string& body,
        const std::string& content_type,
        const std::map<std::string, std::string>& headers = {}
    );

private:
    std::string build_request_line(const std::string& method, const std::string& path);
    std::string build_headers(const std::map<std::string, std::string>& headers);
    std::string url_encode(const std::string& value);
    std::string build_query_string(const std::map<std::string, std::string>& params);
};
