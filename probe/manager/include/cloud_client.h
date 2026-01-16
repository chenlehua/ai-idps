#pragma once

#include <string>
#include <vector>
#include "json.hpp"

using json = nlohmann::json;

class CloudClient {
public:
    explicit CloudClient(const std::string& base_url);

    json send_request(int cmd, const json& data);

    json register_probe(const std::string& probe_id, const std::string& name,
                        const std::string& ip, const std::vector<std::string>& types);

    json heartbeat(const std::string& probe_id, const std::string& rule_version,
                   const json& status, const json& probes);

    json download_rules(const std::string& probe_id, const std::string& version);

    json upload_logs(const std::string& probe_id, const std::vector<json>& logs);

private:
    std::string base_url_;

    std::string http_post(const std::string& url, const std::string& body);
};
