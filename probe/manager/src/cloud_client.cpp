#include "cloud_client.h"
#include "logger.h"

CloudClient::CloudClient(const std::string& base_url)
    : base_url_(base_url) {
}

json CloudClient::send_request(int cmd, const json& data) {
    (void)data;
    json response;
    response["cmd"] = cmd + 1;

    json payload;
    payload["status"] = "not_implemented";
    payload["message"] = "cloud client pending";
    response["data"] = payload;
    return response;
}

json CloudClient::register_probe(const std::string& probe_id, const std::string& name,
                                 const std::string& ip, const std::vector<std::string>& types) {
    json data;
    data["probe_id"] = probe_id;
    data["name"] = name;
    data["ip"] = ip;
    (void)types;
    return send_request(30, data);
}

json CloudClient::heartbeat(const std::string& probe_id, const std::string& rule_version,
                            const json& status, const json& probes) {
    json data;
    data["probe_id"] = probe_id;
    data["rule_version"] = rule_version;
    data["status"] = status;
    data["probes"] = probes;
    return send_request(20, data);
}

json CloudClient::download_rules(const std::string& probe_id, const std::string& version) {
    json data;
    data["probe_id"] = probe_id;
    data["version"] = version;
    return send_request(40, data);
}

json CloudClient::upload_logs(const std::string& probe_id, const std::vector<json>& logs) {
    json data;
    data["probe_id"] = probe_id;
    (void)logs;
    return send_request(10, data);
}

std::string CloudClient::http_post(const std::string& url, const std::string& body) {
    (void)url;
    (void)body;
    LOG_DEBUG("http_post placeholder invoked");
    return {};
}
