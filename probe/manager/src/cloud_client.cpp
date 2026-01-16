#include "cloud_client.h"
#include "logger.h"

#include <curl/curl.h>
#include <sstream>

// 用于接收 libcurl 响应的回调
static size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t total_size = size * nmemb;
    userp->append(static_cast<char*>(contents), total_size);
    return total_size;
}

CloudClient::CloudClient(const std::string& base_url)
    : base_url_(base_url) {
    // 初始化 libcurl（全局初始化应该在程序开始时做一次）
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

std::string CloudClient::http_post(const std::string& url, const std::string& body) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR("Failed to init curl");
        return "";
    }

    std::string response;

    // 设置 URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // 设置 POST 数据
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());

    // 设置请求头
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // 设置响应回调
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // 设置超时
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    // 执行请求
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        LOG_ERROR("curl request failed: ", curl_easy_strerror(res));
        response = "";
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200) {
            LOG_WARN("HTTP response code: ", http_code);
        }
    }

    // 清理
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response;
}

json CloudClient::send_request(int cmd, const json& data) {
    json request;
    request["cmd"] = cmd;
    request["data"] = data;

    std::string body = request.dump();
    LOG_DEBUG("Sending request to cloud: cmd=", cmd);

    // API endpoint: /api/v1/probe
    std::string url = base_url_ + "/api/v1/probe";
    std::string response = http_post(url, body);

    if (response.empty()) {
        json error_response;
        error_response["cmd"] = cmd + 1;
        error_response["data"] = {
            {"status", "error"},
            {"error_code", 1005},
            {"message", "HTTP request failed"}
        };
        return error_response;
    }

    try {
        return json::parse(response);
    } catch (const json::exception& e) {
        LOG_ERROR("Failed to parse response: ", e.what());
        json error_response;
        error_response["cmd"] = cmd + 1;
        error_response["data"] = {
            {"status", "error"},
            {"error_code", 1005},
            {"message", "Invalid JSON response"}
        };
        return error_response;
    }
}

json CloudClient::register_probe(const std::string& probe_id, const std::string& name,
                                 const std::string& ip, const std::vector<std::string>& types) {
    json data;
    data["probe_id"] = probe_id;
    data["name"] = name;
    data["ip"] = ip;
    data["probe_types"] = types;

    LOG_INFO("Registering probe: ", probe_id);
    return send_request(30, data);
}

json CloudClient::heartbeat(const std::string& probe_id, const std::string& rule_version,
                            const json& status, const json& probes) {
    json data;
    data["probe_id"] = probe_id;
    data["rule_version"] = rule_version.empty() ? nullptr : json(rule_version);
    data["status"] = status;
    data["probes"] = probes;

    LOG_DEBUG("Sending heartbeat for probe: ", probe_id);
    return send_request(20, data);
}

json CloudClient::download_rules(const std::string& probe_id, const std::string& version) {
    json data;
    data["probe_id"] = probe_id;
    data["version"] = version;

    LOG_INFO("Downloading rules version: ", version);
    return send_request(40, data);
}

json CloudClient::upload_logs(const std::string& probe_id, const std::vector<json>& logs) {
    json data;
    data["probe_id"] = probe_id;
    data["logs"] = logs;

    LOG_DEBUG("Uploading ", logs.size(), " logs");
    return send_request(10, data);
}
