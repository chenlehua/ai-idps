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

    // ========== Pull 模式 API ==========

    // 检查规则版本 (GET /api/v1/probe/rules/version)
    json check_rule_version(const std::string& probe_id, const std::string& current_version);

    // 下载规则内容 (GET /api/v1/probe/rules/download)
    json download_rules_pull(const std::string& probe_id, const std::string& version = "");

    // 轮询攻击任务 (GET /api/v1/attacks/tasks)
    json poll_attack_tasks(const std::string& probe_id, int limit = 10);

    // 标记任务开始 (POST /api/v1/attacks/tasks/{task_id}/start)
    json start_attack_task(const std::string& task_id);

    // 上报任务结果 (POST /api/v1/attacks/tasks/{task_id}/result)
    json report_task_result(const std::string& task_id, bool success,
                           const json& data = nullptr, const std::string& error = "",
                           int response_time_ms = 0);

private:
    std::string base_url_;

    std::string http_post(const std::string& url, const std::string& body);
    std::string http_get(const std::string& url);
};
