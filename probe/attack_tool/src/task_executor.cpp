#include "task_executor.h"
#include "logger.h"

#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <cstring>

// CURL write callback
static size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total_size = size * nmemb;
    output->append(static_cast<char*>(contents), total_size);
    return total_size;
}

TaskExecutor::TaskExecutor()
    : default_host_("127.0.0.1")
    , default_port_(80)
    , timeout_ms_(30000)
{
    http_generator_ = std::make_unique<HTTPGenerator>();
    tcp_generator_ = std::make_unique<TCPGenerator>();
    udp_generator_ = std::make_unique<UDPGenerator>();

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

TaskExecutor::~TaskExecutor() {
    curl_global_cleanup();
}

AttackResult TaskExecutor::execute(const json& command) {
    AttackResult result;

    auto start_time = std::chrono::steady_clock::now();

    try {
        // Extract task information
        std::string task_id = command.value("task_id", "");
        std::string test_id = command.value("test_id", "");
        std::string attack_type = command.value("attack_type", "http");
        int rule_sid = command.value("rule_sid", 0);

        result.task_id = task_id;
        result.test_id = test_id;
        result.rule_sid = rule_sid;

        // Get payload and target
        json payload = command.value("payload", json::object());
        json target = command.value("target", json::object());

        LOG_INFO("Executing {} attack for task: {}", attack_type, task_id);

        // Execute based on attack type
        if (attack_type == "http") {
            result = execute_http_attack(payload, target);
        } else if (attack_type == "tcp") {
            result = execute_tcp_attack(payload, target);
        } else if (attack_type == "udp") {
            result = execute_udp_attack(payload, target);
        } else {
            result.success = false;
            result.error = "Unknown attack type: " + attack_type;
        }

        // Preserve task info
        result.task_id = task_id;
        result.test_id = test_id;
        result.rule_sid = rule_sid;

    } catch (const std::exception& e) {
        result.success = false;
        result.error = std::string("Exception: ") + e.what();
    }

    // Calculate response time
    auto end_time = std::chrono::steady_clock::now();
    result.response_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time
    ).count();

    return result;
}

void TaskExecutor::cancel(const std::string& task_id) {
    // Currently tasks are synchronous, so cancellation is not implemented
    LOG_WARN("Task cancellation not implemented: {}", task_id);
}

void TaskExecutor::set_default_target(const std::string& host, int port) {
    default_host_ = host;
    default_port_ = port;
}

void TaskExecutor::set_timeout(int timeout_ms) {
    timeout_ms_ = timeout_ms;
}

AttackResult TaskExecutor::execute_http_attack(const json& payload, const json& target) {
    AttackResult result;

    // Get target
    std::string host = target.value("host", default_host_);
    int port = target.value("port", default_port_);
    bool use_ssl = target.value("ssl", port == 443);

    // Get HTTP parameters
    std::string method = payload.value("method", "GET");
    std::string path = payload.value("path", "/");
    std::string body = payload.value("body", "");
    std::string content_type = payload.value("content_type", "text/plain");

    // Build headers map
    std::map<std::string, std::string> headers;
    if (payload.contains("headers") && payload["headers"].is_object()) {
        for (auto& [key, value] : payload["headers"].items()) {
            headers[key] = value.get<std::string>();
        }
    }

    // Ensure Host header
    if (headers.find("Host") == headers.end()) {
        headers["Host"] = host;
    }

    // Build URL
    std::string protocol = use_ssl ? "https" : "http";
    std::string url = protocol + "://" + host;
    if ((use_ssl && port != 443) || (!use_ssl && port != 80)) {
        url += ":" + std::to_string(port);
    }
    url += path;

    LOG_DEBUG("HTTP attack: {} {}", method, url);

    return send_http_request(method, url, headers, body);
}

AttackResult TaskExecutor::execute_tcp_attack(const json& payload, const json& target) {
    // Get target
    std::string host = target.value("host", default_host_);
    int port = target.value("port", default_port_);

    // Generate payload
    std::string data;
    if (payload.contains("content")) {
        data = tcp_generator_->generate_content_payload(
            payload["content"].get<std::string>()
        );
    } else if (payload.contains("hex")) {
        data = tcp_generator_->generate_hex_payload(
            payload["hex"].get<std::string>()
        );
    } else {
        data = tcp_generator_->generate(payload);
    }

    LOG_DEBUG("TCP attack: {}:{} ({} bytes)", host, port, data.size());

    return send_tcp_data(host, port, data);
}

AttackResult TaskExecutor::execute_udp_attack(const json& payload, const json& target) {
    // Get target
    std::string host = target.value("host", default_host_);
    int port = target.value("port", 53);  // Default to DNS port

    // Generate payload
    std::string data;
    if (payload.contains("domain")) {
        data = udp_generator_->generate_dns_payload(
            payload["domain"].get<std::string>()
        );
    } else if (payload.contains("content")) {
        data = udp_generator_->generate_content_payload(
            payload["content"].get<std::string>()
        );
    } else {
        data = udp_generator_->generate(payload);
    }

    LOG_DEBUG("UDP attack: {}:{} ({} bytes)", host, port, data.size());

    return send_udp_data(host, port, data);
}

AttackResult TaskExecutor::send_http_request(
    const std::string& method,
    const std::string& url,
    const std::map<std::string, std::string>& headers,
    const std::string& body
) {
    AttackResult result;

    CURL* curl = curl_easy_init();
    if (!curl) {
        result.success = false;
        result.error = "Failed to initialize CURL";
        return result;
    }

    std::string response_body;
    std::string response_headers;

    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Set method
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
    } else if (method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else if (method == "HEAD") {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }

    // Set headers
    struct curl_slist* header_list = nullptr;
    for (const auto& [key, value] : headers) {
        std::string header = key + ": " + value;
        header_list = curl_slist_append(header_list, header.c_str());
    }
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    // Set callbacks
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response_headers);

    // Set timeouts
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms_));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);

    // Disable SSL verification for testing
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Follow redirects
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

    // Execute request
    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        result.success = true;
        result.data["http_code"] = http_code;
        result.data["response_size"] = response_body.size();

        LOG_DEBUG("HTTP response: {} ({} bytes)", http_code, response_body.size());
    } else {
        result.success = false;
        result.error = curl_easy_strerror(res);
        LOG_WARN("HTTP request failed: {}", result.error);
    }

    // Cleanup
    if (header_list) {
        curl_slist_free_all(header_list);
    }
    curl_easy_cleanup(curl);

    return result;
}

AttackResult TaskExecutor::send_tcp_data(
    const std::string& host,
    int port,
    const std::string& data
) {
    AttackResult result;

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        result.success = false;
        result.error = "Failed to create socket: " + std::string(strerror(errno));
        return result;
    }

    // Set timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms_ / 1000;
    tv.tv_usec = (timeout_ms_ % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Connect
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        result.success = false;
        result.error = "Invalid address: " + host;
        return result;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock);
        result.success = false;
        result.error = "Connection failed: " + std::string(strerror(errno));
        return result;
    }

    // Send data
    ssize_t sent = send(sock, data.c_str(), data.size(), 0);
    if (sent < 0) {
        close(sock);
        result.success = false;
        result.error = "Send failed: " + std::string(strerror(errno));
        return result;
    }

    // Try to receive response
    char recv_buf[4096];
    ssize_t received = recv(sock, recv_buf, sizeof(recv_buf), 0);

    close(sock);

    result.success = true;
    result.data["bytes_sent"] = sent;
    result.data["bytes_received"] = received > 0 ? received : 0;

    LOG_DEBUG("TCP sent {} bytes, received {} bytes", sent, received > 0 ? received : 0);

    return result;
}

AttackResult TaskExecutor::send_udp_data(
    const std::string& host,
    int port,
    const std::string& data
) {
    AttackResult result;

    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        result.success = false;
        result.error = "Failed to create socket: " + std::string(strerror(errno));
        return result;
    }

    // Set timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms_ / 1000;
    tv.tv_usec = (timeout_ms_ % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Prepare address
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        result.success = false;
        result.error = "Invalid address: " + host;
        return result;
    }

    // Send data
    ssize_t sent = sendto(sock, data.c_str(), data.size(), 0,
                          reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (sent < 0) {
        close(sock);
        result.success = false;
        result.error = "Send failed: " + std::string(strerror(errno));
        return result;
    }

    // Try to receive response
    char recv_buf[4096];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    ssize_t received = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                                reinterpret_cast<sockaddr*>(&from_addr), &from_len);

    close(sock);

    result.success = true;
    result.data["bytes_sent"] = sent;
    result.data["bytes_received"] = received > 0 ? received : 0;

    LOG_DEBUG("UDP sent {} bytes, received {} bytes", sent, received > 0 ? received : 0);

    return result;
}
