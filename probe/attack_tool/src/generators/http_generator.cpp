#include "generators/http_generator.h"
#include <sstream>
#include <iomanip>

HTTPGenerator::HTTPGenerator() {
}

std::string HTTPGenerator::generate(const json& payload) {
    std::string method = payload.value("method", "GET");
    std::string path = payload.value("path", "/");
    std::string host = payload.value("host", "localhost");
    std::string body = payload.value("body", "");

    std::map<std::string, std::string> headers;

    // Add default headers
    headers["Host"] = host;
    headers["User-Agent"] = "AttackTool/1.0";
    headers["Accept"] = "*/*";
    headers["Connection"] = "close";

    // Override with payload headers
    if (payload.contains("headers") && payload["headers"].is_object()) {
        for (auto& [key, value] : payload["headers"].items()) {
            headers[key] = value.get<std::string>();
        }
    }

    if (method == "POST" || method == "PUT") {
        std::string content_type = payload.value("content_type", "application/x-www-form-urlencoded");
        headers["Content-Type"] = content_type;
        headers["Content-Length"] = std::to_string(body.size());
        return generate_post_request(host, path, body, content_type, headers);
    }

    // Handle query parameters
    std::map<std::string, std::string> params;
    if (payload.contains("params") && payload["params"].is_object()) {
        for (auto& [key, value] : payload["params"].items()) {
            params[key] = value.get<std::string>();
        }
    }

    return generate_get_request(host, path, headers, params);
}

std::string HTTPGenerator::generate_get_request(
    const std::string& host,
    const std::string& path,
    const std::map<std::string, std::string>& headers,
    const std::map<std::string, std::string>& params
) {
    std::ostringstream request;

    // Build path with query string
    std::string full_path = path;
    if (!params.empty()) {
        full_path += "?" + build_query_string(params);
    }

    // Request line
    request << build_request_line("GET", full_path);

    // Headers
    request << build_headers(headers);

    // End of headers
    request << "\r\n";

    return request.str();
}

std::string HTTPGenerator::generate_post_request(
    const std::string& host,
    const std::string& path,
    const std::string& body,
    const std::string& content_type,
    const std::map<std::string, std::string>& headers
) {
    std::ostringstream request;

    // Request line
    request << build_request_line("POST", path);

    // Headers (copy to add content headers)
    std::map<std::string, std::string> all_headers = headers;
    all_headers["Content-Type"] = content_type;
    all_headers["Content-Length"] = std::to_string(body.size());

    request << build_headers(all_headers);

    // End of headers
    request << "\r\n";

    // Body
    request << body;

    return request.str();
}

std::string HTTPGenerator::build_request_line(const std::string& method, const std::string& path) {
    return method + " " + path + " HTTP/1.1\r\n";
}

std::string HTTPGenerator::build_headers(const std::map<std::string, std::string>& headers) {
    std::ostringstream oss;
    for (const auto& [key, value] : headers) {
        oss << key << ": " << value << "\r\n";
    }
    return oss.str();
}

std::string HTTPGenerator::url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        // Keep alphanumeric and other safe characters
        if (std::isalnum(static_cast<unsigned char>(c)) ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
        }
    }

    return escaped.str();
}

std::string HTTPGenerator::build_query_string(const std::map<std::string, std::string>& params) {
    std::ostringstream oss;
    bool first = true;

    for (const auto& [key, value] : params) {
        if (!first) {
            oss << "&";
        }
        oss << url_encode(key) << "=" << url_encode(value);
        first = false;
    }

    return oss.str();
}
