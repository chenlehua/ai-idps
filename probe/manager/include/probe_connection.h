#pragma once

#include <optional>
#include "json.hpp"

using json = nlohmann::json;

class ProbeConnection {
public:
    explicit ProbeConnection(int fd);

    std::optional<json> read_message();
    void send_message(const json& msg);
    bool is_closed() const;

private:
    int fd_;
    bool closed_;
};
