#include "probe_connection.h"

ProbeConnection::ProbeConnection(int fd)
    : fd_(fd)
    , closed_(false) {
}

std::optional<json> ProbeConnection::read_message() {
    return std::nullopt;
}

void ProbeConnection::send_message(const json& msg) {
    (void)msg;
}

bool ProbeConnection::is_closed() const {
    return closed_;
}
