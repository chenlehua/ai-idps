#include "config.h"
#include "logger.h"

#include <fstream>

void Config::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        LOG_WARN("Config file not found: ", path, ", using defaults");
        return;
    }
    LOG_INFO("Config file loaded: ", path, " (parser pending)");
}
