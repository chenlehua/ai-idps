#include "rule_manager.h"
#include "logger.h"

#include <fstream>

RuleManager::RuleManager(const std::string& rules_dir)
    : rules_dir_(rules_dir)
    , current_version_("v0")
    , rules_path_(rules_dir_ + "/suricata.rules") {
}

const std::string& RuleManager::current_version() const {
    return current_version_;
}

const std::string& RuleManager::rules_path() const {
    return rules_path_;
}

void RuleManager::update(const std::string& version, const std::string& content) {
    std::ofstream out(rules_path_, std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        LOG_ERROR("Failed to write rules to ", rules_path_);
        return;
    }
    out << content;
    current_version_ = version;
    LOG_INFO("Rules updated to version ", version);
}
