#pragma once

#include <string>

class RuleManager {
public:
    explicit RuleManager(const std::string& rules_dir);

    const std::string& current_version() const;
    const std::string& rules_path() const;

    void update(const std::string& version, const std::string& content);

private:
    std::string rules_dir_;
    std::string current_version_;
    std::string rules_path_;
};
