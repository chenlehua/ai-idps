#pragma once

#include <string>
#include <map>
#include "json.hpp"

using json = nlohmann::json;

/**
 * Base class for attack generators
 */
class AttackGenerator {
public:
    virtual ~AttackGenerator() = default;

    // Generate attack payload based on configuration
    virtual std::string generate(const json& payload) = 0;

    // Get attack type name
    virtual std::string type_name() const = 0;
};
