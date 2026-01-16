#pragma once

#include <string>

class ProbeBase {
public:
    virtual ~ProbeBase() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual std::string probe_type() const = 0;
};
