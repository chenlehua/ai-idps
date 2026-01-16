#pragma once

#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace nlohmann {

class json {
public:
    using object_t = std::unordered_map<std::string, json>;
    using array_t = std::vector<json>;
    using string_t = std::string;
    using boolean_t = bool;
    using number_t = double;
    using value_t = std::variant<std::nullptr_t, object_t, array_t, string_t, boolean_t, number_t>;

    json() : value_(nullptr) {}
    json(std::nullptr_t) : value_(nullptr) {}
    json(const char* value) : value_(string_t(value)) {}
    json(const string_t& value) : value_(value) {}
    json(boolean_t value) : value_(value) {}
    json(int value) : value_(static_cast<number_t>(value)) {}
    json(double value) : value_(value) {}
    json(const object_t& value) : value_(value) {}
    json(const array_t& value) : value_(value) {}

    static json parse(const std::string& text) {
        return json(text);
    }

    std::string dump() const {
        if (auto str = std::get_if<string_t>(&value_)) {
            return *str;
        }
        return "{}";
    }

    json& operator[](const std::string& key) {
        if (!std::holds_alternative<object_t>(value_)) {
            value_ = object_t{};
        }
        return std::get<object_t>(value_)[key];
    }

    const json& operator[](const std::string& key) const {
        static json empty;
        if (!std::holds_alternative<object_t>(value_)) {
            return empty;
        }
        const auto& obj = std::get<object_t>(value_);
        auto it = obj.find(key);
        return it == obj.end() ? empty : it->second;
    }

private:
    value_t value_;
};

}  // namespace nlohmann
