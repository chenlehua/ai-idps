#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <regex>

namespace logger {

inline std::string now() {
    auto time_now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(time_now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Helper to convert argument to string
template <typename T>
inline std::string to_string_helper(const T& arg) {
    std::ostringstream oss;
    oss << arg;
    return oss.str();
}

// Base case: no more arguments to replace
inline std::string format_impl(const std::string& fmt) {
    return fmt;
}

// Recursive case: replace first {} with first argument
template <typename T, typename... Args>
inline std::string format_impl(const std::string& fmt, const T& first, const Args&... rest) {
    size_t pos = fmt.find("{}");
    if (pos == std::string::npos) {
        return fmt;
    }
    std::string result = fmt.substr(0, pos) + to_string_helper(first) + fmt.substr(pos + 2);
    return format_impl(result, rest...);
}

// Format function supporting {} placeholders
template <typename... Args>
inline std::string format(const std::string& fmt, const Args&... args) {
    return format_impl(fmt, args...);
}

// Log function with fmt-style formatting
template <typename... Args>
inline void log(const char* level, const std::string& fmt, const Args&... args) {
    std::string msg = format(fmt, args...);
    std::cout << "[" << now() << "] [" << level << "] " << msg << std::endl;
}

// Overload for single string argument (no formatting needed)
inline void log(const char* level, const std::string& msg) {
    std::cout << "[" << now() << "] [" << level << "] " << msg << std::endl;
}

}  // namespace logger

#define LOG_INFO(...) logger::log("INFO", __VA_ARGS__)
#define LOG_WARN(...) logger::log("WARN", __VA_ARGS__)
#define LOG_ERROR(...) logger::log("ERROR", __VA_ARGS__)
#define LOG_DEBUG(...) logger::log("DEBUG", __VA_ARGS__)
