#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

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

template <typename... Args>
inline void log(const char* level, Args&&... args) {
    std::ostringstream oss;
    (oss << ... << args);
    std::cout << "[" << now() << "] [" << level << "] " << oss.str() << std::endl;
}

}  // namespace logger

#define LOG_INFO(...) logger::log("INFO", __VA_ARGS__)
#define LOG_WARN(...) logger::log("WARN", __VA_ARGS__)
#define LOG_ERROR(...) logger::log("ERROR", __VA_ARGS__)
#define LOG_DEBUG(...) logger::log("DEBUG", __VA_ARGS__)
