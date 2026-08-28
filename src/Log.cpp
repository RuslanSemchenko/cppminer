#include "Log.h"

#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

namespace cppminer {

namespace {
std::mutex g_logMutex;
bool g_debug = false;
bool g_quiet = false;

const char* levelTag(LogLevel level)
{
    switch (level) {
        case LogLevel::Error:   return "error";
        case LogLevel::Warning: return "warn ";
        case LogLevel::Notice:  return "note ";
        case LogLevel::Info:    return "info ";
        case LogLevel::Debug:   return "debug";
    }
    return "?????";
}
} // namespace

void logSetDebug(bool enabled) { g_debug = enabled; }
void logSetQuiet(bool quiet) { g_quiet = quiet; }

void logMessage(LogLevel level, const std::string& msg)
{
    if (level == LogLevel::Debug && !g_debug)
        return;
    if (level == LogLevel::Info && g_quiet)
        return;

    std::time_t t = std::time(nullptr);
    std::tm tmBuf{};
#ifdef _WIN32
    localtime_s(&tmBuf, &t);
#else
    localtime_r(&t, &tmBuf);
#endif
    char timeBuf[32];
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tmBuf);

    std::lock_guard<std::mutex> lock(g_logMutex);
    std::fprintf(stderr, "[%s] %s %s\n", timeBuf, levelTag(level), msg.c_str());
    std::fflush(stderr);
}

void logf(LogLevel level, const char* fmt, ...)
{
    if (level == LogLevel::Debug && !g_debug)
        return;
    if (level == LogLevel::Info && g_quiet)
        return;

    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    logMessage(level, buf);
}

} // namespace cppminer
