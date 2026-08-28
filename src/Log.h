#pragma once

// Minimal thread-safe logger, loosely modeled after the reference
// cpuminer's applog(): timestamped lines on stderr, with a couple of level
// filters controlled by CLI flags.

#include <string>

namespace cppminer {

enum class LogLevel { Error, Warning, Notice, Info, Debug };

void logSetDebug(bool enabled);
void logSetQuiet(bool quiet);

void logMessage(LogLevel level, const std::string& msg);

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
void logf(LogLevel level, const char* fmt, ...);

} // namespace cppminer
