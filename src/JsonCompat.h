#pragma once

// Apple SDK math.h exposes signbit/isfinite/isnan/isinf as function-like
// macros. Initialize libc++'s standard declarations first, then remove the
// macros so nlohmann-json's qualified std:: calls remain valid under Clang.
#include <cmath>

#if defined(__APPLE__)
#  if defined(signbit)
#    undef signbit
#  endif
#  if defined(isfinite)
#    undef isfinite
#  endif
#  if defined(isnan)
#    undef isnan
#  endif
#  if defined(isinf)
#    undef isinf
#  endif
#endif

#include <nlohmann/json.hpp>
