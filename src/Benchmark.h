#pragma once

// Offline `--benchmark` mode: no network/pool involved. Verifies every
// SIMD backend this build+CPU supports, times each one individually
// (scalar vs SSE2 vs AVX2 vs SHA-NI, whichever apply) so the speedup from
// this session's SIMD work is directly visible, and separately reports
// the realistic aggregate hashrate --threads worker threads would get
// using the automatically-selected fastest backend.

#include "Config.h"

namespace cppminer {

// Returns the process exit code (0 on success, 1 if any requested
// algorithm's self-test failed).
int runBenchmark(const Config& config);

} // namespace cppminer
