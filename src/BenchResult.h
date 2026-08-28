#pragma once

// Small shared result type for the per-backend SIMD benchmarks (see
// algo/Sha256.h's sha256BenchmarkBackends()/algo/Scrypt.h's
// scryptBenchmarkBackends()) and the overall --benchmark CLI mode
// (Benchmark.h).

#include <string>

namespace cppminer {

struct BackendBenchResult {
    std::string name;
    double hashesPerSecond;
};

} // namespace cppminer
