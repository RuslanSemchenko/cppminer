#pragma once

// Command-line / JSON config handling. JSON config keys mirror the long
// option names (see example-cfg.json in the repository root for the same
// convention in the reference C miner), e.g. {"url": "...", "threads": 4}.

#include <cstdint>
#include <string>

#include "Work.h"

namespace cppminer {

struct Config {
    std::string url;
    std::string user;
    std::string pass;

    // Keep the standalone miner algorithm-neutral by default; select the
    // pool's algorithm explicitly with --algo/-a.
    Algorithm algo = Algorithm::Scrypt;
    uint32_t scryptN = 1024;
    // Whether -a/--algo (or the config file's "algo" key) was actually
    // given, as opposed to `algo` just holding its default value -
    // --benchmark uses this to decide whether to benchmark just that one
    // algorithm or all three.
    bool algoExplicit = false;

    int threads = 0; // 0 => resolved to std::thread::hardware_concurrency()
    int retries = -1; // -1 => retry forever
    int retryPauseSeconds = 30;

    bool quiet = false;
    bool protocolDump = false;
    bool debug = false;

    // TLS certificate/hostname verification is enabled by default. The pin
    // uses libcurl's CURLOPT_PINNEDPUBLICKEY format when non-empty.
    bool tlsVerify = true;
    std::string tlsPin;

    // SHA-256d backend: auto, scalar, sse2, avx2, avx512 or sha-ni.
    std::string sha256Backend = "auto";

    // RandomX memory mode. Full memory is the mining default (roughly 2 GiB
    // shared dataset); --randomx-light is available for constrained hosts.
    bool randomxFullMemory = true;
    bool randomxLargePages = false;

    // Offline SIMD/hashrate benchmark (see Benchmark.h) - no -o/--url
    // needed in this mode.
    bool benchmark = false;
    double benchSeconds = 3.0; // seconds spent timing each individual backend

    // Parses argv into `out`. Returns false when the process should exit
    // right away (bad arguments, or -h/-V were given) - `exitCode` is then
    // the value main() should return.
    static bool parse(int argc, char** argv, Config& out, int& exitCode);
};

} // namespace cppminer
