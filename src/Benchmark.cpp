#include "Benchmark.h"

#include "Log.h"
#include "algo/Lyra2Web.h"
#include "algo/RandomX.h"
#include "algo/Scrypt.h"
#include "algo/Sha256.h"
#include "algo/randomx/randomx.h"
#include "simd/CpuFeatures.h"

#include <algorithm>
#include <array>
#include <memory>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

namespace cppminer {

namespace {

void printBackendTable(const std::vector<BackendBenchResult>& results, const char* activeBackend,
                       const char* unit = "H/s")
{
    double baseline = results.empty() ? 0.0 : results.front().hashesPerSecond;
    for (const auto& r : results) {
        double speedup = baseline > 0.0 ? r.hashesPerSecond / baseline : 0.0;
        bool active = r.name == activeBackend;
        logf(LogLevel::Notice, "    %-14s %14.2f %s   (%.2fx vs scalar)%s", r.name.c_str(),
             r.hashesPerSecond, unit, speedup, active ? "   <- used for mining" : "");
    }
}

double benchmarkMultiThreadSha256d(int threads, double seconds)
{
    std::vector<double> rates(static_cast<size_t>(threads), 0.0);
    std::vector<std::thread> workers;
    for (int t = 0; t < threads; t++) {
        workers.emplace_back([&, t]() {
            uint8_t header[80];
            std::memset(header, static_cast<uint8_t>(0x10 + t), sizeof(header));
            uint32_t target[8] = {0, 0, 0, 0, 0, 0, 0, 0};
            std::atomic<bool> restart{false};
            uint32_t nonce = 0;
            uint64_t totalHashes = 0;
            auto t0 = std::chrono::steady_clock::now();
            double elapsed = 0.0;
            while (elapsed < seconds) {
                uint64_t hashesDone = 0;
                uint32_t maxNonce = nonce + 200000u;
                algo::scanHashSha256d(header, target, maxNonce, nonce, restart, hashesDone);
                totalHashes += hashesDone;
                nonce = maxNonce + 1;
                elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            }
            rates[static_cast<size_t>(t)] = elapsed > 0.0 ? double(totalHashes) / elapsed : 0.0;
        });
    }
    for (auto& w : workers)
        w.join();
    double total = 0.0;
    for (double r : rates)
        total += r;
    return total;
}

double benchmarkMultiThreadScrypt(int threads, uint32_t costN, double seconds)
{
    std::vector<double> rates(static_cast<size_t>(threads), 0.0);
    std::vector<std::thread> workers;
    for (int t = 0; t < threads; t++) {
        workers.emplace_back([&, t]() {
            algo::ScryptEngine engine(costN);
            uint8_t header[80];
            std::memset(header, static_cast<uint8_t>(0x20 + t), sizeof(header));
            uint32_t target[8] = {0, 0, 0, 0, 0, 0, 0, 0};
            std::atomic<bool> restart{false};
            uint32_t nonce = 0;
            uint64_t totalHashes = 0;
            auto t0 = std::chrono::steady_clock::now();
            double elapsed = 0.0;
            while (elapsed < seconds) {
                uint64_t hashesDone = 0;
                uint32_t maxNonce = nonce + 64u;
                algo::scanHashScrypt(engine, header, target, maxNonce, nonce, restart, hashesDone);
                totalHashes += hashesDone;
                nonce = maxNonce + 1;
                elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            }
            rates[static_cast<size_t>(t)] = elapsed > 0.0 ? double(totalHashes) / elapsed : 0.0;
        });
    }
    for (auto& w : workers)
        w.join();
    double total = 0.0;
    for (double r : rates)
        total += r;
    return total;
}

double benchmarkMultiThreadRandomX(int threads, double seconds, bool fullMemory, bool largePages)
{
    auto state = std::make_shared<algo::RandomXState>(fullMemory, largePages);
    std::vector<double> rates(static_cast<size_t>(threads), 0.0);
    std::vector<std::thread> workers;
    for (int t = 0; t < threads; t++) {
        workers.emplace_back([&, t]() {
            algo::RandomXContext ctx(*state);
            std::vector<uint8_t> blob(76, 0x55);
            std::array<uint8_t, 32> seed{};
            uint8_t target[8] = {0, 0, 0, 0, 0, 0, 0, 0};
            uint32_t nonce = static_cast<uint32_t>(t) << 24;
            std::atomic<bool> restart{false};
            uint64_t totalHashes = 0;
            uint8_t resultHash[32];
            std::string warmupError;
            if (!ctx.hash(blob.data(), blob.size(), seed.data(), seed.size(), resultHash, warmupError)) {
                logf(LogLevel::Error, "RandomX benchmark warm-up error: %s", warmupError.c_str());
                return;
            }
            auto t0 = std::chrono::steady_clock::now();
            double elapsed = 0.0;
            while (elapsed < seconds) {
                uint64_t hashesDone = 0;
                const uint32_t maxNonce = nonce > 0xffffffffu - 32u ? 0xffffffffu : nonce + 32u;
                std::string error;
                if (!algo::scanHashRandomX(ctx, blob, 39, seed, target, maxNonce, nonce, restart,
                                            hashesDone, resultHash, error) || !error.empty()) {
                    if (!error.empty())
                        logf(LogLevel::Error, "RandomX benchmark error: %s", error.c_str());
                    totalHashes += hashesDone;
                } else {
                    totalHashes += hashesDone;
                }
                nonce = maxNonce == 0xffffffffu ? static_cast<uint32_t>(t) << 24 : maxNonce + 1;
                elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            }
            rates[static_cast<size_t>(t)] = elapsed > 0.0 ? double(totalHashes) / elapsed : 0.0;
        });
    }
    for (auto& w : workers)
        w.join();
    double total = 0.0;
    for (double r : rates)
        total += r;
    return total;
}

double benchmarkMultiThreadLyra2Web(int threads, uint32_t tcost, double seconds)
{
    std::vector<double> rates(static_cast<size_t>(threads), 0.0);
    std::vector<std::thread> workers;
    for (int t = 0; t < threads; t++) {
        workers.emplace_back([&, t]() {
            algo::Lyra2Context ctx;
            std::vector<uint8_t> blob(76, 0x55);
            uint8_t target[8] = {0, 0, 0, 0, 0, 0, 0, 0};
            std::atomic<bool> restart{false};
            uint64_t nonce = uint64_t(t) << 40;
            uint64_t totalHashes = 0;
            uint8_t resultHash[32];
            auto t0 = std::chrono::steady_clock::now();
            double elapsed = 0.0;
            while (elapsed < seconds) {
                uint64_t hashesDone = 0;
                uint64_t maxNonce = nonce + 8;
                algo::scanHashLyra2Web(ctx, blob, tcost, target, maxNonce, nonce, restart, hashesDone, resultHash);
                totalHashes += hashesDone;
                nonce = maxNonce + 1;
                elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            }
            rates[static_cast<size_t>(t)] = elapsed > 0.0 ? double(totalHashes) / elapsed : 0.0;
        });
    }
    for (auto& w : workers)
        w.join();
    double total = 0.0;
    for (double r : rates)
        total += r;
    return total;
}

} // namespace

int runBenchmark(const Config& config)
{
    const double perBackendSeconds = config.benchSeconds;
    const double multiThreadSeconds = std::max(config.benchSeconds, 2.0);

    logf(LogLevel::Notice, "=== cppminer benchmark ===");
    logf(LogLevel::Notice, "CPU features: %s", simd::cpuFeaturesString());
    logf(LogLevel::Notice, "threads: %d", config.threads);

    bool doSha256d = !config.algoExplicit || config.algo == Algorithm::Sha256d;
    bool doScrypt = !config.algoExplicit || config.algo == Algorithm::Scrypt;
    bool doLyra2Web = !config.algoExplicit || config.algo == Algorithm::Lyra2Web;
    bool doRandomX = !config.algoExplicit || config.algo == Algorithm::RandomX;
    bool anyFailed = false;

    if (doSha256d) {
        logf(LogLevel::Notice, "--- sha256d ---");
        if (!algo::sha256SimdSelfTest()) {
            logf(LogLevel::Error, "sha256d self-test FAILED, skipping its benchmark");
            anyFailed = true;
        } else {
            logf(LogLevel::Notice, "self-test OK. Per-backend, single-thread comparison:");
            printBackendTable(algo::sha256BenchmarkBackends(perBackendSeconds), algo::sha256ActiveBackendName());
            double total = benchmarkMultiThreadSha256d(config.threads, multiThreadSeconds);
            logf(LogLevel::Notice, "  realistic total with %d thread(s) (%s): %.2f H/s", config.threads,
                 algo::sha256ActiveBackendName(), total);
        }
    }

    if (doScrypt) {
        logf(LogLevel::Notice, "--- scrypt (N=%u) ---", config.scryptN);
        if (!algo::scryptSimdSelfTest()) {
            logf(LogLevel::Error, "scrypt self-test FAILED, skipping its benchmark");
            anyFailed = true;
        } else {
            logf(LogLevel::Notice, "self-test OK. Per-backend, single-thread comparison:");
            printBackendTable(algo::scryptBenchmarkBackends(perBackendSeconds, config.scryptN),
                               algo::scryptActiveBackendName());
            double total = benchmarkMultiThreadScrypt(config.threads, config.scryptN, multiThreadSeconds);
            logf(LogLevel::Notice, "  realistic total with %d thread(s) (%s): %.2f H/s", config.threads,
                 algo::scryptActiveBackendName(), total);
        }
    }

    if (doRandomX) {
        logf(LogLevel::Notice, "--- randomx (%s) ---", config.randomxFullMemory ? "full-memory" : "light-memory");
        if (!algo::randomXSelfTest()) {
            logf(LogLevel::Error, "RandomX self-test FAILED, skipping its benchmark");
            anyFailed = true;
        } else {
            logf(LogLevel::Notice, "self-test OK (official API vector); SIMD: %s; backend: %s.",
                 algo::randomXSimdFeaturesString(), algo::randomXActiveBackendName());
            logf(LogLevel::Notice, "Argon2 cache-init SIMD comparison:");
            const randomx_flags flags = randomx_get_flags();
            const char* activeArgon = (flags & RANDOMX_FLAG_ARGON2_AVX2)   ? "AVX2"
                                    : (flags & RANDOMX_FLAG_ARGON2_SSSE3) ? "SSSE3"
                                                                          : "scalar";
            printBackendTable(algo::randomXBenchmarkArgonBackends(perBackendSeconds), activeArgon, "init/s");
            double total = benchmarkMultiThreadRandomX(config.threads, multiThreadSeconds,
                                                       config.randomxFullMemory, config.randomxLargePages);
            logf(LogLevel::Notice, "  realistic total with %d thread(s) (%s): %.2f H/s", config.threads,
                 algo::randomXActiveBackendName(), total);
        }
    }

    if (doLyra2Web) {
        logf(LogLevel::Notice, "--- lyra2web ---");
        if (!algo::lyra2WebSelfTest()) {
            logf(LogLevel::Error, "lyra2web self-test FAILED, skipping its benchmark");
            anyFailed = true;
        } else {
            logf(LogLevel::Notice, "self-test OK (active backend: %s).", algo::lyra2WebActiveBackendName());
            double total = benchmarkMultiThreadLyra2Web(config.threads, 4, multiThreadSeconds);
            logf(LogLevel::Notice, "  realistic total with %d thread(s) (%s): %.2f H/s", config.threads,
                 algo::lyra2WebActiveBackendName(), total);
        }
    }

    return anyFailed ? 1 : 0;
}

} // namespace cppminer
