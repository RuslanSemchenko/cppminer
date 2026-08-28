#pragma once

// SHA-256 / SHA-256d built on top of OpenSSL's EVP interface rather than a
// hand-rolled compression function, so the well tested libcrypto
// implementation does the actual bit-twiddling.

#include "../BenchResult.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <openssl/evp.h>
#include <string>
#include <vector>

namespace cppminer::algo {

class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256& other);
    Sha256& operator=(const Sha256& other);

    void update(const uint8_t* data, size_t len);
    // Writes the 32-byte digest to `out`. The object must not be reused
    // afterwards.
    void finalize(uint8_t out[32]);

    static void hash(const uint8_t* data, size_t len, uint8_t out[32]);
    static void hash256d(const uint8_t* data, size_t len, uint8_t out[32]);

private:
    EVP_MD_CTX* ctx_;
};

// sha256d mining hot loop.
//
// `header` is the 80-byte classic block header (see Work.h); bytes [76,80)
// are treated as the nonce and are overwritten on every attempt. `nonceInOut`
// is the starting nonce on entry, and on return holds either the winning
// nonce (return value true) or the last nonce that was tried (false).
// `target` is the 8-word target produced by util::diffToTarget. The scan
// stops at `maxNonce` or as soon as `restart` becomes true.
bool scanHashSha256d(uint8_t header[80], const uint32_t target[8], uint32_t maxNonce,
                      uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone);

// Verifies every SIMD backend the current CPU/binary supports (scalar,
// SSE2, AVX2, SHA-NI, whichever apply) produces bit-identical results to
// each other and to OpenSSL's sha256d, both on the raw compression
// function and end-to-end through scanHashSha256d(). Called once at
// startup, mirroring lyra2WebSelfTest().
bool sha256SimdSelfTest();

// Selects the backend used by scanHashSha256d(). `auto` keeps the runtime
// default priority; explicit values are scalar, sse2, avx2, avx512 or sha-ni.
// Returns false with a human-readable error when the name is unknown or the
// requested instructions are unavailable on this CPU.
bool sha256SelectBackend(const std::string& name, std::string& error);

// Name of the backend scanHashSha256d() will actually use on this CPU
// ("SHA-NI", "AVX-512 (16-way)", "AVX2 (8-way)", "SSE2 (4-way)" or
// "scalar"), for logging.
const char* sha256ActiveBackendName();

// Runs every backend this CPU/binary supports for roughly
// `secondsPerBackend` seconds each (via a synthetic header/impossible
// target, so no early exit) and reports each one's real sha256d hash
// rate - used by --benchmark, see Benchmark.h.
std::vector<BackendBenchResult> sha256BenchmarkBackends(double secondsPerBackend);

} // namespace cppminer::algo
