#pragma once

// scrypt(N, r=1, p=1, dkLen=32) as used by Litecoin-family coins: a
// hand-rolled PBKDF2-HMAC-SHA256 wrapper (see simd/Sha256Simd.h) around a
// SIMD-batched Salsa20/8 ROMix core (see simd/ScryptSimd.h), replacing the
// previous OpenSSL-generic-SCRYPT-KDF implementation so the dominant cost
// (ROMix) can actually be vectorized - OpenSSL's own SCRYPT is kept around
// purely as the self-test's independent correctness oracle (see
// scryptSimdSelfTest()).

#include "../BenchResult.h"

#include <atomic>
#include <cstdint>
#include <vector>

namespace cppminer::algo {

// Owns the ROMix scratch buffer ("V"), sized once for whichever SIMD
// width this CPU will use, and reused for every hash - allocating
// ~128*N*width bytes per hash would otherwise dominate the cost for
// small N. One instance per mining thread, matching the previous
// OpenSSL-context-per-thread convention.
class ScryptEngine {
public:
    explicit ScryptEngine(uint32_t costN);

    // Single-lane convenience hash (header used as both PBKDF2 password
    // and salt, matching scrypt-based cryptocurrency convention); output
    // bytes are little-endian-word-encoded, bit-identical to what
    // OpenSSL's EVP SCRYPT KDF produces for the same inputs. Always uses
    // the scalar/SHA-NI single-lane path regardless of this engine's
    // batching width - used by the self-test and available for any
    // future non-mining caller.
    void hash(const uint8_t header[80], uint8_t output[32]);

    uint32_t costN() const { return costN_; }
    int width() const { return width_; }
    uint32_t* scratch() { return scratch_.data(); }

private:
    uint32_t costN_;
    int width_; // 1, 4 or 8 - chosen once from simd::cpuFeatures()
    std::vector<uint32_t> scratch_;
};

// Mining hot loop, mirrors scanHashSha256d (see Sha256.h) but for scrypt:
// batches engine.width() nonces at a time through the SIMD ROMix core.
bool scanHashScrypt(ScryptEngine& engine, uint8_t header[80], const uint32_t target[8], uint32_t maxNonce,
                     uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone);

// Verifies the scalar/SSE2/AVX2 ROMix backends agree with each other and
// that the full PBKDF2+ROMix pipeline matches OpenSSL's independently
// implemented SCRYPT KDF, both directly and end-to-end through
// scanHashScrypt(). Called once at startup, mirroring lyra2WebSelfTest().
bool scryptSimdSelfTest();

// Name of the backend scanHashScrypt() will actually use on this CPU
// ("AVX2 (8-way)", "SSE2 (4-way)" or "scalar"), for logging.
const char* scryptActiveBackendName();

// Runs every ROMix backend this CPU supports for roughly
// `secondsPerBackend` seconds each, at the given cost parameter, and
// reports each one's real scrypt hash rate - used by --benchmark, see
// Benchmark.h.
std::vector<BackendBenchResult> scryptBenchmarkBackends(double secondsPerBackend, uint32_t costN);

} // namespace cppminer::algo
