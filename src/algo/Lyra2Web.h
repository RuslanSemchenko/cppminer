#pragma once

// Lyra2-webchain / lyra2v2-webchain (MintMe) hashing, built on the vendored
// reference Lyra2/Sponge core in algo/lyra2. The pool sends a full opaque
// job "blob"; mining only ever patches an 8-byte little-endian nonce into
// its last 8 bytes and runs Lyra2 over the whole thing (see WebchainClient
// for how the blob/target/time-cost are obtained from the pool).

#include "../BenchResult.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cppminer::simd {
struct Lyra2Sse2Context;
struct Lyra2Avx2Context;
struct Lyra2Avx512Context;
}

namespace cppminer::algo {

// Owns the scalar ~6 MB Lyra2 scratch matrix and, when available, the AVX2
// four-lane matrix. Allocate one context per mining thread.
// Owns the ~6 MB Lyra2 scratch matrix (NROWS=16384, NCOLS=4). Allocate one
// per mining thread and reuse it for the thread's whole lifetime.
class Lyra2Context {
public:
    Lyra2Context();
    ~Lyra2Context();
    Lyra2Context(const Lyra2Context&) = delete;
    Lyra2Context& operator=(const Lyra2Context&) = delete;

    void* handle() const { return ctx_; }
    cppminer::simd::Lyra2Sse2Context* simdSse2Handle() const { return simdSse2Ctx_; }
    cppminer::simd::Lyra2Avx2Context* simdHandle() const { return simdCtx_; }
    cppminer::simd::Lyra2Avx512Context* simd512Handle() const { return simd512Ctx_; }

private:
    void* ctx_;
    cppminer::simd::Lyra2Sse2Context* simdSse2Ctx_;
    cppminer::simd::Lyra2Avx2Context* simdCtx_;
    cppminer::simd::Lyra2Avx512Context* simd512Ctx_;
};

// Lyra2(kLen=32, pwd=data, pwdlen=size, timeCost=tcost); tcost must be 1
// (lyra2v2-webchain, post hard-fork) or 4 (lyra2-webchain, legacy).
void lyra2WebHash(Lyra2Context& ctx, const uint8_t* data, size_t size, uint32_t tcost, uint8_t out[32]);
const char* lyra2WebActiveBackendName();

// Parallel SIMD lane count for this context (1 for scalar).
size_t lyra2WebSimdLanes(const Lyra2Context& ctx);

// Selects the Lyra2 SIMD backend for newly created Lyra2Context objects.
// `auto` keeps the runtime default priority; explicit values are scalar,
// sse2, avx2 or avx512. Returns false when the name is unknown or the
// requested instructions are unavailable on this CPU.
bool lyra2WebSelectBackend(const std::string& name, std::string& error);

// Offline per-backend hashrate comparison (scalar, SSE2, AVX2, AVX-512).
std::vector<BackendBenchResult> lyra2WebBenchmarkBackends(double secondsPerBackend, uint32_t tcost);

// Mining hot loop. `blob`'s last 8 bytes are overwritten with the
// little-endian nonce on every attempt. `nonceInOut` is the starting nonce
// on entry and, on return, either the winning nonce (true) or the last
// nonce tried (false); on a win `resultHash` receives the 32-byte hash,
// which the Webchain submit protocol needs alongside the nonce. `target` is
// the pool's raw 8-byte target, compared per Webchain/XMRig convention:
// bswap64(le64dec(hash)) <= le64dec(target).
bool scanHashLyra2Web(Lyra2Context& ctx, std::vector<uint8_t>& blob, uint32_t tcost,
                       const uint8_t target[8], uint64_t maxNonce, uint64_t& nonceInOut,
                       std::atomic<bool>& restart, uint64_t& hashesDone, uint8_t resultHash[32]);

// Verifies the port against the bundled Webchain reference vectors (both
// time-cost variants). Called once at startup.
bool lyra2WebSelfTest();

} // namespace cppminer::algo
