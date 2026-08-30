#include "Lyra2Web.h"

#include "../ByteUtils.h"
#include "lyra2/Lyra2.h"
#include "../simd/CpuFeatures.h"
#include "../simd/Lyra2Simd.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <stdlib.h>
#endif

namespace cppminer::algo {
namespace {

enum class Lyra2Backend { Auto, Scalar, Sse2, Avx2, Avx512 };

Lyra2Backend selectedLyraBackend = Lyra2Backend::Auto;

bool parseLyraBackendName(const std::string& name, Lyra2Backend& out)
{
    std::string lower;
    lower.reserve(name.size());
    for (char c : name)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower == "auto") {
        out = Lyra2Backend::Auto;
        return true;
    }
    if (lower == "scalar") {
        out = Lyra2Backend::Scalar;
        return true;
    }
    if (lower == "sse2") {
        out = Lyra2Backend::Sse2;
        return true;
    }
    if (lower == "avx2") {
        out = Lyra2Backend::Avx2;
        return true;
    }
    if (lower == "avx512" || lower == "avx-512") {
        out = Lyra2Backend::Avx512;
        return true;
    }
    return false;
}

const char* backendName(Lyra2Backend backend)
{
    switch (backend) {
    case Lyra2Backend::Auto:
        return "auto";
    case Lyra2Backend::Scalar:
        return "scalar";
    case Lyra2Backend::Sse2:
        return "SSE2 2-way";
    case Lyra2Backend::Avx2:
        return "AVX2 4-way";
    case Lyra2Backend::Avx512:
        return "AVX-512 8-way";
    }
    return "unknown";
}

bool backendSupported(Lyra2Backend backend, const simd::CpuFeatures& feat)
{
    switch (backend) {
    case Lyra2Backend::Auto:
    case Lyra2Backend::Scalar:
        return true;
    case Lyra2Backend::Sse2:
        return feat.sse2;
    case Lyra2Backend::Avx2:
        return feat.avx2;
    case Lyra2Backend::Avx512:
        return feat.avx512f;
    }
    return false;
}

Lyra2Backend effectiveLyraBackend(const simd::CpuFeatures& feat)
{
    if (selectedLyraBackend != Lyra2Backend::Auto)
        return selectedLyraBackend;
    // AVX2 is the default on CPUs that expose both ISAs: Lyra2 is
    // memory-bound and AVX-512 may lower the core frequency enough to lose.
    if (feat.avx2)
        return Lyra2Backend::Avx2;
    if (feat.avx512f)
        return Lyra2Backend::Avx512;
    if (feat.sse2)
        return Lyra2Backend::Sse2;
    return Lyra2Backend::Scalar;
}

Lyra2Backend envLyraBackendOverride()
{
#ifdef _WIN32
    char* value = nullptr;
    size_t length = 0;
    const bool hasValue = _dupenv_s(&value, &length, "CPPMINER_LYRA_BACKEND") == 0 && value != nullptr;
    const std::string stored = hasValue ? value : "";
    if (value)
        free(value);
    if (stored.empty())
        return Lyra2Backend::Auto;
    Lyra2Backend parsed = Lyra2Backend::Auto;
    if (!parseLyraBackendName(stored, parsed))
        return Lyra2Backend::Auto;
    return parsed;
#else
    const char* value = std::getenv("CPPMINER_LYRA_BACKEND");
    if (!value)
        return Lyra2Backend::Auto;
    Lyra2Backend parsed = Lyra2Backend::Auto;
    if (!parseLyraBackendName(value, parsed))
        return Lyra2Backend::Auto;
    return parsed;
#endif
}

void createSimdContexts(Lyra2Backend backend, const simd::CpuFeatures& feat,
                        simd::Lyra2Sse2Context*& sse2, simd::Lyra2Avx2Context*& avx2,
                        simd::Lyra2Avx512Context*& avx512)
{
    if (backend == Lyra2Backend::Scalar)
        return;
    if (backend == Lyra2Backend::Avx512 && feat.avx512f)
        avx512 = simd::lyra2Avx512Create();
    else if (backend == Lyra2Backend::Avx2 && feat.avx2)
        avx2 = simd::lyra2Avx2Create();
    else if (backend == Lyra2Backend::Sse2 && feat.sse2)
        sse2 = simd::lyra2Sse2Create();
}

} // namespace

Lyra2Context::Lyra2Context()
    : ctx_(nullptr), simdSse2Ctx_(nullptr), simdCtx_(nullptr), simd512Ctx_(nullptr)
{
    ctx_ = LYRA2_create();
    if (!ctx_)
        throw std::runtime_error("failed to allocate the Lyra2 scratch matrix (~6 MB)");

    const auto features = simd::cpuFeatures();
    const Lyra2Backend envOverride = envLyraBackendOverride();
    const Lyra2Backend backend = envOverride != Lyra2Backend::Auto ? envOverride : effectiveLyraBackend(features);
    createSimdContexts(backend, features, simdSse2Ctx_, simdCtx_, simd512Ctx_);
}

Lyra2Context::~Lyra2Context()
{
    simd::lyra2Avx512Destroy(simd512Ctx_);
    simd::lyra2Avx2Destroy(simdCtx_);
    simd::lyra2Sse2Destroy(simdSse2Ctx_);
    LYRA2_destroy(ctx_);
}

void lyra2WebHash(Lyra2Context& ctx, const uint8_t* data, size_t size, uint32_t tcost, uint8_t out[32])
{
    LYRA2(ctx.handle(), out, 32, data, static_cast<int32_t>(size), tcost);
}

const char* lyra2WebActiveBackendName()
{
    const auto features = simd::cpuFeatures();
    const Lyra2Backend envOverride = envLyraBackendOverride();
    const Lyra2Backend backend = envOverride != Lyra2Backend::Auto ? envOverride : effectiveLyraBackend(features);
    if (backend == Lyra2Backend::Scalar)
        return "scalar";
    if (backend == Lyra2Backend::Sse2 && features.sse2)
        return "SSE2 2-way";
    if (backend == Lyra2Backend::Avx2 && features.avx2)
        return "AVX2 4-way";
    if (backend == Lyra2Backend::Avx512 && features.avx512f)
        return "AVX-512 8-way";
    return "scalar";
}

size_t lyra2WebSimdLanes(const Lyra2Context& ctx)
{
    if (ctx.simd512Handle())
        return 8;
    if (ctx.simdHandle())
        return 4;
    if (ctx.simdSse2Handle())
        return 2;
    return 1;
}

bool lyra2WebSelectBackend(const std::string& name, std::string& error)
{
    Lyra2Backend parsed = Lyra2Backend::Auto;
    if (!parseLyraBackendName(name, parsed)) {
        error = "unknown Lyra2 backend '" + name + "' (expected auto, scalar, sse2, avx2 or avx512)";
        return false;
    }
    const auto features = simd::cpuFeatures();
    if (parsed != Lyra2Backend::Auto && !backendSupported(parsed, features)) {
        error = std::string("Lyra2 backend '") + backendName(parsed) + "' is not available on this CPU";
        return false;
    }
    selectedLyraBackend = parsed;
    return true;
}

namespace {

// Big-endian comparison of the Lyra2 hash against the little-endian target,
// exactly mirroring Webchain/XMRig semantics (see lyra2web.c in the
// repository root for the original derivation).
bool lyra2WebFullTest(const uint8_t hash[32], const uint8_t target[8])
{
    uint64_t hb = util::swab64(util::le64dec(hash));
    uint64_t tb = util::le64dec(target);
    return hb <= tb;
}

uint64_t nonceSpanCount(uint64_t first, uint64_t last)
{
    if (last < first)
        return 0;
    const uint64_t distance = last - first;
    return distance == UINT64_MAX ? UINT64_MAX : distance + 1;
}

} // namespace

bool scanHashLyra2Web(Lyra2Context& ctx, std::vector<uint8_t>& blob, uint32_t tcost,
                       const uint8_t target[8], uint64_t maxNonce, uint64_t& nonceInOut,
                       std::atomic<bool>& restart, uint64_t& hashesDone, uint8_t resultHash[32])
{
    if (blob.size() < 8)
        throw std::runtime_error("Webchain job blob is smaller than the 8-byte nonce field");

    if (nonceInOut > maxNonce) {
        hashesDone = 0;
        return false;
    }

    uint64_t n = nonceInOut - 1;
    const uint64_t firstNonce = nonceInOut;
    uint8_t* noncePtr = blob.data() + blob.size() - 8;
    uint8_t hash[32];

    if ((tcost == 1 || tcost == 4) &&
        (ctx.simd512Handle() || ctx.simdHandle() || ctx.simdSse2Handle())) {
        const uint64_t first = nonceInOut;
        uint64_t current = nonceInOut;
        const size_t batch = ctx.simd512Handle() ? 8 : (ctx.simdHandle() ? 4 : 2);
        uint64_t lastTried = first;
        while (current <= maxNonce) {
            const uint64_t remaining = maxNonce - current + 1;
            const uint64_t lanes = remaining < batch ? remaining : batch;
            uint8_t hashes[8][32]{};
            if (ctx.simd512Handle())
                simd::lyra2Avx512Hash8(*ctx.simd512Handle(), blob.data(), blob.size(), current, tcost, hashes);
            else if (ctx.simdHandle())
                simd::lyra2Avx2Hash4(*ctx.simdHandle(), blob.data(), blob.size(), current, tcost, hashes);
            else
                simd::lyra2Sse2Hash2(*ctx.simdSse2Handle(), blob.data(), blob.size(), current, tcost, hashes);
            for (uint64_t lane = 0; lane < lanes; ++lane) {
                if (lyra2WebFullTest(hashes[lane], target)) {
                    const uint64_t winningNonce = current + lane;
                    std::memcpy(noncePtr, &winningNonce, sizeof(winningNonce));
                    nonceInOut = winningNonce;
                    hashesDone = nonceSpanCount(first, winningNonce);
                    std::memcpy(resultHash, hashes[lane], 32);
                    return true;
                }
            }
            lastTried = current + lanes - 1;
            if (lanes == remaining || restart.load(std::memory_order_relaxed))
                break;
            current += lanes;
        }
        nonceInOut = lastTried;
        hashesDone = nonceSpanCount(first, lastTried);
        return false;
    }

    do {
        n++;
        std::memcpy(noncePtr, &n, 8);
        lyra2WebHash(ctx, blob.data(), blob.size(), tcost, hash);

        if (lyra2WebFullTest(hash, target)) {
            nonceInOut = n;
            hashesDone = nonceSpanCount(firstNonce, n);
            std::memcpy(resultHash, hash, 32);
            return true;
        }
    } while (n < maxNonce && !restart.load(std::memory_order_relaxed));

    nonceInOut = n;
    hashesDone = n - firstNonce + 1;
    return false;
}

namespace {

// Webchain reference test vector, copied from mintme-com/miner
// (src/crypto/Lyra2_test.h) / the repository root's lyra2web_test_data.c.
const uint8_t kTestInput[76] = {
    0x03, 0x05, 0xA0, 0xDB, 0xD6, 0xBF, 0x05, 0xCF, 0x16, 0xE5, 0x03, 0xF3, 0xA6, 0x6F, 0x78, 0x00,
    0x7C, 0xBF, 0x34, 0x14, 0x43, 0x32, 0xEC, 0xBF, 0xC2, 0x2E, 0xD9, 0x5C, 0x87, 0x00, 0x38, 0x3B,
    0x30, 0x9A, 0xCE, 0x19, 0x23, 0xA0, 0x96, 0x4B, 0x00, 0x00, 0x00, 0x08, 0xBA, 0x93, 0x9A, 0x62,
    0x72, 0x4C, 0x0D, 0x75, 0x81, 0xFC, 0xE5, 0x76, 0x1E, 0x9D, 0x8A, 0x0E, 0x6A, 0x1C, 0x3F, 0x92,
    0x4F, 0xDD, 0x84, 0x93, 0xD1, 0x11, 0x56, 0x49, 0xC0, 0x5E, 0xB6, 0x01,
};

// timeCost = 4 (lyra2-webchain, legacy)
const uint8_t kTestOutputTcost4[32] = {
    0x76, 0x98, 0xA3, 0xE1, 0x1C, 0x42, 0x91, 0x51, 0x6A, 0x7F, 0xD7, 0x3C, 0x4B, 0x83, 0x8B, 0x4D,
    0xC5, 0x42, 0xF8, 0xB1, 0xE5, 0x57, 0x67, 0x90, 0x7B, 0x9F, 0x0E, 0xA2, 0x58, 0x34, 0x9D, 0xFA,
};

// timeCost = 1 (lyra2v2-webchain, post hard-fork)
const uint8_t kTestOutputTcost1[32] = {
    0x74, 0x66, 0x24, 0x8F, 0xBD, 0x1A, 0x45, 0x0B, 0x84, 0x07, 0x8E, 0x0E, 0x1F, 0xA2, 0xE0, 0xCD,
    0x4E, 0x4F, 0x69, 0x76, 0xA8, 0x8D, 0xCD, 0xA7, 0xBC, 0x68, 0xD0, 0x7E, 0x8B, 0xB0, 0xCB, 0x89,
};

} // namespace

bool lyra2WebSelfTest()
{
    Lyra2Context ctx;
    uint8_t hash[32];

    lyra2WebHash(ctx, kTestInput, sizeof(kTestInput), 4, hash);
    if (std::memcmp(hash, kTestOutputTcost4, 32) != 0)
        return false;

    lyra2WebHash(ctx, kTestInput, sizeof(kTestInput), 1, hash);
    if (std::memcmp(hash, kTestOutputTcost1, 32) != 0)
        return false;

    if (ctx.simd512Handle() || ctx.simdHandle() || ctx.simdSse2Handle()) {
        uint8_t simdHashes[8][32];
        uint8_t laneBlob[sizeof(kTestInput)];
        const uint64_t lanes = ctx.simd512Handle() ? 8 : (ctx.simdHandle() ? 4 : 2);
        for (uint32_t tcost : {1u, 4u}) {
            if (ctx.simd512Handle())
                simd::lyra2Avx512Hash8(*ctx.simd512Handle(), kTestInput, sizeof(kTestInput), 0, tcost, simdHashes);
            else if (ctx.simdHandle())
                simd::lyra2Avx2Hash4(*ctx.simdHandle(), kTestInput, sizeof(kTestInput), 0, tcost, simdHashes);
            else
                simd::lyra2Sse2Hash2(*ctx.simdSse2Handle(), kTestInput, sizeof(kTestInput), 0, tcost, simdHashes);
            for (uint64_t lane = 0; lane < lanes; ++lane) {
                std::memcpy(laneBlob, kTestInput, sizeof(laneBlob));
                std::memcpy(laneBlob + sizeof(laneBlob) - sizeof(uint64_t), &lane, sizeof(lane));
                lyra2WebHash(ctx, laneBlob, sizeof(laneBlob), tcost, hash);
                if (std::memcmp(hash, simdHashes[lane], 32) != 0)
                    return false;
            }
        }
    }

    return true;
}

namespace {

const uint8_t kBenchBlob[76] = {
    0x03, 0x05, 0xA0, 0xDB, 0xD6, 0xBF, 0x05, 0xCF, 0x16, 0xE5, 0x03, 0xF3, 0xA6, 0x6F, 0x78, 0x00,
    0x7C, 0xBF, 0x34, 0x14, 0x43, 0x32, 0xEC, 0xBF, 0xC2, 0x2E, 0xD9, 0x5C, 0x87, 0x00, 0x38, 0x3B,
    0x30, 0x9A, 0xCE, 0x19, 0x23, 0xA0, 0x96, 0x4B, 0x00, 0x00, 0x00, 0x08, 0xBA, 0x93, 0x9A, 0x62,
    0x72, 0x4C, 0x0D, 0x75, 0x81, 0xFC, 0xE5, 0x76, 0x1E, 0x9D, 0x8A, 0x0E, 0x6A, 0x1C, 0x3F, 0x92,
    0x4F, 0xDD, 0x84, 0x93, 0xD1, 0x11, 0x56, 0x49, 0xC0, 0x5E, 0xB6, 0x01,
};

void pushBenchResult(std::vector<BackendBenchResult>& results, const char* name, uint64_t totalHashes, double elapsed)
{
    results.push_back({name, elapsed > 0.0 ? double(totalHashes) / elapsed : 0.0});
}

void benchmarkScalarLyra(std::vector<BackendBenchResult>& results, uint32_t tcost, double seconds)
{
    Lyra2Context ctx;
    std::vector<uint8_t> blob(std::begin(kBenchBlob), std::end(kBenchBlob));
    uint8_t hash[32];
    uint64_t nonce = 0;
    uint64_t totalHashes = 0;
    auto t0 = std::chrono::steady_clock::now();
    double elapsed = 0.0;
    while (elapsed < seconds) {
        std::memcpy(blob.data() + blob.size() - sizeof(uint64_t), &nonce, sizeof(nonce));
        lyra2WebHash(ctx, blob.data(), blob.size(), tcost, hash);
        ++nonce;
        ++totalHashes;
        elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    }
    pushBenchResult(results, "scalar", totalHashes, elapsed);
}

} // namespace

std::vector<BackendBenchResult> lyra2WebBenchmarkBackends(double secondsPerBackend, uint32_t tcost)
{
    std::vector<BackendBenchResult> results;
    const auto features = simd::cpuFeatures();

    benchmarkScalarLyra(results, tcost, secondsPerBackend);

    if (features.sse2) {
        simd::Lyra2Sse2Context* raw = simd::lyra2Sse2Create();
        if (raw) {
            uint8_t out[2][32];
            uint64_t nonce = 0;
            uint64_t totalHashes = 0;
            auto t0 = std::chrono::steady_clock::now();
            double elapsed = 0.0;
            while (elapsed < secondsPerBackend) {
                simd::lyra2Sse2Hash2(*raw, kBenchBlob, sizeof(kBenchBlob), nonce, tcost, out);
                nonce += 2;
                totalHashes += 2;
                elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            }
            simd::lyra2Sse2Destroy(raw);
            pushBenchResult(results, "SSE2 2-way", totalHashes, elapsed);
        }
    }

    if (features.avx2) {
        simd::Lyra2Avx2Context* raw = simd::lyra2Avx2Create();
        if (raw) {
            uint8_t out[4][32];
            uint64_t nonce = 0;
            uint64_t totalHashes = 0;
            auto t0 = std::chrono::steady_clock::now();
            double elapsed = 0.0;
            while (elapsed < secondsPerBackend) {
                simd::lyra2Avx2Hash4(*raw, kBenchBlob, sizeof(kBenchBlob), nonce, tcost, out);
                nonce += 4;
                totalHashes += 4;
                elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            }
            simd::lyra2Avx2Destroy(raw);
            pushBenchResult(results, "AVX2 4-way", totalHashes, elapsed);
        }
    }

    if (features.avx512f) {
        simd::Lyra2Avx512Context* raw = simd::lyra2Avx512Create();
        if (raw) {
            uint8_t out[8][32];
            uint64_t nonce = 0;
            uint64_t totalHashes = 0;
            auto t0 = std::chrono::steady_clock::now();
            double elapsed = 0.0;
            while (elapsed < secondsPerBackend) {
                simd::lyra2Avx512Hash8(*raw, kBenchBlob, sizeof(kBenchBlob), nonce, tcost, out);
                nonce += 8;
                totalHashes += 8;
                elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            }
            simd::lyra2Avx512Destroy(raw);
            pushBenchResult(results, "AVX-512 8-way", totalHashes, elapsed);
        }
    }

    return results;
}

} // namespace cppminer::algo
