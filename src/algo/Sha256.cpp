#include "Sha256.h"

#include "../ByteUtils.h"
#include "../simd/CpuFeatures.h"
#include "../simd/Sha256Simd.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>

namespace cppminer::algo {

Sha256::Sha256()
{
    ctx_ = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr);
}

Sha256::~Sha256()
{
    EVP_MD_CTX_free(ctx_);
}

Sha256::Sha256(const Sha256& other)
{
    ctx_ = EVP_MD_CTX_new();
    EVP_MD_CTX_copy_ex(ctx_, other.ctx_);
}

Sha256& Sha256::operator=(const Sha256& other)
{
    if (this != &other)
        EVP_MD_CTX_copy_ex(ctx_, other.ctx_);
    return *this;
}

void Sha256::update(const uint8_t* data, size_t len)
{
    EVP_DigestUpdate(ctx_, data, len);
}

void Sha256::finalize(uint8_t out[32])
{
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx_, out, &len);
}

void Sha256::hash(const uint8_t* data, size_t len, uint8_t out[32])
{
    Sha256 h;
    h.update(data, len);
    h.finalize(out);
}

void Sha256::hash256d(const uint8_t* data, size_t len, uint8_t out[32])
{
    uint8_t tmp[32];
    hash(data, len, tmp);
    hash(tmp, 32, out);
}

namespace {

using namespace simd;

using SingleLaneTransform = void (*)(uint32_t[8], const uint8_t[64]);
using NwayTransform4 = void (*)(uint32_t[4 * 8], const uint32_t[4 * 16]);
using NwayTransform8 = void (*)(uint32_t[8 * 8], const uint32_t[8 * 16]);
using NwayTransform16 = void (*)(uint32_t[16 * 8], const uint32_t[16 * 16]);

enum class Sha256Backend { Auto, Scalar, Sse2, Avx2, Avx512, ShaNi };

Sha256Backend selectedBackend = Sha256Backend::Auto;

Sha256Backend automaticBackend(const CpuFeatures& feat)
{
    if (feat.sha)
        return Sha256Backend::ShaNi;
    if (feat.avx512f)
        return Sha256Backend::Avx512;
    if (feat.avx2)
        return Sha256Backend::Avx2;
    if (feat.sse2)
        return Sha256Backend::Sse2;
    return Sha256Backend::Scalar;
}

bool backendSupported(Sha256Backend backend, const CpuFeatures& feat)
{
    switch (backend) {
    case Sha256Backend::Auto:
    case Sha256Backend::Scalar:
        return true;
    case Sha256Backend::Sse2:
        return feat.sse2;
    case Sha256Backend::Avx2:
        return feat.avx2;
    case Sha256Backend::Avx512:
        return feat.avx512f;
    case Sha256Backend::ShaNi:
        return feat.sha;
    }
    return false;
}

const char* backendName(Sha256Backend backend)
{
    switch (backend) {
    case Sha256Backend::Auto:
        return "auto";
    case Sha256Backend::Scalar:
        return "scalar";
    case Sha256Backend::Sse2:
        return "SSE2 (4-way)";
    case Sha256Backend::Avx2:
        return "AVX2 (8-way)";
    case Sha256Backend::Avx512:
        return "AVX-512 (16-way)";
    case Sha256Backend::ShaNi:
        return "SHA-NI";
    }
    return "unknown";
}

// Builds the fixed (non-nonce) parts of sha256d's second 64-byte block:
// header[64,76) (12 bytes carried over from the first block) followed by
// the standard single-block SHA-256 padding for an 80-byte message.
// Bytes [12,16) (the nonce) are left as-is for the caller to fill in.
void buildBlock2Template(uint8_t block2[64], const uint8_t header[80])
{
    std::memset(block2, 0, 64);
    std::memcpy(block2, header + 64, 12);
    block2[16] = 0x80;
    util::be32enc(block2 + 60, 640); // bit length of the 80-byte header
}

// Builds the fixed parts of the outer sha256d block (padding a 32-byte
// digest to one block); bytes [0,32) (the inner digest) are left for the
// caller to fill in.
void buildBlock3Template(uint8_t block3[64])
{
    std::memset(block3, 0, 64);
    block3[32] = 0x80;
    util::be32enc(block3 + 60, 256); // bit length of a 32-byte digest
}

// Single-lane scan: used for the scalar fallback and for SHA-NI, which is
// hardware-accelerated but not itself "batched" across nonces.
bool scanSingleLane(SingleLaneTransform transform, uint8_t header[80], const uint32_t target[8], uint32_t maxNonce,
                     uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone)
{
    uint32_t midstate[8];
    std::memcpy(midstate, kSha256InitState, sizeof(midstate));
    transform(midstate, header);

    uint8_t block2[64];
    buildBlock2Template(block2, header);
    uint8_t block3[64];
    buildBlock3Template(block3);

    const uint32_t firstNonce = nonceInOut;
    uint32_t n = firstNonce;

    for (;;) {
        util::be32enc(block2 + 12, n);
        uint32_t state1[8];
        std::memcpy(state1, midstate, sizeof(state1));
        transform(state1, block2);

        for (int k = 0; k < 8; k++)
            util::be32enc(block3 + 4 * k, state1[k]);
        uint32_t state2[8];
        std::memcpy(state2, kSha256InitState, sizeof(state2));
        transform(state2, block3);

        uint32_t cmp[8];
        for (int k = 0; k < 8; k++)
            cmp[k] = util::swab32(state2[k]);
        if (util::fullTest(cmp, target)) {
            nonceInOut = n;
            hashesDone = uint64_t(n) - firstNonce + 1;
            return true;
        }

        if (n >= maxNonce || restart.load(std::memory_order_relaxed)) {
            nonceInOut = n;
            hashesDone = uint64_t(n) - firstNonce + 1;
            return false;
        }
        n++;
    }
}

// N-way batched scan, shared by the SSE2 (N=4) and AVX2 (N=8) backends.
template <int N, typename NwayTransform>
bool scanNway(NwayTransform transform, uint8_t header[80], const uint32_t target[8], uint32_t maxNonce,
              uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone)
{
    uint32_t midstate[8];
    std::memcpy(midstate, kSha256InitState, sizeof(midstate));
    sha256TransformScalar(midstate, header);

    uint8_t block2Template[64];
    buildBlock2Template(block2Template, header);
    uint8_t block3Template[64];
    buildBlock3Template(block3Template);

    // Word-major/lane-minor buffers, broadcasting the lane-invariant parts
    // once up front; only the nonce word (word 3 of block2) and the inner
    // digest words (0..7 of block3) change per batch.
    uint32_t state1[N * 8];
    uint32_t blocks2[N * 16];
    uint32_t blocks3[N * 16];
    uint32_t stateOut[N * 8];
    for (int lane = 0; lane < N; lane++) {
        for (int w = 0; w < 8; w++)
            state1[w * N + lane] = midstate[w];
        for (int w = 0; w < 16; w++)
            blocks2[w * N + lane] = util::be32dec(block2Template + 4 * w);
        for (int w = 0; w < 16; w++)
            blocks3[w * N + lane] = util::be32dec(block3Template + 4 * w);
    }

    const uint32_t firstNonce = nonceInOut;
    uint32_t n = firstNonce;

    for (;;) {
        for (int lane = 0; lane < N; lane++)
            blocks2[3 * N + lane] = n + uint32_t(lane);

        uint32_t s1[N * 8];
        std::memcpy(s1, state1, sizeof(s1));
        transform(s1, blocks2);

        uint32_t b3[N * 16];
        std::memcpy(b3, blocks3, sizeof(b3));
        for (int lane = 0; lane < N; lane++)
            for (int w = 0; w < 8; w++)
                b3[w * N + lane] = s1[w * N + lane];

        for (int lane = 0; lane < N; lane++)
            for (int w = 0; w < 8; w++)
                stateOut[w * N + lane] = kSha256InitState[w];
        transform(stateOut, b3);

        for (int lane = 0; lane < N; lane++) {
            uint32_t nonce = n + uint32_t(lane);
            if (nonce > maxNonce)
                break;
            uint32_t cmp[8];
            for (int w = 0; w < 8; w++)
                cmp[w] = util::swab32(stateOut[w * N + lane]);
            if (util::fullTest(cmp, target)) {
                nonceInOut = nonce;
                hashesDone = uint64_t(nonce) - firstNonce + 1;
                return true;
            }
        }

        uint64_t batchEnd = std::min<uint64_t>(uint64_t(n) + N - 1, uint64_t(maxNonce));
        bool exhausted = uint64_t(n) + N - 1 >= maxNonce;
        bool restarted = restart.load(std::memory_order_relaxed);
        if (exhausted || restarted) {
            nonceInOut = uint32_t(batchEnd);
            hashesDone = batchEnd - firstNonce + 1;
            return false;
        }
        n += N;
    }
}

} // namespace

bool scanHashSha256d(uint8_t header[80], const uint32_t target[8], uint32_t maxNonce,
                      uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone)
{
    const CpuFeatures& feat = cpuFeatures();
    // Auto retains the conservative historical priority; explicit selection
    // is validated by sha256SelectBackend() before worker threads start.
    const Sha256Backend backend = selectedBackend == Sha256Backend::Auto ? automaticBackend(feat) : selectedBackend;
    switch (backend) {
    case Sha256Backend::ShaNi:
        return scanSingleLane(sha256TransformShani, header, target, maxNonce, nonceInOut, restart, hashesDone);
    case Sha256Backend::Avx512:
        return scanNway<16>(static_cast<NwayTransform16>(sha256Transform16way), header, target, maxNonce, nonceInOut,
                            restart, hashesDone);
    case Sha256Backend::Avx2:
        return scanNway<8>(static_cast<NwayTransform8>(sha256Transform8way), header, target, maxNonce, nonceInOut,
                            restart, hashesDone);
    case Sha256Backend::Sse2:
        return scanNway<4>(static_cast<NwayTransform4>(sha256Transform4way), header, target, maxNonce, nonceInOut,
                            restart, hashesDone);
    case Sha256Backend::Auto:
    case Sha256Backend::Scalar:
        return scanSingleLane(sha256TransformScalar, header, target, maxNonce, nonceInOut, restart, hashesDone);
    }
    return false;
}

bool sha256SelectBackend(const std::string& name, std::string& error)
{
    std::string key = name;
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    Sha256Backend requested;
    if (key == "auto")
        requested = Sha256Backend::Auto;
    else if (key == "scalar")
        requested = Sha256Backend::Scalar;
    else if (key == "sse2")
        requested = Sha256Backend::Sse2;
    else if (key == "avx2")
        requested = Sha256Backend::Avx2;
    else if (key == "avx512" || key == "avx-512")
        requested = Sha256Backend::Avx512;
    else if (key == "sha-ni" || key == "shani")
        requested = Sha256Backend::ShaNi;
    else {
        error = "unknown sha256 backend '" + name + "' (expected auto, scalar, sse2, avx2, avx512 or sha-ni)";
        return false;
    }

    const CpuFeatures& feat = cpuFeatures();
    if (!backendSupported(requested, feat)) {
        error = "sha256 backend '" + name + "' is not supported by this CPU";
        return false;
    }
    selectedBackend = requested;
    return true;
}

const char* sha256ActiveBackendName()
{
    const CpuFeatures& feat = cpuFeatures();
    const Sha256Backend active = selectedBackend == Sha256Backend::Auto ? automaticBackend(feat) : selectedBackend;
    return backendName(active);
}

namespace {

// Small deterministic PRNG (xorshift32) - good enough to generate varied
// self-test inputs without depending on <random>'s heavier machinery.
uint32_t xorshift32(uint32_t& state)
{
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

void fillRandom(uint32_t& seed, uint8_t* out, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = static_cast<uint8_t>(xorshift32(seed));
}

bool bytesEqual(const uint8_t* a, const uint8_t* b, size_t len)
{
    return std::memcmp(a, b, len) == 0;
}

// SHA-256("abc"), the standard NIST/FIPS-180 example vector: verifies the
// scalar transform (the oracle every other backend below is checked
// against) is itself actually correct, not just internally consistent.
bool testAbcVector()
{
    uint8_t block[64];
    std::memset(block, 0, 64);
    block[0] = 'a';
    block[1] = 'b';
    block[2] = 'c';
    block[3] = 0x80;
    util::be32enc(block + 60, 24);

    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };

    uint32_t state[8];
    std::memcpy(state, kSha256InitState, sizeof(state));
    sha256TransformScalar(state, block);
    uint8_t digest[32];
    for (int i = 0; i < 8; i++)
        util::be32enc(digest + 4 * i, state[i]);
    return bytesEqual(digest, expected, 32);
}

// Cross-checks a single-lane transform against the (already NIST-verified)
// scalar one over many random (state, block) pairs.
bool testSingleLaneAgainstScalar(SingleLaneTransform transform, uint32_t& seed)
{
    for (int iter = 0; iter < 200; iter++) {
        uint32_t stateA[8], stateB[8];
        uint8_t seedState[32];
        fillRandom(seed, seedState, 32);
        std::memcpy(stateA, seedState, 32);
        std::memcpy(stateB, seedState, 32);
        uint8_t block[64];
        fillRandom(seed, block, 64);

        sha256TransformScalar(stateA, block);
        transform(stateB, block);
        if (!bytesEqual(reinterpret_cast<uint8_t*>(stateA), reinterpret_cast<uint8_t*>(stateB), 32))
            return false;
    }
    return true;
}

template <int N, typename NwayTransform>
bool testNwayAgainstScalar(NwayTransform transform, uint32_t& seed)
{
    for (int iter = 0; iter < 100; iter++) {
        uint32_t scalarState[N][8];
        uint8_t blocks[N][64];
        uint32_t wayState[N * 8];
        uint32_t wayBlocks[N * 16];

        for (int lane = 0; lane < N; lane++) {
            uint8_t seedState[32];
            fillRandom(seed, seedState, 32);
            std::memcpy(scalarState[lane], seedState, 32);
            fillRandom(seed, blocks[lane], 64);
            for (int w = 0; w < 8; w++)
                wayState[w * N + lane] = scalarState[lane][w];
            for (int w = 0; w < 16; w++)
                wayBlocks[w * N + lane] = util::be32dec(blocks[lane] + 4 * w);
        }

        for (int lane = 0; lane < N; lane++)
            sha256TransformScalar(scalarState[lane], blocks[lane]);
        transform(wayState, wayBlocks);

        for (int lane = 0; lane < N; lane++)
            for (int w = 0; w < 8; w++)
                if (wayState[w * N + lane] != scalarState[lane][w])
                    return false;
    }
    return true;
}

// End-to-end check of the real scanHashSha256d() (batching, padding and
// all) against OpenSSL's independently-implemented sha256d. `fullTest`'s
// semantics are "<=", not "==", so an arbitrary nonce upstream of the one
// a naively-picked target was derived from has a roughly 50% chance of
// satisfying it purely by chance - forcing one specific nonce to "win"
// isn't reliable. Instead this brute-forces the same range with the
// trusted oracle, in nonce order, to find whichever nonce a correct
// implementation MUST report first, then checks the real scan agrees -
// this still exercises every lane position of an N-way batch (whichever
// nonce ends up winning lands in a different lane each trial).
bool testScanIntegration(uint32_t& seed)
{
    for (int trial = 0; trial < 4; trial++) {
        uint8_t header[80];
        fillRandom(seed, header, 80);
        uint32_t baseNonce = xorshift32(seed) & 0x00ffffffu;
        uint32_t maxNonce = baseNonce + 15; // spans a full AVX-512 (16-way) batch

        auto hashForNonce = [&](uint32_t n, uint8_t digest[32]) {
            uint8_t h[80];
            std::memcpy(h, header, 80);
            util::be32enc(h + 76, n);
            Sha256::hash256d(h, 80, digest);
        };

        // Deriving the target from maxNonce's own digest guarantees at
        // least maxNonce satisfies fullTest(), so the brute-force search
        // below always terminates with a definite expected answer.
        uint8_t lastDigest[32];
        hashForNonce(maxNonce, lastDigest);
        uint32_t target[8];
        for (int k = 0; k < 8; k++)
            target[k] = util::le32dec(lastDigest + 4 * k);

        uint32_t expectedNonce = maxNonce;
        for (uint32_t n = baseNonce; n <= maxNonce; n++) {
            uint8_t digest[32];
            hashForNonce(n, digest);
            uint32_t cmp[8];
            for (int k = 0; k < 8; k++)
                cmp[k] = util::le32dec(digest + 4 * k);
            if (util::fullTest(cmp, target)) {
                expectedNonce = n;
                break;
            }
        }

        uint32_t nonce = baseNonce;
        std::atomic<bool> restart{false};
        uint64_t hashesDone = 0;
        bool found = scanHashSha256d(header, target, maxNonce, nonce, restart, hashesDone);
        if (!found || nonce != expectedNonce)
            return false;
    }
    return true;
}

} // namespace

bool sha256SimdSelfTest()
{
    if (!testAbcVector())
        return false;

    uint32_t seed = 0x9e3779b9u;
    const CpuFeatures& feat = cpuFeatures();

    if (!testSingleLaneAgainstScalar(sha256TransformScalar, seed))
        return false;
    if (feat.sha && !testSingleLaneAgainstScalar(sha256TransformShani, seed))
        return false;
    if (feat.sse2 &&
        !testNwayAgainstScalar<4>(static_cast<NwayTransform4>(sha256Transform4way), seed))
        return false;
    if (feat.avx2 &&
        !testNwayAgainstScalar<8>(static_cast<NwayTransform8>(sha256Transform8way), seed))
        return false;
    if (feat.avx512f &&
        !testNwayAgainstScalar<16>(static_cast<NwayTransform16>(sha256Transform16way), seed))
        return false;

    if (!testScanIntegration(seed))
        return false;

    return true;
}

namespace {

// Runs one backend for roughly `seconds`, accumulating hashesDone across
// as many scanXxx() batches as it takes, and records the resulting real
// sha256d hash rate.
template <typename ScanFn>
void benchmarkOneBackend(std::vector<BackendBenchResult>& results, const char* name, uint8_t header[80],
                          const uint32_t target[8], double seconds, ScanFn&& scan)
{
    std::atomic<bool> restart{false};
    uint32_t nonce = 0;
    uint64_t totalHashes = 0;
    auto t0 = std::chrono::steady_clock::now();
    double elapsed = 0.0;
    while (elapsed < seconds) {
        uint64_t hashesDone = 0;
        uint32_t maxNonce = nonce + 200000u;
        scan(header, target, maxNonce, nonce, restart, hashesDone);
        totalHashes += hashesDone;
        nonce = maxNonce + 1;
        elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    }
    results.push_back({name, elapsed > 0.0 ? double(totalHashes) / elapsed : 0.0});
}

} // namespace

std::vector<BackendBenchResult> sha256BenchmarkBackends(double secondsPerBackend)
{
    std::vector<BackendBenchResult> results;

    uint8_t header[80];
    uint32_t seed = 0xc0ffeeu;
    fillRandom(seed, header, 80);
    uint32_t target[8] = {0, 0, 0, 0, 0, 0, 0, 0}; // never satisfied - runs the full duration

    const CpuFeatures& feat = cpuFeatures();

    benchmarkOneBackend(results, "scalar", header, target, secondsPerBackend,
                        [](uint8_t h[80], const uint32_t t[8], uint32_t mn, uint32_t& n, std::atomic<bool>& r,
                           uint64_t& hd) { scanSingleLane(sha256TransformScalar, h, t, mn, n, r, hd); });

    if (feat.sse2)
        benchmarkOneBackend(results, "SSE2 (4-way)", header, target, secondsPerBackend,
                            [](uint8_t h[80], const uint32_t t[8], uint32_t mn, uint32_t& n, std::atomic<bool>& r,
                               uint64_t& hd) {
                                scanNway<4>(static_cast<NwayTransform4>(sha256Transform4way), h, t, mn, n, r, hd);
                            });

    if (feat.avx2)
        benchmarkOneBackend(results, "AVX2 (8-way)", header, target, secondsPerBackend,
                            [](uint8_t h[80], const uint32_t t[8], uint32_t mn, uint32_t& n, std::atomic<bool>& r,
                               uint64_t& hd) {
                                scanNway<8>(static_cast<NwayTransform8>(sha256Transform8way), h, t, mn, n, r, hd);
                            });

    if (feat.avx512f)
        benchmarkOneBackend(results, "AVX-512 (16-way)", header, target, secondsPerBackend,
                            [](uint8_t h[80], const uint32_t t[8], uint32_t mn, uint32_t& n, std::atomic<bool>& r,
                               uint64_t& hd) {
                                scanNway<16>(static_cast<NwayTransform16>(sha256Transform16way), h, t, mn, n, r, hd);
                            });

    if (feat.sha)
        benchmarkOneBackend(results, "SHA-NI", header, target, secondsPerBackend,
                            [](uint8_t h[80], const uint32_t t[8], uint32_t mn, uint32_t& n, std::atomic<bool>& r,
                               uint64_t& hd) { scanSingleLane(sha256TransformShani, h, t, mn, n, r, hd); });

    return results;
}

} // namespace cppminer::algo
