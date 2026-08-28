#include "Scrypt.h"

#include "../ByteUtils.h"
#include "../simd/CpuFeatures.h"
#include "../simd/Sha256Simd.h"
#include "../simd/ScryptSimd.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <stdexcept>

namespace cppminer::algo {

using namespace simd;

namespace {

using TransformFn = void (*)(uint32_t[8], const uint8_t[64]);

TransformFn wrapperTransform()
{
    return cpuFeatures().sha ? sha256TransformShani : sha256TransformScalar;
}

// HMAC-SHA256 key setup: header is longer than one block (80 > 64 bytes),
// so per the HMAC definition the effective key is SHA256(header) (32
// bytes, zero-padded to 64 for the ipad/opad xor). tstate/ostate come out
// as the hash state right after consuming just the 64-byte ipad/opad
// block, ready for PBKDF2's per-block continuations below.
void hmacInit(const uint8_t header[80], uint32_t tstate[8], uint32_t ostate[8], TransformFn transform)
{
    uint32_t ihash[8];
    std::memcpy(ihash, kSha256InitState, sizeof(ihash));
    transform(ihash, header);

    uint8_t block2[64];
    std::memset(block2, 0, sizeof(block2));
    std::memcpy(block2, header + 64, 16);
    block2[16] = 0x80;
    util::be32enc(block2 + 60, 640); // bit length of the 80-byte header
    transform(ihash, block2);

    uint8_t ipadBlock[64], opadBlock[64];
    for (int i = 0; i < 8; i++) {
        util::be32enc(ipadBlock + 4 * i, ihash[i] ^ 0x36363636u);
        util::be32enc(opadBlock + 4 * i, ihash[i] ^ 0x5c5c5c5cu);
    }
    for (int i = 8; i < 16; i++) {
        util::be32enc(ipadBlock + 4 * i, 0x36363636u);
        util::be32enc(opadBlock + 4 * i, 0x5c5c5c5cu);
    }

    std::memcpy(ostate, kSha256InitState, 8 * sizeof(uint32_t));
    transform(ostate, opadBlock);
    std::memcpy(tstate, kSha256InitState, 8 * sizeof(uint32_t));
    transform(tstate, ipadBlock);
}

// PBKDF2-HMAC-SHA256(header, header, iterations=1, dkLen=128) -> X[32
// words]. Four PBKDF2 blocks, each one HMAC-SHA256(header, header ||
// BE32(blockIndex)) call; tstate/ostate (after ipad/opad) and the first
// 64 bytes of the inner hash's input (ipad || header[0:64)) are shared
// across all four, mirroring the reference miner's PBKDF2_SHA256_80_128.
void pbkdf2_80_128(const uint32_t tstate[8], const uint32_t ostate[8], const uint8_t header[80], uint32_t X[32],
                    TransformFn transform)
{
    uint32_t istate[8];
    std::memcpy(istate, tstate, sizeof(istate));
    transform(istate, header); // consumes header[0,64)

    uint8_t innerTail[64]; // header[64,80) || BE32(i) || padding(1184 bits total)
    std::memset(innerTail, 0, sizeof(innerTail));
    std::memcpy(innerTail, header + 64, 16);
    innerTail[20] = 0x80;
    util::be32enc(innerTail + 60, 1184); // bits in ipadBlock(64) + header(80) + counter(4)

    uint8_t outerBlock[64]; // innerDigest || padding(768 bits total)
    std::memset(outerBlock, 0, sizeof(outerBlock));
    outerBlock[32] = 0x80;
    util::be32enc(outerBlock + 60, 768); // bits in opadBlock(64) + innerDigest(32)

    for (uint32_t i = 0; i < 4; i++) {
        util::be32enc(innerTail + 16, i + 1);
        uint32_t obuf[8];
        std::memcpy(obuf, istate, sizeof(obuf));
        transform(obuf, innerTail);

        for (int k = 0; k < 8; k++)
            util::be32enc(outerBlock + 4 * k, obuf[k]);
        uint32_t ostate2[8];
        std::memcpy(ostate2, ostate, sizeof(ostate2));
        transform(ostate2, outerBlock);

        // scrypt/Salsa20 treats block words as little-endian, unlike
        // SHA-256's own big-endian convention - swab32 bridges the two,
        // exactly like the reference miner's PBKDF2_SHA256_80_128 does.
        for (int k = 0; k < 8; k++)
            X[8 * i + k] = util::swab32(ostate2[k]);
    }
}

// PBKDF2-HMAC-SHA256(header, X', iterations=1, dkLen=32) -> output[8
// words], the final scrypt digest. X' (32 little-endian words) is
// re-encoded to bytes via le32enc before hashing so the shared transform
// (which always be32dec's its input) sees the correct values - mirroring
// the reference's swap=1 sha256_transform() calls for this step.
void pbkdf2_128_32(const uint32_t tstate[8], const uint32_t ostate[8], const uint32_t saltX[32], uint32_t output[8],
                    TransformFn transform)
{
    uint32_t st[8];
    std::memcpy(st, tstate, sizeof(st));

    uint8_t block[64];
    for (int i = 0; i < 16; i++)
        util::le32enc(block + 4 * i, saltX[i]);
    transform(st, block);
    for (int i = 0; i < 16; i++)
        util::le32enc(block + 4 * i, saltX[16 + i]);
    transform(st, block);

    uint8_t finalBlock[64];
    std::memset(finalBlock, 0, sizeof(finalBlock));
    util::be32enc(finalBlock + 0, 1); // PBKDF2 block-index counter (always 1: dkLen=32 needs one block)
    finalBlock[4] = 0x80;
    util::be32enc(finalBlock + 60, 1568); // bits in ipadBlock(64) + X'(128) + counter(4)
    transform(st, finalBlock);

    uint8_t outerBlock[64];
    std::memset(outerBlock, 0, sizeof(outerBlock));
    for (int i = 0; i < 8; i++)
        util::be32enc(outerBlock + 4 * i, st[i]);
    outerBlock[32] = 0x80;
    util::be32enc(outerBlock + 60, 768);

    uint32_t ost[8];
    std::memcpy(ost, ostate, sizeof(ost));
    transform(ost, outerBlock);

    for (int i = 0; i < 8; i++)
        output[i] = util::swab32(ost[i]);
}

int chooseWidth()
{
    // No hardware-accelerated option exists for scrypt's Salsa20/8 core
    // (unlike sha256d's SHA-NI), so the widest software vector path wins
    // outright here.
    if (cpuFeatures().avx512f)
        return 16;
    if (cpuFeatures().avx2)
        return 8;
    if (cpuFeatures().sse2)
        return 4;
    return 1;
}

void romix(int width, uint32_t* B, uint32_t* scratch, uint32_t costN)
{
    switch (width) {
    case 16:
        scryptRomix16way(B, scratch, costN);
        return;
    case 8:
        scryptRomix8way(B, scratch, costN);
        return;
    case 4:
        scryptRomix4way(B, scratch, costN);
        return;
    default:
        scryptRomixScalar(B, scratch, costN);
        return;
    }
}

} // namespace

ScryptEngine::ScryptEngine(uint32_t costN)
    : costN_(costN), width_(chooseWidth()), scratch_(scryptScratchWords(costN, chooseWidth()))
{
}

void ScryptEngine::hash(const uint8_t header[80], uint8_t output[32])
{
    TransformFn transform = wrapperTransform();
    uint32_t tstate[8], ostate[8];
    hmacInit(header, tstate, ostate, transform);
    uint32_t X[32];
    pbkdf2_80_128(tstate, ostate, header, X, transform);

    // Single-lane hash always uses the scalar ROMix, regardless of this
    // engine's configured batching width, so it can run with any scratch
    // buffer size - callers needing width-1 scratch specifically (e.g.
    // the self-test) pass a throwaway engine.
    std::vector<uint32_t> scratch1(scryptScratchWords(costN_, 1));
    scryptRomixScalar(X, scratch1.data(), costN_);

    uint32_t outWords[8];
    pbkdf2_128_32(tstate, ostate, X, outWords, transform);
    for (int i = 0; i < 8; i++)
        util::le32enc(output + 4 * i, outWords[i]);
}

namespace {

// Shared by scanHashScrypt() (which sources width/scratch/N from a
// ScryptEngine) and the benchmark (which wants to force a specific width
// regardless of what this CPU would actually pick, to compare backends
// side by side).
bool scanHashScryptImpl(int width, uint32_t* scratch, uint32_t costN, uint8_t header[80], const uint32_t target[8],
                         uint32_t maxNonce, uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone)
{
    constexpr int kMaxWidth = 16;
    TransformFn transform = wrapperTransform();

    const uint32_t firstNonce = nonceInOut;
    uint32_t n = firstNonce;

    uint8_t laneHeader[kMaxWidth][80];

    for (;;) {
        uint32_t B[32 * kMaxWidth];
        uint32_t tstateLane[kMaxWidth][8];
        uint32_t ostateLane[kMaxWidth][8];

        for (int lane = 0; lane < width; lane++) {
            std::memcpy(laneHeader[lane], header, 80);
            util::be32enc(laneHeader[lane] + 76, n + uint32_t(lane));

            hmacInit(laneHeader[lane], tstateLane[lane], ostateLane[lane], transform);
            uint32_t X[32];
            pbkdf2_80_128(tstateLane[lane], ostateLane[lane], laneHeader[lane], X, transform);
            for (int w = 0; w < 32; w++)
                B[w * width + lane] = X[w];
        }

        romix(width, B, scratch, costN);

        for (int lane = 0; lane < width; lane++) {
            uint32_t nonce = n + uint32_t(lane);
            if (nonce > maxNonce)
                break;

            uint32_t X[32];
            for (int w = 0; w < 32; w++)
                X[w] = B[w * width + lane];
            uint32_t outWords[8];
            pbkdf2_128_32(tstateLane[lane], ostateLane[lane], X, outWords, transform);

            if (util::fullTest(outWords, target)) {
                nonceInOut = nonce;
                hashesDone = uint64_t(nonce) - firstNonce + 1;
                return true;
            }
        }

        uint64_t batchEnd = std::min<uint64_t>(uint64_t(n) + width - 1, uint64_t(maxNonce));
        bool exhausted = uint64_t(n) + width - 1 >= maxNonce;
        bool restarted = restart.load(std::memory_order_relaxed);
        if (exhausted || restarted) {
            nonceInOut = uint32_t(batchEnd);
            hashesDone = batchEnd - firstNonce + 1;
            return false;
        }
        n += uint32_t(width);
    }
}

} // namespace

bool scanHashScrypt(ScryptEngine& engine, uint8_t header[80], const uint32_t target[8], uint32_t maxNonce,
                     uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone)
{
    return scanHashScryptImpl(engine.width(), engine.scratch(), engine.costN(), header, target, maxNonce, nonceInOut,
                               restart, hashesDone);
}

const char* scryptActiveBackendName()
{
    switch (chooseWidth()) {
    case 16:
        return "AVX-512 (16-way)";
    case 8:
        return "AVX2 (8-way)";
    case 4:
        return "SSE2 (4-way)";
    default:
        return "scalar";
    }
}

namespace {

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

// OpenSSL's mature, independently-implemented SCRYPT KDF, used purely as
// the correctness oracle below - never on the mining hot path.
void opensslScryptReference(const uint8_t header[80], uint32_t costN, uint8_t output[32])
{
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "SCRYPT", nullptr);
    if (!kdf)
        throw std::runtime_error("OpenSSL: the SCRYPT KDF is not available");
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx) {
        EVP_KDF_free(kdf);
        throw std::runtime_error("EVP_KDF_CTX_new failed");
    }

    uint64_t n = costN, r = 1, p = 1;
    uint64_t maxMem = 1ull << 30;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<uint8_t*>(header), 80),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(header), 80),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_R, &r),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_P, &p),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxMem),
        OSSL_PARAM_construct_end(),
    };
    bool ok = EVP_KDF_derive(ctx, output, 32, params) == 1;
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    if (!ok)
        throw std::runtime_error("EVP_KDF_derive (scrypt) failed");
}

bool testEngineAgainstOpenssl(uint32_t costN, int iterations, uint32_t& seed)
{
    for (int iter = 0; iter < iterations; iter++) {
        uint8_t header[80];
        fillRandom(seed, header, 80);

        uint8_t expected[32];
        opensslScryptReference(header, costN, expected);

        ScryptEngine engine(costN);
        uint8_t got[32];
        engine.hash(header, got);

        if (std::memcmp(expected, got, 32) != 0)
            return false;
    }
    return true;
}

// Cross-checks a batched ROMix backend against the scalar one over
// several random W-lane batches.
bool testRomixAgainstScalar(int width, uint32_t costN, uint32_t& seed)
{
    constexpr int kMaxWidth = 16;
    for (int iter = 0; iter < 5; iter++) {
        uint32_t scalarX[kMaxWidth][32];
        uint32_t batched[32 * kMaxWidth];
        for (int lane = 0; lane < width; lane++) {
            uint8_t bytes[128];
            fillRandom(seed, bytes, 128);
            for (int w = 0; w < 32; w++) {
                scalarX[lane][w] = util::le32dec(bytes + 4 * w);
                batched[w * width + lane] = scalarX[lane][w];
            }
        }

        std::vector<uint32_t> scratchScalar(scryptScratchWords(costN, 1));
        for (int lane = 0; lane < width; lane++)
            scryptRomixScalar(scalarX[lane], scratchScalar.data(), costN);

        std::vector<uint32_t> scratchWide(scryptScratchWords(costN, width));
        romix(width, batched, scratchWide.data(), costN);

        for (int lane = 0; lane < width; lane++)
            for (int w = 0; w < 32; w++)
                if (batched[w * width + lane] != scalarX[lane][w])
                    return false;
    }
    return true;
}

// End-to-end check of the real scanHashScrypt() against OpenSSL's scrypt.
// Uses the same "brute-force the trusted oracle in nonce order to learn
// the expected winner" strategy as the sha256d self-test's
// testScanIntegration() - see its comment for why forcing one specific
// nonce to win via an arbitrarily-picked target isn't reliable, since
// fullTest() is a "<=" comparison.
bool testScanIntegration(uint32_t costN, uint32_t& seed)
{
    ScryptEngine engine(costN);
    for (int trial = 0; trial < 4; trial++) {
        uint8_t header[80];
        fillRandom(seed, header, 80);
        uint32_t baseNonce = xorshift32(seed) & 0x00ffffffu;
        uint32_t maxNonce = baseNonce + 15; // spans a full AVX-512 (16-way) batch

        auto hashForNonce = [&](uint32_t n, uint8_t digest[32]) {
            uint8_t h[80];
            std::memcpy(h, header, 80);
            util::be32enc(h + 76, n);
            opensslScryptReference(h, costN, digest);
        };

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
        bool found = scanHashScrypt(engine, header, target, maxNonce, nonce, restart, hashesDone);
        if (!found || nonce != expectedNonce)
            return false;
    }
    return true;
}

} // namespace

bool scryptSimdSelfTest()
{
    uint32_t seed = 0x2545f491u;
    // A small costN keeps the self-test's many hashes fast; correctness
    // does not depend on N's magnitude (it must merely be a power of two,
    // same requirement the reference miner has).
    constexpr uint32_t kTestN = 16;

    if (!testEngineAgainstOpenssl(kTestN, 3, seed))
        return false;
    if (cpuFeatures().sse2 && !testRomixAgainstScalar(4, kTestN, seed))
        return false;
    if (cpuFeatures().avx2 && !testRomixAgainstScalar(8, kTestN, seed))
        return false;
    if (cpuFeatures().avx512f && !testRomixAgainstScalar(16, kTestN, seed))
        return false;
    if (!testScanIntegration(kTestN, seed))
        return false;

    return true;
}

std::vector<BackendBenchResult> scryptBenchmarkBackends(double secondsPerBackend, uint32_t costN)
{
    std::vector<BackendBenchResult> results;

    uint8_t header[80];
    uint32_t seed = 0xdeadbeefu;
    fillRandom(seed, header, 80);
    uint32_t target[8] = {0, 0, 0, 0, 0, 0, 0, 0}; // never satisfied - runs the full duration

    auto runWidth = [&](const char* name, int width) {
        std::vector<uint32_t> scratch(scryptScratchWords(costN, width));
        std::atomic<bool> restart{false};
        uint32_t nonce = 0;
        uint64_t totalHashes = 0;
        auto t0 = std::chrono::steady_clock::now();
        double elapsed = 0.0;
        while (elapsed < secondsPerBackend) {
            uint64_t hashesDone = 0;
            // scrypt is far more expensive per hash than sha256d, so a
            // much smaller batch keeps the elapsed-time check responsive.
            uint32_t maxNonce = nonce + uint32_t(width) * 50u;
            scanHashScryptImpl(width, scratch.data(), costN, header, target, maxNonce, nonce, restart, hashesDone);
            totalHashes += hashesDone;
            nonce = maxNonce + 1;
            elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        }
        results.push_back({name, elapsed > 0.0 ? double(totalHashes) / elapsed : 0.0});
    };

    runWidth("scalar", 1);
    if (cpuFeatures().sse2)
        runWidth("SSE2 (4-way)", 4);
    if (cpuFeatures().avx2)
        runWidth("AVX2 (8-way)", 8);
    if (cpuFeatures().avx512f)
        runWidth("AVX-512 (16-way)", 16);

    return results;
}

} // namespace cppminer::algo
