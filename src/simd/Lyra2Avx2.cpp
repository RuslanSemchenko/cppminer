#include "Lyra2Simd.h"

#if defined(__AVX2__)

#include <immintrin.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <vector>

namespace cppminer::simd {
namespace {

constexpr size_t kLanes = 4;
constexpr size_t kRows = 16384;
constexpr size_t kCols = 4;
constexpr size_t kBlockWords = 12;
constexpr size_t kRowWords = kCols * kBlockWords;
constexpr size_t kInputBlockBytes = 64;
constexpr size_t kInputBlockWords = 8;
constexpr size_t kMaxInputBlocks = (65536 + 6 * sizeof(uint64_t)) / kInputBlockBytes + 1;

inline __m256i ror64(__m256i x, int bits)
{
    return _mm256_or_si256(_mm256_srli_epi64(x, bits), _mm256_slli_epi64(x, 64 - bits));
}

inline void g(__m256i& a, __m256i& b, __m256i& c, __m256i& d)
{
    a = _mm256_add_epi64(a, b);
    d = ror64(_mm256_xor_si256(d, a), 32);
    c = _mm256_add_epi64(c, d);
    b = ror64(_mm256_xor_si256(b, c), 24);
    a = _mm256_add_epi64(a, b);
    d = ror64(_mm256_xor_si256(d, a), 16);
    c = _mm256_add_epi64(c, d);
    b = ror64(_mm256_xor_si256(b, c), 63);
}

inline void lyraRound(std::array<__m256i, 16>& v)
{
    g(v[0], v[4], v[8], v[12]);
    g(v[1], v[5], v[9], v[13]);
    g(v[2], v[6], v[10], v[14]);
    g(v[3], v[7], v[11], v[15]);
    g(v[0], v[5], v[10], v[15]);
    g(v[1], v[6], v[11], v[12]);
    g(v[2], v[7], v[8], v[13]);
    g(v[3], v[4], v[9], v[14]);
}

inline void lyraReduced(std::array<__m256i, 16>& v)
{
    lyraRound(v);
}

inline void lyraFull(std::array<__m256i, 16>& v)
{
    for (int i = 0; i < 12; ++i)
        lyraRound(v);
}

inline __m256i loadMatrix(const std::vector<uint64_t>& matrix, size_t row, size_t word)
{
    const size_t base = (row * kRowWords + word) * kLanes;
    return _mm256_loadu_si256(reinterpret_cast<const __m256i*>(matrix.data() + base));
}

inline void storeMatrix(std::vector<uint64_t>& matrix, size_t row, size_t word, __m256i value)
{
    const size_t base = (row * kRowWords + word) * kLanes;
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(matrix.data() + base), value);
}

inline __m256i loadInput(const std::vector<uint64_t>& input, size_t block, size_t word)
{
    const size_t base = (block * kInputBlockWords + word) * kLanes;
    return _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input.data() + base));
}

inline void storeOutput(const std::array<__m256i, 16>& state, uint8_t out[kLanes][32])
{
    alignas(32) uint64_t lanes[kLanes];
    for (size_t word = 0; word < 4; ++word) {
        _mm256_store_si256(reinterpret_cast<__m256i*>(lanes), state[word]);
        for (size_t lane = 0; lane < kLanes; ++lane)
            std::memcpy(out[lane] + word * sizeof(uint64_t), &lanes[lane], sizeof(uint64_t));
    }
}

inline void absorbSafe(std::array<__m256i, 16>& state, const std::vector<uint64_t>& input, size_t blocks)
{
    for (size_t block = 0; block < blocks; ++block) {
        for (size_t word = 0; word < kInputBlockWords; ++word)
            state[word] = _mm256_xor_si256(state[word], loadInput(input, block, word));
        lyraFull(state);
    }
}

inline void squeezeRow0(std::array<__m256i, 16>& state, std::vector<uint64_t>& matrix)
{
    for (size_t col = 0; col < kCols; ++col) {
        const size_t outCol = kCols - 1 - col;
        for (size_t word = 0; word < kBlockWords; ++word)
            storeMatrix(matrix, 0, outCol * kBlockWords + word, state[word]);
        lyraReduced(state);
    }
}

inline void duplexRow1(std::array<__m256i, 16>& state, std::vector<uint64_t>& matrix)
{
    for (size_t col = 0; col < kCols; ++col) {
        for (size_t word = 0; word < kBlockWords; ++word)
            state[word] = _mm256_xor_si256(state[word], loadMatrix(matrix, 0, col * kBlockWords + word));
        lyraReduced(state);
        const size_t outCol = kCols - 1 - col;
        for (size_t word = 0; word < kBlockWords; ++word) {
            __m256i in = loadMatrix(matrix, 0, col * kBlockWords + word);
            storeMatrix(matrix, 1, outCol * kBlockWords + word, _mm256_xor_si256(in, state[word]));
        }
    }
}

inline void duplexSetup(std::array<__m256i, 16>& state, std::vector<uint64_t>& matrix,
                        size_t prev, size_t rowa, size_t row)
{
    for (size_t col = 0; col < kCols; ++col) {
        for (size_t word = 0; word < kBlockWords; ++word) {
            __m256i in = loadMatrix(matrix, prev, col * kBlockWords + word);
            __m256i inout = loadMatrix(matrix, rowa, col * kBlockWords + word);
            state[word] = _mm256_xor_si256(state[word], _mm256_add_epi64(in, inout));
        }
        lyraReduced(state);
        const size_t outCol = kCols - 1 - col;
        for (size_t word = 0; word < kBlockWords; ++word) {
            __m256i in = loadMatrix(matrix, prev, col * kBlockWords + word);
            storeMatrix(matrix, row, outCol * kBlockWords + word, _mm256_xor_si256(in, state[word]));
        }
        for (size_t word = 0; word < kBlockWords; ++word) {
            __m256i inout = loadMatrix(matrix, rowa, col * kBlockWords + word);
            __m256i rotated = word == 0 ? state[11] : state[word - 1];
            storeMatrix(matrix, rowa, col * kBlockWords + word, _mm256_xor_si256(inout, rotated));
        }
    }
}

inline void duplexWandering(std::array<__m256i, 16>& state, std::vector<uint64_t>& matrix,
                            size_t prev, const std::array<size_t, kLanes>& rowa, size_t row)
{
    for (size_t col = 0; col < kCols; ++col) {
        std::array<__m256i, kBlockWords> inout{};
        for (size_t word = 0; word < kBlockWords; ++word) {
            inout[word] = _mm256_set_epi64x(
                static_cast<long long>(matrix[(rowa[3] * kRowWords + col * kBlockWords + word) * kLanes + 3]),
                static_cast<long long>(matrix[(rowa[2] * kRowWords + col * kBlockWords + word) * kLanes + 2]),
                static_cast<long long>(matrix[(rowa[1] * kRowWords + col * kBlockWords + word) * kLanes + 1]),
                static_cast<long long>(matrix[(rowa[0] * kRowWords + col * kBlockWords + word) * kLanes + 0]));
            __m256i in = loadMatrix(matrix, prev, col * kBlockWords + word);
            state[word] = _mm256_xor_si256(state[word], _mm256_add_epi64(in, inout[word]));
        }
        lyraReduced(state);

        bool hasOverlap = false;
        for (size_t lane = 0; lane < kLanes; ++lane)
            hasOverlap = hasOverlap || rowa[lane] == row;

        if (!hasOverlap) {
            alignas(32) uint64_t ioLanes[kLanes];
            for (size_t word = 0; word < kBlockWords; ++word) {
                const __m256i rotated = word == 0 ? state[11] : state[word - 1];
                const __m256i updatedOut = _mm256_xor_si256(
                    loadMatrix(matrix, row, col * kBlockWords + word), state[word]);
                storeMatrix(matrix, row, col * kBlockWords + word, updatedOut);

                const __m256i updatedIo = _mm256_xor_si256(inout[word], rotated);
                _mm256_store_si256(reinterpret_cast<__m256i*>(ioLanes), updatedIo);
                for (size_t lane = 0; lane < kLanes; ++lane)
                    matrix[(rowa[lane] * kRowWords + col * kBlockWords + word) * kLanes + lane] = ioLanes[lane];
            }
        } else {
            alignas(32) uint64_t stateLanes[kBlockWords][kLanes];
            alignas(32) uint64_t inoutLanes[kBlockWords][kLanes];
            for (size_t word = 0; word < kBlockWords; ++word) {
                _mm256_store_si256(reinterpret_cast<__m256i*>(stateLanes[word]), state[word]);
                _mm256_store_si256(reinterpret_cast<__m256i*>(inoutLanes[word]), inout[word]);
            }
            for (size_t word = 0; word < kBlockWords; ++word) {
                const size_t outBase = (row * kRowWords + col * kBlockWords + word) * kLanes;
                for (size_t lane = 0; lane < kLanes; ++lane) {
                    const size_t ioBase = (rowa[lane] * kRowWords + col * kBlockWords + word) * kLanes + lane;
                    const uint64_t rotated = word == 0 ? stateLanes[11][lane] : stateLanes[word - 1][lane];
                    const uint64_t ioValue = inoutLanes[word][lane] ^ rotated;
                    if (rowa[lane] == row)
                        matrix[outBase + lane] = matrix[outBase + lane] ^ stateLanes[word][lane] ^ rotated;
                    else {
                        matrix[outBase + lane] = matrix[outBase + lane] ^ stateLanes[word][lane];
                        matrix[ioBase] = ioValue;
                    }
                }
            }
        }
    }
}

} // namespace

struct Lyra2Avx2Context {
    std::vector<uint64_t> matrix;
    std::vector<uint64_t> input;
    std::vector<uint8_t> padded;

    Lyra2Avx2Context()
        : matrix(kRows * kRowWords * kLanes, 0),
          input(kMaxInputBlocks * kInputBlockWords * kLanes, 0),
          padded(kLanes * kMaxInputBlocks * kInputBlockBytes, 0)
    {
    }
};

Lyra2Avx2Context* lyra2Avx2Create()
{
    try {
        return new Lyra2Avx2Context();
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}

void lyra2Avx2Destroy(Lyra2Avx2Context* ctx)
{
    delete ctx;
}

void lyra2Avx2Hash4(Lyra2Avx2Context& ctx, const uint8_t* blob, size_t blobSize,
                    uint64_t firstNonce, uint32_t timeCost, uint8_t out[kLanes][32])
{
    constexpr size_t kBasilBytes = 6 * sizeof(uint64_t);
    const size_t blockCount = (blobSize + kBasilBytes) / kInputBlockBytes + 1;
    const size_t paddedSize = blockCount * kInputBlockBytes;
    std::memset(ctx.padded.data(), 0, kLanes * paddedSize);
    uint8_t* padded = ctx.padded.data();

    const uint64_t basil[kLanes][6] = {
        {32, blobSize, 0, timeCost, kRows, kCols},
        {32, blobSize, 0, timeCost, kRows, kCols},
        {32, blobSize, 0, timeCost, kRows, kCols},
        {32, blobSize, 0, timeCost, kRows, kCols},
    };
    for (size_t lane = 0; lane < kLanes; ++lane) {
        uint8_t* laneInput = padded + lane * paddedSize;
        std::memcpy(laneInput, blob, blobSize);
        uint64_t nonce = firstNonce + lane;
        std::memcpy(laneInput + blobSize - sizeof(uint64_t), &nonce, sizeof(nonce));
        std::memcpy(laneInput + blobSize, basil[lane], kBasilBytes);
        laneInput[blobSize + kBasilBytes] = 0x80;
        laneInput[paddedSize - 1] ^= 0x01;
    }

    std::fill(ctx.input.begin(), ctx.input.begin() + blockCount * kInputBlockWords * kLanes, 0);
    for (size_t block = 0; block < blockCount; ++block) {
        for (size_t word = 0; word < kInputBlockWords; ++word) {
            for (size_t lane = 0; lane < kLanes; ++lane) {
                uint64_t value;
                std::memcpy(&value, padded + lane * paddedSize + block * kInputBlockBytes + word * sizeof(uint64_t), sizeof(value));
                ctx.input[(block * kInputBlockWords + word) * kLanes + lane] = value;
            }
        }
    }

    std::fill(ctx.matrix.begin(), ctx.matrix.end(), 0);
    std::array<__m256i, 16> state;
    for (size_t word = 0; word < 8; ++word)
        state[word] = _mm256_setzero_si256();
    const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
    };
    for (size_t word = 0; word < 8; ++word)
        state[8 + word] = _mm256_set1_epi64x(static_cast<long long>(iv[word]));

    absorbSafe(state, ctx.input, blockCount);
    squeezeRow0(state, ctx.matrix);
    duplexRow1(state, ctx.matrix);

    size_t row = 2;
    size_t prev = 1;
    size_t rowa = 0;
    int64_t step = 1;
    size_t window = 2;
    int64_t gap = 1;
    while (row < kRows) {
        duplexSetup(state, ctx.matrix, prev, rowa, row);
        rowa = static_cast<size_t>((static_cast<int64_t>(rowa) + step) & static_cast<int64_t>(window - 1));
        prev = row++;
        if (rowa == 0) {
            step = static_cast<int64_t>(window) + gap;
            window *= 2;
            gap = -gap;
        }
    }

    std::array<size_t, kLanes> rowaLanes{};
    row = 0;
    for (uint32_t tau = 1; tau <= timeCost; ++tau) {
        step = (tau & 1) == 0 ? -1 : static_cast<int64_t>(kRows / 2 - 1);
        do {
            alignas(32) uint64_t state0[kLanes];
            _mm256_store_si256(reinterpret_cast<__m256i*>(state0), state[0]);
            for (size_t lane = 0; lane < kLanes; ++lane)
                rowaLanes[lane] = static_cast<size_t>(state0[lane] & (kRows - 1));
            duplexWandering(state, ctx.matrix, prev, rowaLanes, row);
            prev = row;
            row = static_cast<size_t>((static_cast<int64_t>(row) + step) & static_cast<int64_t>(kRows - 1));
        } while (row != 0);
    }

    for (size_t word = 0; word < kBlockWords; ++word) {
        __m256i io = _mm256_set_epi64x(
            static_cast<long long>(ctx.matrix[(rowaLanes[3] * kRowWords + word) * kLanes + 3]),
            static_cast<long long>(ctx.matrix[(rowaLanes[2] * kRowWords + word) * kLanes + 2]),
            static_cast<long long>(ctx.matrix[(rowaLanes[1] * kRowWords + word) * kLanes + 1]),
            static_cast<long long>(ctx.matrix[(rowaLanes[0] * kRowWords + word) * kLanes + 0]));
        state[word] = _mm256_xor_si256(state[word], io);
    }
    lyraFull(state);
    storeOutput(state, out);
}

} // namespace cppminer::simd

#endif // __AVX2__
