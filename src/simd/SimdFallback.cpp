// Portable fallback implementations for non-x86 targets. The public SIMD
// entry points remain available so the common dispatch and self-test code can
// be compiled unchanged, while each lane is evaluated through the scalar
// implementation when x86 intrinsics are unavailable.
#include "Sha256Simd.h"
#include "ScryptSimd.h"
#include "../ByteUtils.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace cppminer::simd {
namespace {

template <int N>
void sha256TransformNwayFallback(uint32_t state[N * 8], const uint32_t blocks[N * 16])
{
    for (int lane = 0; lane < N; lane++) {
        uint32_t laneState[8];
        uint8_t laneBlock[64];
        for (int word = 0; word < 8; word++)
            laneState[word] = state[word * N + lane];
        for (int word = 0; word < 16; word++)
            util::be32enc(laneBlock + 4 * word, blocks[word * N + lane]);

        sha256TransformScalar(laneState, laneBlock);

        for (int word = 0; word < 8; word++)
            state[word * N + lane] = laneState[word];
    }
}

template <int N>
void scryptRomixNwayFallback(uint32_t B[32 * N], uint32_t* V, uint32_t costN)
{
    (void)V;
    const size_t laneScratchWords = scryptScratchWords(costN, 1);
    std::vector<uint32_t> laneScratch(laneScratchWords);
    for (int lane = 0; lane < N; lane++) {
        uint32_t laneB[32];
        for (int word = 0; word < 32; word++)
            laneB[word] = B[word * N + lane];

        scryptRomixScalar(laneB, laneScratch.data(), costN);

        for (int word = 0; word < 32; word++)
            B[word * N + lane] = laneB[word];
    }
}

} // namespace

void sha256Transform4way(uint32_t state[4 * 8], const uint32_t blocks[4 * 16])
{
    sha256TransformNwayFallback<4>(state, blocks);
}

void sha256Transform8way(uint32_t state[8 * 8], const uint32_t blocks[8 * 16])
{
    sha256TransformNwayFallback<8>(state, blocks);
}

void sha256Transform16way(uint32_t state[16 * 8], const uint32_t blocks[16 * 16])
{
    sha256TransformNwayFallback<16>(state, blocks);
}

void sha256TransformShani(uint32_t state[8], const uint8_t block[64])
{
    sha256TransformScalar(state, block);
}

void scryptRomix4way(uint32_t B[32 * 4], uint32_t* V, uint32_t costN)
{
    scryptRomixNwayFallback<4>(B, V, costN);
}

void scryptRomix8way(uint32_t B[32 * 8], uint32_t* V, uint32_t costN)
{
    scryptRomixNwayFallback<8>(B, V, costN);
}

void scryptRomix16way(uint32_t B[32 * 16], uint32_t* V, uint32_t costN)
{
    scryptRomixNwayFallback<16>(B, V, costN);
}

} // namespace cppminer::simd
