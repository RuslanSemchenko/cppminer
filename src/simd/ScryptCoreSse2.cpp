// 4-way SSE2 scrypt ROMix: batches 4 independent nonces so Salsa20/8's
// adds/xors/rotates run 4-wide, and so the 4 lanes' data-dependent
// "read V[j]" memory accesses can be issued together each iteration
// instead of one at a time. See ScryptSimd.h for the full rationale and
// the word-major/lane-minor buffer layout.
#include "ScryptSimd.h"

#include <emmintrin.h>

namespace cppminer::simd {

// constexpr at namespace scope has internal linkage, so this doesn't clash
// with the same-named constant in ScryptCoreAvx2.cpp's own translation unit.
constexpr int W = 4;

namespace {

using V = __m128i;

inline V add(V a, V b) { return _mm_add_epi32(a, b); }
inline V xorv(V a, V b) { return _mm_xor_si128(a, b); }
inline V andv(V a, V b) { return _mm_and_si128(a, b); }
inline V shr(V a, int n) { return _mm_srli_epi32(a, n); }
inline V shl(V a, int n) { return _mm_slli_epi32(a, n); }
inline V rotl(V a, int n) { return _mm_or_si128(shl(a, n), shr(a, 32 - n)); }
inline V load(const uint32_t* p) { return _mm_loadu_si128(reinterpret_cast<const __m128i*>(p)); }
inline void store(uint32_t* p, V v) { _mm_storeu_si128(reinterpret_cast<__m128i*>(p), v); }

// Same structure/index pattern as the scalar xorSalsa8 (ScryptCoreScalar.cpp)
// and the reference miner's xor_salsa8, just W-wide per operation.
void xorSalsa8(V B[16], const V Bx[16])
{
    V x[16];
    for (int i = 0; i < 16; i++)
        x[i] = B[i] = xorv(B[i], Bx[i]);

    for (int r = 0; r < 8; r += 2) {
        x[4] = xorv(x[4], rotl(add(x[0], x[12]), 7));    x[9] = xorv(x[9], rotl(add(x[5], x[1]), 7));
        x[14] = xorv(x[14], rotl(add(x[10], x[6]), 7));  x[3] = xorv(x[3], rotl(add(x[15], x[11]), 7));
        x[8] = xorv(x[8], rotl(add(x[4], x[0]), 9));     x[13] = xorv(x[13], rotl(add(x[9], x[5]), 9));
        x[2] = xorv(x[2], rotl(add(x[14], x[10]), 9));   x[7] = xorv(x[7], rotl(add(x[3], x[15]), 9));
        x[12] = xorv(x[12], rotl(add(x[8], x[4]), 13));  x[1] = xorv(x[1], rotl(add(x[13], x[9]), 13));
        x[6] = xorv(x[6], rotl(add(x[2], x[14]), 13));   x[11] = xorv(x[11], rotl(add(x[7], x[3]), 13));
        x[0] = xorv(x[0], rotl(add(x[12], x[8]), 18));   x[5] = xorv(x[5], rotl(add(x[1], x[13]), 18));
        x[10] = xorv(x[10], rotl(add(x[6], x[2]), 18));  x[15] = xorv(x[15], rotl(add(x[11], x[7]), 18));

        x[1] = xorv(x[1], rotl(add(x[0], x[3]), 7));     x[6] = xorv(x[6], rotl(add(x[5], x[4]), 7));
        x[11] = xorv(x[11], rotl(add(x[10], x[9]), 7));  x[12] = xorv(x[12], rotl(add(x[15], x[14]), 7));
        x[2] = xorv(x[2], rotl(add(x[1], x[0]), 9));     x[7] = xorv(x[7], rotl(add(x[6], x[5]), 9));
        x[8] = xorv(x[8], rotl(add(x[11], x[10]), 9));   x[13] = xorv(x[13], rotl(add(x[12], x[15]), 9));
        x[3] = xorv(x[3], rotl(add(x[2], x[1]), 13));    x[4] = xorv(x[4], rotl(add(x[7], x[6]), 13));
        x[9] = xorv(x[9], rotl(add(x[8], x[11]), 13));   x[14] = xorv(x[14], rotl(add(x[13], x[12]), 13));
        x[0] = xorv(x[0], rotl(add(x[3], x[2]), 18));    x[5] = xorv(x[5], rotl(add(x[4], x[7]), 18));
        x[10] = xorv(x[10], rotl(add(x[9], x[8]), 18));  x[15] = xorv(x[15], rotl(add(x[14], x[13]), 18));
    }

    for (int i = 0; i < 16; i++)
        B[i] = add(B[i], x[i]);
}

} // namespace

void scryptRomix4way(uint32_t B[32 * W], uint32_t* V_, uint32_t costN)
{
    V x[32];
    for (int i = 0; i < 32; i++)
        x[i] = load(B + i * W);

    for (uint32_t row = 0; row < costN; row++) {
        uint32_t* dst = V_ + size_t(row) * 32 * W;
        for (int i = 0; i < 32; i++)
            store(dst + i * W, x[i]);
        xorSalsa8(x + 0, x + 16);
        xorSalsa8(x + 16, x + 0);
    }

    for (uint32_t row = 0; row < costN; row++) {
        V jVec = andv(x[16], _mm_set1_epi32(static_cast<int>(costN - 1)));
        uint32_t j[W];
        store(j, jVec);
        for (int i = 0; i < 32; i++) {
            uint32_t gathered[W];
            for (int lane = 0; lane < W; lane++)
                gathered[lane] = V_[size_t(j[lane]) * 32 * W + size_t(i) * W + lane];
            x[i] = xorv(x[i], load(gathered));
        }
        xorSalsa8(x + 0, x + 16);
        xorSalsa8(x + 16, x + 0);
    }

    for (int i = 0; i < 32; i++)
        store(B + i * W, x[i]);
}

} // namespace cppminer::simd
