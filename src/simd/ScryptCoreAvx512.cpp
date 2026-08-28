// 16-way AVX-512F scrypt ROMix - same technique as ScryptCoreAvx2.cpp's
// 8-way version, twice as wide again. Compiled with AVX-512F codegen
// enabled for this translation unit only (see miner/CMakeLists.txt);
// every other file stays on the compiler's default baseline so the
// binary still runs on CPUs without AVX-512F - see simd/CpuFeatures.h for
// the runtime check gating calls into here. Still uses a manual per-lane
// gather (16 scalar loads) rather than `_mm512_i32gather_epi32` for the
// "read V[j]" step, consistent with ScryptSimd.h's rationale for every
// other width.
#include "ScryptSimd.h"

#include <immintrin.h>

namespace cppminer::simd {

constexpr int W16 = 16;

namespace {

using V = __m512i;

inline V add(V a, V b) { return _mm512_add_epi32(a, b); }
inline V xorv(V a, V b) { return _mm512_xor_si512(a, b); }
inline V andv(V a, V b) { return _mm512_and_si512(a, b); }
inline V shr(V a, int n) { return _mm512_srli_epi32(a, n); }
inline V shl(V a, int n) { return _mm512_slli_epi32(a, n); }
inline V rotl(V a, int n) { return _mm512_or_si512(shl(a, n), shr(a, 32 - n)); }
inline V load(const uint32_t* p) { return _mm512_loadu_si512(reinterpret_cast<const void*>(p)); }
inline void store(uint32_t* p, V v) { _mm512_storeu_si512(reinterpret_cast<void*>(p), v); }

// Same structure/index pattern as the scalar xorSalsa8 (ScryptCoreScalar.cpp)
// and the reference miner's xor_salsa8, just W16-wide per operation.
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

void scryptRomix16way(uint32_t B[32 * W16], uint32_t* V_, uint32_t costN)
{
    V x[32];
    for (int i = 0; i < 32; i++)
        x[i] = load(B + i * W16);

    for (uint32_t row = 0; row < costN; row++) {
        uint32_t* dst = V_ + size_t(row) * 32 * W16;
        for (int i = 0; i < 32; i++)
            store(dst + i * W16, x[i]);
        xorSalsa8(x + 0, x + 16);
        xorSalsa8(x + 16, x + 0);
    }

    for (uint32_t row = 0; row < costN; row++) {
        V jVec = andv(x[16], _mm512_set1_epi32(static_cast<int>(costN - 1)));
        uint32_t j[W16];
        store(j, jVec);
        for (int i = 0; i < 32; i++) {
            uint32_t gathered[W16];
            for (int lane = 0; lane < W16; lane++)
                gathered[lane] = V_[size_t(j[lane]) * 32 * W16 + size_t(i) * W16 + lane];
            x[i] = xorv(x[i], load(gathered));
        }
        xorSalsa8(x + 0, x + 16);
        xorSalsa8(x + 16, x + 0);
    }

    for (int i = 0; i < 32; i++)
        store(B + i * W16, x[i]);
}

} // namespace cppminer::simd
