// 16-way AVX-512F SHA-256 - same technique as Sha256Avx2.cpp's 8-way
// version, just twice as wide again (512-bit ZMM registers, 16 lanes).
// Needs this translation unit built with AVX-512F codegen enabled
// (/arch:AVX512 on MSVC, -mavx512f on GCC/Clang - see miner/CMakeLists.txt
// for the actual wiring); every other file stays on the compiler's default
// (SSE2) baseline so the resulting binary still runs on CPUs without
// AVX-512F - see simd/CpuFeatures.h for the runtime check gating calls
// into here.
#include "Sha256Simd.h"

#include <immintrin.h>

namespace cppminer::simd {

namespace {

using V = __m512i;

inline V add(V a, V b) { return _mm512_add_epi32(a, b); }
inline V xorv(V a, V b) { return _mm512_xor_si512(a, b); }
inline V andv(V a, V b) { return _mm512_and_si512(a, b); }
inline V orv(V a, V b) { return _mm512_or_si512(a, b); }
inline V shr(V a, int n) { return _mm512_srli_epi32(a, n); }
inline V shl(V a, int n) { return _mm512_slli_epi32(a, n); }
inline V rotr(V a, int n) { return orv(shr(a, n), shl(a, 32 - n)); }

inline V Ch(V x, V y, V z) { return xorv(andv(x, xorv(y, z)), z); }
inline V Maj(V x, V y, V z) { return orv(andv(x, orv(y, z)), andv(y, z)); }
inline V bigS0(V x) { return xorv(xorv(rotr(x, 2), rotr(x, 13)), rotr(x, 22)); }
inline V bigS1(V x) { return xorv(xorv(rotr(x, 6), rotr(x, 11)), rotr(x, 25)); }
inline V smallS0(V x) { return xorv(xorv(rotr(x, 7), rotr(x, 18)), shr(x, 3)); }
inline V smallS1(V x) { return xorv(xorv(rotr(x, 17), rotr(x, 19)), shr(x, 10)); }

} // namespace

void sha256Transform16way(uint32_t state[16 * 8], const uint32_t blocks[16 * 16])
{
    constexpr int N = 16;
    V w[64];
    for (int i = 0; i < 16; i++)
        w[i] = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(blocks + i * N));
    for (int i = 16; i < 64; i++)
        w[i] = add(add(smallS1(w[i - 2]), w[i - 7]), add(smallS0(w[i - 15]), w[i - 16]));

    V a = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 0 * N));
    V b = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 1 * N));
    V c = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 2 * N));
    V d = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 3 * N));
    V e = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 4 * N));
    V f = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 5 * N));
    V g = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 6 * N));
    V h = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 7 * N));

    for (int i = 0; i < 64; i++) {
        V kv = _mm512_set1_epi32(static_cast<int>(kSha256K[i]));
        V t1 = add(add(add(h, bigS1(e)), Ch(e, f, g)), add(kv, w[i]));
        V t2 = add(bigS0(a), Maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = add(d, t1);
        d = c;
        c = b;
        b = a;
        a = add(t1, t2);
    }

    _mm512_storeu_si512(reinterpret_cast<__m512i*>(state + 0 * N), add(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 0 * N)), a));
    _mm512_storeu_si512(reinterpret_cast<__m512i*>(state + 1 * N), add(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 1 * N)), b));
    _mm512_storeu_si512(reinterpret_cast<__m512i*>(state + 2 * N), add(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 2 * N)), c));
    _mm512_storeu_si512(reinterpret_cast<__m512i*>(state + 3 * N), add(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 3 * N)), d));
    _mm512_storeu_si512(reinterpret_cast<__m512i*>(state + 4 * N), add(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 4 * N)), e));
    _mm512_storeu_si512(reinterpret_cast<__m512i*>(state + 5 * N), add(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 5 * N)), f));
    _mm512_storeu_si512(reinterpret_cast<__m512i*>(state + 6 * N), add(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 6 * N)), g));
    _mm512_storeu_si512(reinterpret_cast<__m512i*>(state + 7 * N), add(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(state + 7 * N)), h));
}

} // namespace cppminer::simd
