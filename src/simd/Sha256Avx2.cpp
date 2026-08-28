// 8-way AVX2 SHA-256 - same technique as Sha256Sse2.cpp's 4-way version,
// just twice as wide (256-bit YMM registers, 8 lanes). Compiled with
// AVX2 codegen enabled for this translation unit only (see
// miner/CMakeLists.txt); every other file stays on the compiler's default
// (SSE2) baseline so the resulting binary still runs on CPUs without AVX2 -
// see simd/CpuFeatures.h for the runtime check gating calls into here.
#include "Sha256Simd.h"

#include <immintrin.h>

namespace cppminer::simd {

namespace {

using V = __m256i;

inline V add(V a, V b) { return _mm256_add_epi32(a, b); }
inline V xorv(V a, V b) { return _mm256_xor_si256(a, b); }
inline V andv(V a, V b) { return _mm256_and_si256(a, b); }
inline V orv(V a, V b) { return _mm256_or_si256(a, b); }
inline V shr(V a, int n) { return _mm256_srli_epi32(a, n); }
inline V shl(V a, int n) { return _mm256_slli_epi32(a, n); }
inline V rotr(V a, int n) { return orv(shr(a, n), shl(a, 32 - n)); }

inline V Ch(V x, V y, V z) { return xorv(andv(x, xorv(y, z)), z); }
inline V Maj(V x, V y, V z) { return orv(andv(x, orv(y, z)), andv(y, z)); }
inline V bigS0(V x) { return xorv(xorv(rotr(x, 2), rotr(x, 13)), rotr(x, 22)); }
inline V bigS1(V x) { return xorv(xorv(rotr(x, 6), rotr(x, 11)), rotr(x, 25)); }
inline V smallS0(V x) { return xorv(xorv(rotr(x, 7), rotr(x, 18)), shr(x, 3)); }
inline V smallS1(V x) { return xorv(xorv(rotr(x, 17), rotr(x, 19)), shr(x, 10)); }

} // namespace

void sha256Transform8way(uint32_t state[8 * 8], const uint32_t blocks[8 * 16])
{
    constexpr int N = 8;
    V w[64];
    for (int i = 0; i < 16; i++)
        w[i] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(blocks + i * N));
    for (int i = 16; i < 64; i++)
        w[i] = add(add(smallS1(w[i - 2]), w[i - 7]), add(smallS0(w[i - 15]), w[i - 16]));

    V a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 0 * N));
    V b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 1 * N));
    V c = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 2 * N));
    V d = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 3 * N));
    V e = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 4 * N));
    V f = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 5 * N));
    V g = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 6 * N));
    V h = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 7 * N));

    for (int i = 0; i < 64; i++) {
        V kv = _mm256_set1_epi32(static_cast<int>(kSha256K[i]));
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

    _mm256_storeu_si256(reinterpret_cast<__m256i*>(state + 0 * N), add(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 0 * N)), a));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(state + 1 * N), add(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 1 * N)), b));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(state + 2 * N), add(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 2 * N)), c));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(state + 3 * N), add(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 3 * N)), d));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(state + 4 * N), add(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 4 * N)), e));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(state + 5 * N), add(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 5 * N)), f));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(state + 6 * N), add(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 6 * N)), g));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(state + 7 * N), add(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(state + 7 * N)), h));
}

} // namespace cppminer::simd
