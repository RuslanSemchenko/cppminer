// 4-way SSE2 SHA-256, batching 4 independent messages so the round
// function's adds/xors/rotates each cover 4 lanes per instruction instead
// of 1. Structurally identical to the reference miner's non-assembly
// HAVE_SHA256_4WAY C path (see sha2.c's sha256d_ms_4way and friends), just
// written with SSE2 intrinsics instead of hand-written asm, and driven
// from a plain uint32_t "word-major/lane-minor" buffer instead of asm
// register allocation.
#include "Sha256Simd.h"

#include <emmintrin.h>

namespace cppminer::simd {

namespace {

using V = __m128i;

inline V add(V a, V b) { return _mm_add_epi32(a, b); }
inline V xorv(V a, V b) { return _mm_xor_si128(a, b); }
inline V andv(V a, V b) { return _mm_and_si128(a, b); }
inline V orv(V a, V b) { return _mm_or_si128(a, b); }
inline V shr(V a, int n) { return _mm_srli_epi32(a, n); }
inline V shl(V a, int n) { return _mm_slli_epi32(a, n); }
inline V rotr(V a, int n) { return orv(shr(a, n), shl(a, 32 - n)); }

inline V Ch(V x, V y, V z) { return xorv(andv(x, xorv(y, z)), z); }
inline V Maj(V x, V y, V z) { return orv(andv(x, orv(y, z)), andv(y, z)); }
inline V bigS0(V x) { return xorv(xorv(rotr(x, 2), rotr(x, 13)), rotr(x, 22)); }
inline V bigS1(V x) { return xorv(xorv(rotr(x, 6), rotr(x, 11)), rotr(x, 25)); }
inline V smallS0(V x) { return xorv(xorv(rotr(x, 7), rotr(x, 18)), shr(x, 3)); }
inline V smallS1(V x) { return xorv(xorv(rotr(x, 17), rotr(x, 19)), shr(x, 10)); }

} // namespace

void sha256Transform4way(uint32_t state[4 * 8], const uint32_t blocks[4 * 16])
{
    constexpr int N = 4;
    V w[64];
    for (int i = 0; i < 16; i++)
        w[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(blocks + i * N));
    for (int i = 16; i < 64; i++)
        w[i] = add(add(smallS1(w[i - 2]), w[i - 7]), add(smallS0(w[i - 15]), w[i - 16]));

    V a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 0 * N));
    V b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 1 * N));
    V c = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 2 * N));
    V d = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 3 * N));
    V e = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 4 * N));
    V f = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 5 * N));
    V g = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 6 * N));
    V h = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 7 * N));

    for (int i = 0; i < 64; i++) {
        V kv = _mm_set1_epi32(static_cast<int>(kSha256K[i]));
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

    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 0 * N), add(_mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 0 * N)), a));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 1 * N), add(_mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 1 * N)), b));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 2 * N), add(_mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 2 * N)), c));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 3 * N), add(_mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 3 * N)), d));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 4 * N), add(_mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 4 * N)), e));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 5 * N), add(_mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 5 * N)), f));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 6 * N), add(_mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 6 * N)), g));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 7 * N), add(_mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 7 * N)), h));
}

} // namespace cppminer::simd
