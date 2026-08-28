// 4-way ARM NEON SHA-256 - the AArch64 counterpart of Sha256Sse2.cpp's
// 4-way SSE2 version: identical word-major/lane-minor buffer layout and
// round structure, just with uint32x4_t/NEON intrinsics standing in for
// __m128i/SSE2 ones. This project currently only ships an x64/MSVC/Windows
// build, so the whole translation unit (the <arm_neon.h> include included)
// is compiled out below and has zero effect there; it only becomes active
// when built for AArch64.
#if defined(__aarch64__) || defined(_M_ARM64)
#include "Sha256Simd.h"
#include <arm_neon.h>
namespace cppminer::simd {
namespace {
using V = uint32x4_t;
inline V add(V a, V b) { return vaddq_u32(a, b); }
inline V xorv(V a, V b) { return veorq_u32(a, b); }
inline V andv(V a, V b) { return vandq_u32(a, b); }
inline V orv(V a, V b) { return vorrq_u32(a, b); }
// vshrq_n_u32/vshlq_n_u32 require a compile-time-constant shift amount
// (they're macros around a builtin that checks this at compile time),
// so the shift is a template parameter here rather than a runtime int -
// every call site below passes a literal (2, 13, 22, 6, 11, 25, 7, 18,
// 3, 17, 19 or 10), which becomes the template argument.
template<int n> inline V shr(V a) { return vshrq_n_u32(a, n); }
template<int n> inline V shl(V a) { return vshlq_n_u32(a, n); }
template<int n> inline V rotr(V a) { return orv(shr<n>(a), shl<32 - n>(a)); }
inline V Ch(V x, V y, V z) { return xorv(andv(x, xorv(y, z)), z); }
inline V Maj(V x, V y, V z) { return orv(andv(x, orv(y, z)), andv(y, z)); }
inline V bigS0(V x) { return xorv(xorv(rotr<2>(x), rotr<13>(x)), rotr<22>(x)); }
inline V bigS1(V x) { return xorv(xorv(rotr<6>(x), rotr<11>(x)), rotr<25>(x)); }
inline V smallS0(V x) { return xorv(xorv(rotr<7>(x), rotr<18>(x)), shr<3>(x)); }
inline V smallS1(V x) { return xorv(xorv(rotr<17>(x), rotr<19>(x)), shr<10>(x)); }
} // namespace
void sha256Transform4wayNeon(uint32_t state[4 * 8], const uint32_t blocks[4 * 16])
{
    constexpr int N = 4;
    V w[64];
    for (int i = 0; i < 16; i++)
        w[i] = vld1q_u32(blocks + i * N);
    for (int i = 16; i < 64; i++)
        w[i] = add(add(smallS1(w[i - 2]), w[i - 7]), add(smallS0(w[i - 15]), w[i - 16]));
    V a = vld1q_u32(state + 0 * N);
    V b = vld1q_u32(state + 1 * N);
    V c = vld1q_u32(state + 2 * N);
    V d = vld1q_u32(state + 3 * N);
    V e = vld1q_u32(state + 4 * N);
    V f = vld1q_u32(state + 5 * N);
    V g = vld1q_u32(state + 6 * N);
    V h = vld1q_u32(state + 7 * N);
    for (int i = 0; i < 64; i++) {
        V kv = vdupq_n_u32(kSha256K[i]);
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
    vst1q_u32(state + 0 * N, add(vld1q_u32(state + 0 * N), a));
    vst1q_u32(state + 1 * N, add(vld1q_u32(state + 1 * N), b));
    vst1q_u32(state + 2 * N, add(vld1q_u32(state + 2 * N), c));
    vst1q_u32(state + 3 * N, add(vld1q_u32(state + 3 * N), d));
    vst1q_u32(state + 4 * N, add(vld1q_u32(state + 4 * N), e));
    vst1q_u32(state + 5 * N, add(vld1q_u32(state + 5 * N), f));
    vst1q_u32(state + 6 * N, add(vld1q_u32(state + 6 * N), g));
    vst1q_u32(state + 7 * N, add(vld1q_u32(state + 7 * N), h));
}
} // namespace cppminer::simd
#endif // defined(__aarch64__) || defined(_M_ARM64)
