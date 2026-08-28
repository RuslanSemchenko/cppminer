#pragma once

// Multiple interchangeable implementations of the SHA-256 block compression
// function, from plain scalar C++ up to hardware-accelerated SHA-NI and
// software-vectorized AVX2/SSE2, all producing bit-identical results. This
// is the shared building block for both the sha256d mining loop (see
// ../algo/Sha256.cpp) and scrypt's PBKDF2/HMAC-SHA256 wrapper (see
// ../algo/Scrypt.cpp), mirroring how the reference C miner's sha2.c/scrypt.c
// both sit on top of one sha256_transform()/HAVE_SHA256_4WAY primitive.
//
// Every transform below treats its input block(s) as raw bytes holding
// big-endian 32-bit words - the standard SHA-256 wire format, and the same
// convention util::be32enc/be32dec use elsewhere in this codebase - and
// takes/returns state as plain uint32_t words (no byte-swapping needed by
// callers).
//
// N-way ("batched") transforms process N independent messages at once for
// throughput, using a word-major/lane-minor layout: word `i` (0..15 for a
// block, 0..7 for a state) of lane `lane` (0..N-1) lives at index
// `i * N + lane`. Use packBlockWords()/lane-wise loops to build/consume
// this layout - see Sha256.cpp for the calling convention.

#include <cstdint>

namespace cppminer::simd {

inline constexpr uint32_t kSha256InitState[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

inline constexpr uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

// Scalar (1-way), portable, no intrinsics: always available, used as the
// baseline/fallback and as the correctness oracle the other backends are
// self-tested against.
void sha256TransformScalar(uint32_t state[8], const uint8_t block[64]);

// SSE2 4-way and AVX2 8-way batched transforms: `state`/`blocks` use the
// word-major/lane-minor layout described above, i.e. state[8*N] and
// blocks[16*N] words respectively. Only call these when
// cpuFeatures().sse2 / .avx2 is true (SSE2 is guaranteed on any x86-64
// build, so sha256Transform4way is always safe to call there).
void sha256Transform4way(uint32_t state[4 * 8], const uint32_t blocks[4 * 16]);
void sha256Transform8way(uint32_t state[8 * 8], const uint32_t blocks[8 * 16]);

// AVX-512F 16-way batched transform: same word-major/lane-minor layout as
// above, i.e. state[8*16] and blocks[16*16] words. This translation unit
// needs to be built with AVX-512F codegen enabled (/arch:AVX512 on MSVC,
// -mavx512f on GCC/Clang - see Sha256Avx512.cpp). This header doesn't add a
// CpuFeatures bit for AVX-512F (sse2/avx2 above are the only ones currently
// probed for) - callers must gate calls to this one accordingly, the same
// way sse2/avx2 are gated above, once runtime detection for it exists.
void sha256Transform16way(uint32_t state[16 * 8], const uint32_t blocks[16 * 16]);

// Hardware SHA extensions (single lane) - drop-in replacement for
// sha256TransformScalar with identical semantics, only safe to call when
// cpuFeatures().sha is true.
void sha256TransformShani(uint32_t state[8], const uint8_t block[64]);

#if defined(__aarch64__) || defined(_M_ARM64)
// AArch64-only backends, declared behind the same guard used to compile
// their implementation files (Sha256ArmNeon.cpp / Sha256ArmCrypto.cpp) so
// this header adds nothing on x64 builds:
//  - sha256Transform4wayNeon: 4-way NEON batched transform, same
//    word-major/lane-minor layout as the x86 N-way transforms above.
//  - sha256TransformArmCrypto: single-lane ARMv8 Cryptography Extensions
//    transform, analogous to sha256TransformShani above, only safe to call
//    when cpuFeatures().armSha2 is true.
void sha256Transform4wayNeon(uint32_t state[4 * 8], const uint32_t blocks[4 * 16]);
void sha256TransformArmCrypto(uint32_t state[8], const uint8_t block[64]);
#endif // defined(__aarch64__) || defined(_M_ARM64)

} // namespace cppminer::simd
