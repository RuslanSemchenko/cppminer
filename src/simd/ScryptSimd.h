#pragma once

// N-way batched scrypt ROMix (the Salsa20/8-based memory-hard core that
// dominates scrypt(N,r=1,p=1)'s cost - see algo/Scrypt.cpp for the
// PBKDF2/HMAC-SHA256 wrapper around it). Batches W independent nonces so
// the pure-arithmetic Salsa20/8 quarter-rounds run W-wide per instruction,
// and so the data-dependent random reads ROMix does ("read V[j], j comes
// from the running state") can overlap across W independent, largely
// uncorrelated cache misses instead of happening one nonce at a time -
// for a memory-bound algorithm like scrypt this latency-hiding effect
// typically matters as much as the arithmetic vectorization itself.
//
// Layout (mirrors Sha256Simd.h's N-way convention): `B` holds W lanes'
// 32-word (128-byte) scrypt block in word-major/lane-minor order - word
// `i` (0..31) of lane `lane` (0..W-1) lives at `B[i*W+lane]`. `V` is the
// ROMix scratch buffer, one independent length-N history per lane, same
// per-row word-major/lane-minor layout; size it with scryptScratchWords().
//
// Deliberately does NOT use hardware gather instructions (AVX2
// vpgatherdd) for the "read V[j]" step even on backends where it exists:
// AMD's Zen-family gather implementation is well known to be slow (often
// no faster than sequential scalar loads), so every width here builds the
// gathered vector via W ordinary scalar loads instead - simpler, and at
// least as fast as gather on the CPU families the reference miner and
// this project actually target.

#include <cstddef>
#include <cstdint>

namespace cppminer::simd {

constexpr size_t scryptScratchWords(uint32_t costN, int width)
{
    return size_t(costN) * 32 * size_t(width);
}

// Scalar (1-way): B[32], V must hold scryptScratchWords(costN, 1) words.
// Portable baseline/fallback and the correctness oracle the batched
// backends are self-tested against.
void scryptRomixScalar(uint32_t B[32], uint32_t* V, uint32_t costN);

// SSE2 4-way / AVX2 8-way / AVX-512F 16-way: B[32*W], V must hold
// scryptScratchWords(costN, W) words. Only call scryptRomix8way when
// cpuFeatures().avx2 is true, scryptRomix16way when cpuFeatures().avx512f
// is true; SSE2 is guaranteed on any x86-64 build.
void scryptRomix4way(uint32_t B[32 * 4], uint32_t* V, uint32_t costN);
void scryptRomix8way(uint32_t B[32 * 8], uint32_t* V, uint32_t costN);
void scryptRomix16way(uint32_t B[32 * 16], uint32_t* V, uint32_t costN);

} // namespace cppminer::simd
