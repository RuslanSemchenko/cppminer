#pragma once

// Lyra2/Webchain SIMD backends. Each ISA-specific implementation lives in its
// own translation unit and is runtime-gated by CpuFeatures before invocation.
// The scalar LYRA2 implementation remains the portable oracle/fallback.

#include <cstddef>
#include <cstdint>

namespace cppminer::simd {

struct Lyra2Sse2Context;
Lyra2Sse2Context* lyra2Sse2Create();
void lyra2Sse2Destroy(Lyra2Sse2Context* ctx);
void lyra2Sse2Hash2(Lyra2Sse2Context& ctx, const uint8_t* blob, size_t blobSize,
                    uint64_t firstNonce, uint32_t timeCost, uint8_t out[2][32]);

struct Lyra2Avx2Context;
Lyra2Avx2Context* lyra2Avx2Create();
void lyra2Avx2Destroy(Lyra2Avx2Context* ctx);
void lyra2Avx2Hash4(Lyra2Avx2Context& ctx, const uint8_t* blob, size_t blobSize,
                    uint64_t firstNonce, uint32_t timeCost, uint8_t out[4][32]);

struct Lyra2Avx512Context;
Lyra2Avx512Context* lyra2Avx512Create();
void lyra2Avx512Destroy(Lyra2Avx512Context* ctx);
void lyra2Avx512Hash8(Lyra2Avx512Context& ctx, const uint8_t* blob, size_t blobSize,
                      uint64_t firstNonce, uint32_t timeCost, uint8_t out[8][32]);

} // namespace cppminer::simd
