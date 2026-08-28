#include "Lyra2Simd.h"

#if !defined(__SSE2__) && !defined(_M_X64)
namespace cppminer::simd {

struct Lyra2Sse2Context {};

Lyra2Sse2Context* lyra2Sse2Create()
{
    return nullptr;
}

void lyra2Sse2Destroy(Lyra2Sse2Context*)
{
}

void lyra2Sse2Hash2(Lyra2Sse2Context&, const uint8_t*, size_t, uint64_t, uint32_t, uint8_t[2][32])
{
}

} // namespace cppminer::simd
#endif

#if !defined(__AVX2__)
namespace cppminer::simd {

struct Lyra2Avx2Context {};

Lyra2Avx2Context* lyra2Avx2Create()
{
    return nullptr;
}

void lyra2Avx2Destroy(Lyra2Avx2Context*)
{
}

void lyra2Avx2Hash4(Lyra2Avx2Context&, const uint8_t*, size_t, uint64_t, uint32_t, uint8_t[4][32])
{
}

} // namespace cppminer::simd
#endif

#if !defined(__AVX512F__)
namespace cppminer::simd {

struct Lyra2Avx512Context {};

Lyra2Avx512Context* lyra2Avx512Create()
{
    return nullptr;
}

void lyra2Avx512Destroy(Lyra2Avx512Context*)
{
}

void lyra2Avx512Hash8(Lyra2Avx512Context&, const uint8_t*, size_t, uint64_t, uint32_t, uint8_t[8][32])
{
}

} // namespace cppminer::simd
#endif
