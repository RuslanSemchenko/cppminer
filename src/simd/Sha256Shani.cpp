// Hardware-accelerated single-block SHA-256 using the Intel/AMD SHA
// extensions (SHA256RNDS2/SHA256MSG1/SHA256MSG2). This is the standard
// technique Intel published for these instructions (state repacked into
// two 128-bit "ABEF"/"CDGH" halves, message words byte-shuffled into
// big-endian lanes once up front, then four rounds processed per
// SHA256RNDS2 pair) - see e.g. Intel's "Intel SHA Extensions" whitepaper
// or the public-domain reference implementation these constants/shuffle
// masks were cross-checked against. Only the additive round constants
// come from this file's own kSha256K table (loaded 4 at a time) rather
// than being repeated as literals, so there is only one place in the
// codebase that can get the K table wrong.
#include "Sha256Simd.h"

#include <immintrin.h>

namespace cppminer::simd {

void sha256TransformShani(uint32_t state[8], const uint8_t block[64])
{
    const __m128i mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    __m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 0));
    __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 4));

    tmp = _mm_shuffle_epi32(tmp, 0xB1);          // CDAB
    state1 = _mm_shuffle_epi32(state1, 0x1B);    // EFGH
    __m128i state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
    state1 = _mm_blend_epi16(state1, tmp, 0xF0);      // CDGH

    const __m128i abefSave = state0;
    const __m128i cdghSave = state1;

    auto k4 = [](int i) { return _mm_loadu_si128(reinterpret_cast<const __m128i*>(kSha256K + i)); };

    // Rounds 0-3
    __m128i msg0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 0)), mask);
    __m128i msg = _mm_add_epi32(msg0, k4(0));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 4-7
    __m128i msg1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 16)), mask);
    msg = _mm_add_epi32(msg1, k4(4));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 8-11
    __m128i msg2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 32)), mask);
    msg = _mm_add_epi32(msg2, k4(8));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 12-15
    __m128i msg3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 48)), mask);
    msg = _mm_add_epi32(msg3, k4(12));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 16-63: the message schedule now cycles through msg0..msg3
    // (period 4). Each group of 4 rounds combines the "current" register
    // (holding W[k..k+3]) with the one written 3 groups ago (holding
    // W[k-4..k-1]) via SHA256MSG2 to produce W[k+4..k+7] into the "next"
    // register, and - except near the very end, where no further message
    // words are needed - also preps that same "3 groups ago" register via
    // SHA256MSG1 for its own SHA256MSG2 use 3 groups from now.
    struct Group {
        int k;
        bool extend;   // compute W[k+4..k+7] via alignr+SHA256MSG2
        bool prepNext; // trailing SHA256MSG1 update for a later group
    };
    static const Group groups[] = {
        {16, true, true}, {20, true, true}, {24, true, true}, {28, true, true},
        {32, true, true}, {36, true, true}, {40, true, true}, {44, true, true},
        {48, true, true}, {52, true, false}, {56, true, false}, {60, false, false},
    };
    __m128i* cur[4] = {&msg0, &msg1, &msg2, &msg3};
    for (int gi = 0; gi < 12; gi++) {
        __m128i& c0 = *cur[gi % 4];           // holds W[k..k+3] going in
        __m128i& c1 = *cur[(gi + 1) % 4];     // receives W[k+4..k+7]
        __m128i& cPrev = *cur[(gi + 3) % 4];  // holds W[k-4..k-1]

        msg = _mm_add_epi32(c0, k4(groups[gi].k));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        if (groups[gi].extend) {
            tmp = _mm_alignr_epi8(c0, cPrev, 4);
            c1 = _mm_add_epi32(c1, tmp);
            c1 = _mm_sha256msg2_epu32(c1, c0);
        }
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        if (groups[gi].prepNext)
            cPrev = _mm_sha256msg1_epu32(cPrev, c0);
    }

    state0 = _mm_add_epi32(state0, abefSave);
    state1 = _mm_add_epi32(state1, cdghSave);

    tmp = _mm_shuffle_epi32(state0, 0x1B);      // FEBA
    state1 = _mm_shuffle_epi32(state1, 0xB1);   // DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
    state1 = _mm_alignr_epi8(state1, tmp, 8);    // ABEF

    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 0), state0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 4), state1);
}

} // namespace cppminer::simd
