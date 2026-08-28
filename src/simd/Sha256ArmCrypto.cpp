// Hardware-accelerated single-block SHA-256 using the ARMv8 Cryptography
// Extensions (SHA256H/SHA256H2/SHA256SU0/SHA256SU1) - the AArch64
// counterpart of Sha256Shani.cpp's x86 SHA-NI version, and a drop-in
// replacement for sha256TransformScalar with identical semantics. This
// project currently only ships an x64/MSVC/Windows build, so the whole
// translation unit (the <arm_neon.h> include included) is compiled out
// below and has zero effect there; it only becomes active when built for
// AArch64.
//
// Transcribed round-for-round from, and verified line-by-line against, the
// public-domain reference implementation in noloader/SHA-Intrinsics'
// sha256-arm.c
// (https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-arm.c),
// written by Jeffrey Walton, itself based on code from ARM and on Johannes
// Schneiders/Skip Hovsmith/Barry O'Rourke's mbedTLS contribution; that file
// also embeds a known-answer self-test (SHA-256 of an empty, correctly
// padded message) which was used as the correctness oracle while porting.
// The overall register/round structure was further cross-checked against
// mbedTLS's own ARMv8-CE sha256.c, which implements the identical algorithm
// under different variable names (abcd/efgh/sched) - both agree that the
// pre-update value of state0/abcd must be snapshotted (see `tmp2` below)
// before it gets overwritten, and only *that* saved copy fed into the
// second hash-round intrinsic - the one detail here that's easy to get
// backwards (and has caused real-world bugs in other projects when gotten
// wrong).
//
// Unlike the x86 SHA extensions (Sha256Shani.cpp), ARMv8's SHA256H/SHA256H2
// need no ABEF/CDGH shuffle beforehand: state0/state1 hold the state words
// in plain A,B,C,D / E,F,G,H order on both load and store.
#if defined(__aarch64__) || defined(_M_ARM64)

#include "Sha256Simd.h"

#include <arm_neon.h>

namespace cppminer::simd {

void sha256TransformArmCrypto(uint32_t state[8], const uint8_t block[64])
{
    uint32x4_t state0 = vld1q_u32(state + 0);
    uint32x4_t state1 = vld1q_u32(state + 4);
    const uint32x4_t abcdSave = state0;
    const uint32x4_t efghSave = state1;

    auto k4 = [](int i) { return vld1q_u32(kSha256K + i); };

    // SHA-256 message words are big-endian on the wire (the same
    // convention util::be32dec uses elsewhere in this codebase), but
    // AArch64 is little-endian, so byte-swap each loaded word.
    uint32x4_t msg0 = vld1q_u32(reinterpret_cast<const uint32_t*>(block + 0));
    uint32x4_t msg1 = vld1q_u32(reinterpret_cast<const uint32_t*>(block + 16));
    uint32x4_t msg2 = vld1q_u32(reinterpret_cast<const uint32_t*>(block + 32));
    uint32x4_t msg3 = vld1q_u32(reinterpret_cast<const uint32_t*>(block + 48));
    msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
    msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
    msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
    msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));

    uint32x4_t tmp0 = vaddq_u32(msg0, k4(0));
    uint32x4_t tmp1, tmp2;

    // Rounds 0-3
    msg0 = vsha256su0q_u32(msg0, msg1);
    tmp2 = state0;
    tmp1 = vaddq_u32(msg1, k4(4));
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp2, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // Rounds 4-7
    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp2 = state0;
    tmp0 = vaddq_u32(msg2, k4(8));
    state0 = vsha256hq_u32(state0, state1, tmp1);
    state1 = vsha256h2q_u32(state1, tmp2, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // Rounds 8-11
    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp2 = state0;
    tmp1 = vaddq_u32(msg3, k4(12));
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp2, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // Rounds 12-15
    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp2 = state0;
    tmp0 = vaddq_u32(msg0, k4(16));
    state0 = vsha256hq_u32(state0, state1, tmp1);
    state1 = vsha256h2q_u32(state1, tmp2, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // Rounds 16-19
    msg0 = vsha256su0q_u32(msg0, msg1);
    tmp2 = state0;
    tmp1 = vaddq_u32(msg1, k4(20));
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp2, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // Rounds 20-23
    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp2 = state0;
    tmp0 = vaddq_u32(msg2, k4(24));
    state0 = vsha256hq_u32(state0, state1, tmp1);
    state1 = vsha256h2q_u32(state1, tmp2, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // Rounds 24-27
    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp2 = state0;
    tmp1 = vaddq_u32(msg3, k4(28));
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp2, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // Rounds 28-31
    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp2 = state0;
    tmp0 = vaddq_u32(msg0, k4(32));
    state0 = vsha256hq_u32(state0, state1, tmp1);
    state1 = vsha256h2q_u32(state1, tmp2, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // Rounds 32-35
    msg0 = vsha256su0q_u32(msg0, msg1);
    tmp2 = state0;
    tmp1 = vaddq_u32(msg1, k4(36));
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp2, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // Rounds 36-39
    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp2 = state0;
    tmp0 = vaddq_u32(msg2, k4(40));
    state0 = vsha256hq_u32(state0, state1, tmp1);
    state1 = vsha256h2q_u32(state1, tmp2, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // Rounds 40-43
    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp2 = state0;
    tmp1 = vaddq_u32(msg3, k4(44));
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp2, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // Rounds 44-47
    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp2 = state0;
    tmp0 = vaddq_u32(msg0, k4(48));
    state0 = vsha256hq_u32(state0, state1, tmp1);
    state1 = vsha256h2q_u32(state1, tmp2, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // Rounds 48-51 (no more message-schedule words are needed past this point)
    tmp2 = state0;
    tmp1 = vaddq_u32(msg1, k4(52));
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp2, tmp0);

    // Rounds 52-55
    tmp2 = state0;
    tmp0 = vaddq_u32(msg2, k4(56));
    state0 = vsha256hq_u32(state0, state1, tmp1);
    state1 = vsha256h2q_u32(state1, tmp2, tmp1);

    // Rounds 56-59
    tmp2 = state0;
    tmp1 = vaddq_u32(msg3, k4(60));
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp2, tmp0);

    // Rounds 60-63
    tmp2 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp1);
    state1 = vsha256h2q_u32(state1, tmp2, tmp1);

    state0 = vaddq_u32(state0, abcdSave);
    state1 = vaddq_u32(state1, efghSave);

    vst1q_u32(state + 0, state0);
    vst1q_u32(state + 4, state1);
}

} // namespace cppminer::simd

#endif // defined(__aarch64__) || defined(_M_ARM64)
