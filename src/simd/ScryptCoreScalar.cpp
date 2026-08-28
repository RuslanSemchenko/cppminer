#include "ScryptSimd.h"

#include <cstring>

namespace cppminer::simd {

namespace {

inline uint32_t rotl(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

// Direct port of the well known public-domain xor_salsa8 (Colin Percival's
// scrypt reference / the reference miner's scrypt.c): B ^= Bx, then 4
// double-rounds of the Salsa20 core permutation, then feed the original
// (post-xor) block back in with a final add.
void xorSalsa8(uint32_t B[16], const uint32_t Bx[16])
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (B[i] ^= Bx[i]);

    for (int r = 0; r < 8; r += 2) {
        x[4] ^= rotl(x[0] + x[12], 7);   x[9] ^= rotl(x[5] + x[1], 7);
        x[14] ^= rotl(x[10] + x[6], 7);  x[3] ^= rotl(x[15] + x[11], 7);
        x[8] ^= rotl(x[4] + x[0], 9);    x[13] ^= rotl(x[9] + x[5], 9);
        x[2] ^= rotl(x[14] + x[10], 9);  x[7] ^= rotl(x[3] + x[15], 9);
        x[12] ^= rotl(x[8] + x[4], 13);  x[1] ^= rotl(x[13] + x[9], 13);
        x[6] ^= rotl(x[2] + x[14], 13);  x[11] ^= rotl(x[7] + x[3], 13);
        x[0] ^= rotl(x[12] + x[8], 18);  x[5] ^= rotl(x[1] + x[13], 18);
        x[10] ^= rotl(x[6] + x[2], 18);  x[15] ^= rotl(x[11] + x[7], 18);

        x[1] ^= rotl(x[0] + x[3], 7);    x[6] ^= rotl(x[5] + x[4], 7);
        x[11] ^= rotl(x[10] + x[9], 7);  x[12] ^= rotl(x[15] + x[14], 7);
        x[2] ^= rotl(x[1] + x[0], 9);    x[7] ^= rotl(x[6] + x[5], 9);
        x[8] ^= rotl(x[11] + x[10], 9);  x[13] ^= rotl(x[12] + x[15], 9);
        x[3] ^= rotl(x[2] + x[1], 13);   x[4] ^= rotl(x[7] + x[6], 13);
        x[9] ^= rotl(x[8] + x[11], 13);  x[14] ^= rotl(x[13] + x[12], 13);
        x[0] ^= rotl(x[3] + x[2], 18);   x[5] ^= rotl(x[4] + x[7], 18);
        x[10] ^= rotl(x[9] + x[8], 18);  x[15] ^= rotl(x[14] + x[13], 18);
    }

    for (int i = 0; i < 16; i++)
        B[i] += x[i];
}

} // namespace

void scryptRomixScalar(uint32_t B[32], uint32_t* V, uint32_t costN)
{
    for (uint32_t i = 0; i < costN; i++) {
        std::memcpy(V + size_t(i) * 32, B, 128);
        xorSalsa8(B + 0, B + 16);
        xorSalsa8(B + 16, B + 0);
    }
    for (uint32_t i = 0; i < costN; i++) {
        uint32_t j = 32 * (B[16] & (costN - 1));
        for (int k = 0; k < 32; k++)
            B[k] ^= V[j + k];
        xorSalsa8(B + 0, B + 16);
        xorSalsa8(B + 16, B + 0);
    }
}

} // namespace cppminer::simd
