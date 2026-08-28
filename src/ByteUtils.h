#pragma once

// Small, self-contained collection of byte/word helpers used throughout the
// miner: hex<->binary conversion, big/little-endian codecs (named after the
// well known be32dec/le32dec/swab32 helpers from the reference cpuminer C
// code, since the mining wire protocols are built entirely out of them) and
// the difficulty<->target conversion used to decide whether a hash is a
// valid share.

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace cppminer::util {

inline uint32_t swab32(uint32_t v)
{
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
           ((v & 0x00ff0000u) >> 8)  | ((v & 0xff000000u) >> 24);
}

inline uint64_t swab64(uint64_t v)
{
    return ((v & 0x00000000000000ffULL) << 56) | ((v & 0x000000000000ff00ULL) << 40) |
           ((v & 0x0000000000ff0000ULL) << 24) | ((v & 0x00000000ff000000ULL) << 8)  |
           ((v & 0x000000ff00000000ULL) >> 8)  | ((v & 0x0000ff0000000000ULL) >> 24) |
           ((v & 0x00ff000000000000ULL) >> 40) | ((v & 0xff00000000000000ULL) >> 56);
}

inline uint32_t be32dec(const void* pp)
{
    const uint8_t* p = static_cast<const uint8_t*>(pp);
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline uint32_t le32dec(const void* pp)
{
    const uint8_t* p = static_cast<const uint8_t*>(pp);
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

inline void be32enc(void* pp, uint32_t x)
{
    uint8_t* p = static_cast<uint8_t*>(pp);
    p[0] = uint8_t(x >> 24); p[1] = uint8_t(x >> 16); p[2] = uint8_t(x >> 8); p[3] = uint8_t(x);
}

inline void le32enc(void* pp, uint32_t x)
{
    uint8_t* p = static_cast<uint8_t*>(pp);
    p[0] = uint8_t(x); p[1] = uint8_t(x >> 8); p[2] = uint8_t(x >> 16); p[3] = uint8_t(x >> 24);
}

inline uint64_t le64dec(const void* pp)
{
    const uint8_t* p = static_cast<const uint8_t*>(pp);
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i)
        v = (v << 8) | p[i];
    return v;
}

inline void le64enc(void* pp, uint64_t x)
{
    uint8_t* p = static_cast<uint8_t*>(pp);
    for (int i = 0; i < 8; ++i) { p[i] = uint8_t(x); x >>= 8; }
}

// hex helpers -----------------------------------------------------------

// Decodes exactly `outLen` bytes from `hex` (which must be `outLen * 2`
// characters long). Returns false on malformed input.
bool hex2bin(uint8_t* out, const std::string& hex, size_t outLen);

std::string bin2hex(const uint8_t* data, size_t len);

// Convenience wrapper: size is derived from the hex string; returns an
// empty vector if `hex` has an odd length or contains invalid characters.
std::vector<uint8_t> hexToBytes(const std::string& hex);

// difficulty / target ----------------------------------------------------
//
// `target`/`hash` are 8-word (256-bit) big numbers stored the same way the
// original cpuminer stores them: target[0] is the least significant 32-bit
// limb, target[7] the most significant one.

void diffToTarget(uint32_t target[8], double diff);
bool fullTest(const uint32_t hash[8], const uint32_t target[8]);

} // namespace cppminer::util
