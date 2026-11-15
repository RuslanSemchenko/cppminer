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
    return ((v & 0x000000ffU) << 24u) | ((v & 0x0000ff00U) << 8u) |
           ((v & 0x00ff0000U) >> 8u)  | ((v & 0xff000000U) >> 24u);
}

inline uint64_t swab64(uint64_t v)
{
    return ((v & 0x00000000000000ffULL) << 56ULL) | ((v & 0x000000000000ff00ULL) << 40ULL) |
           ((v & 0x0000000000ff0000ULL) << 24ULL) | ((v & 0x00000000ff000000ULL) << 8ULL)  |
           ((v & 0x000000ff00000000ULL) >> 8ULL)  | ((v & 0x0000ff0000000000ULL) >> 24ULL) |
           ((v & 0x00ff000000000000ULL) >> 40ULL) | ((v & 0xff00000000000000ULL) >> 56ULL);
}

inline uint32_t be32dec(const void* pp)
{
    const uint8_t* p = static_cast<const uint8_t*>(pp);
    return (static_cast<uint32_t>(p[0]) << 24u)
         | (static_cast<uint32_t>(p[1]) << 16u)
         | (static_cast<uint32_t>(p[2]) << 8u)
         | static_cast<uint32_t>(p[3]);
}

inline uint32_t le32dec(const void* pp)
{
    const uint8_t* p = static_cast<const uint8_t*>(pp);
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8u)
         | (static_cast<uint32_t>(p[2]) << 16u)
         | (static_cast<uint32_t>(p[3]) << 24u);
}

inline void be32enc(void* pp, uint32_t x)
{
    uint8_t* p = static_cast<uint8_t*>(pp);
    p[0] = static_cast<uint8_t>(x >> 24u);
    p[1] = static_cast<uint8_t>(x >> 16u);
    p[2] = static_cast<uint8_t>(x >> 8u);
    p[3] = static_cast<uint8_t>(x);
}

inline void le32enc(void* pp, uint32_t x)
{
    uint8_t* p = static_cast<uint8_t*>(pp);
    p[0] = static_cast<uint8_t>(x);
    p[1] = static_cast<uint8_t>(x >> 8u);
    p[2] = static_cast<uint8_t>(x >> 16u);
    p[3] = static_cast<uint8_t>(x >> 24u);
}

inline uint64_t le64dec(const void* pp)
{
    const uint8_t* p = static_cast<const uint8_t*>(pp);
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8u) | p[static_cast<size_t>(i)];
    }
    return v;
}

inline void le64enc(void* pp, uint64_t x)
{
    uint8_t* p = static_cast<uint8_t*>(pp);
    for (int i = 0; i < 8; ++i) {
        p[static_cast<size_t>(i)] = static_cast<uint8_t>(x);
        x >>= 8u;
    }
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

void diffToTarget(uint32_t* target, double diff);
bool fullTest(const uint32_t* hash, const uint32_t* target);

} // namespace cppminer::util
