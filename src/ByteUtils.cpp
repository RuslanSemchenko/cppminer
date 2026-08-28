#include "ByteUtils.h"

namespace cppminer::util {

namespace {
inline int hexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
} // namespace

bool hex2bin(uint8_t* out, const std::string& hex, size_t outLen)
{
    if (hex.size() != outLen * 2)
        return false;
    for (size_t i = 0; i < outLen; ++i) {
        int hi = hexValue(hex[2 * i]);
        int lo = hexValue(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = uint8_t((hi << 4) | lo);
    }
    return true;
}

std::string bin2hex(const uint8_t* data, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    std::string s(len * 2, '0');
    for (size_t i = 0; i < len; ++i) {
        s[2 * i]     = digits[(data[i] >> 4) & 0xf];
        s[2 * i + 1] = digits[data[i] & 0xf];
    }
    return s;
}

std::vector<uint8_t> hexToBytes(const std::string& hex)
{
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0)
        return out;
    out.resize(hex.size() / 2);
    if (!hex2bin(out.data(), hex, out.size()))
        out.clear();
    return out;
}

void diffToTarget(uint32_t target[8], double diff)
{
    int k = 6;
    for (; k > 0 && diff > 1.0; k--)
        diff /= 4294967296.0;
    uint64_t m = (uint64_t)(4294901760.0 / diff);
    if (m == 0 && k == 6) {
        for (int i = 0; i < 8; i++)
            target[i] = 0xffffffffu;
    } else {
        for (int i = 0; i < 8; i++)
            target[i] = 0;
        target[k] = (uint32_t)m;
        target[k + 1] = (uint32_t)(m >> 32);
    }
}

bool fullTest(const uint32_t hash[8], const uint32_t target[8])
{
    bool rc = true;
    for (int i = 7; i >= 0; i--) {
        if (hash[i] > target[i]) { rc = false; break; }
        if (hash[i] < target[i]) { rc = true; break; }
    }
    return rc;
}

} // namespace cppminer::util
