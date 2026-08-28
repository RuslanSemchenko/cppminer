#include "CpuFeatures.h"

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

// ARM runtime-feature-detection headers - only ever pulled in when actually
// targeting AArch64, so this is a complete no-op on this project's real
// x64/MSVC/Windows build.
#if defined(__aarch64__) || defined(_M_ARM64)
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#elif defined(_WIN32)
#include <windows.h>
#include <processthreadsapi.h>
#endif
#endif

#include <cstdint>
#include <cstring>
#include <string>

namespace cppminer::simd {

namespace {

#if defined(_MSC_VER)
void cpuidRaw(uint32_t leaf, uint32_t subleaf, uint32_t out[4])
{
    int regs[4];
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
    for (int i = 0; i < 4; i++)
        out[i] = static_cast<uint32_t>(regs[i]);
}

uint64_t xgetbv(uint32_t index)
{
    return _xgetbv(index);
}
#elif defined(__x86_64__) || defined(__i386__)
void cpuidRaw(uint32_t leaf, uint32_t subleaf, uint32_t out[4])
{
    __cpuid_count(leaf, subleaf, out[0], out[1], out[2], out[3]);
}

uint64_t xgetbv(uint32_t index)
{
    uint32_t eax, edx;
    __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(index));
    return (static_cast<uint64_t>(edx) << 32) | eax;
}
#endif

CpuFeatures detect()
{
    CpuFeatures f;
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    uint32_t regs[4] = {0, 0, 0, 0};
    cpuidRaw(0, 0, regs);
    uint32_t maxLeaf = regs[0];

    if (maxLeaf >= 1) {
        cpuidRaw(1, 0, regs);
        uint32_t ecx = regs[2];
        uint32_t edx = regs[3];
        f.sse2 = (edx & (1u << 26)) != 0;
        f.ssse3 = (ecx & (1u << 9)) != 0;
        f.sse41 = (ecx & (1u << 19)) != 0;

        bool osxsave = (ecx & (1u << 27)) != 0;
        bool avxBit = (ecx & (1u << 28)) != 0;
        if (avxBit && osxsave) {
            // Confirm the OS actually saves/restores YMM state (bits 1 and
            // 2 of XCR0), not just that the CPU can execute AVX - an AVX
            // capable CPU running under an OS/hypervisor that never called
            // XSETBV for YMM would fault on the first AVX instruction.
            uint64_t xcr0 = xgetbv(0);
            if ((xcr0 & 0x6ull) == 0x6ull)
                f.avx = true;
        }
    }

    if (maxLeaf >= 7) {
        cpuidRaw(7, 0, regs);
        uint32_t ebx = regs[1];
        bool avx2Bit = (ebx & (1u << 5)) != 0;
        bool avx512fBit = (ebx & (1u << 16)) != 0;
        bool shaBit = (ebx & (1u << 29)) != 0;

        // SHA extensions only touch legacy 128-bit XMM state, which every
        // OS already enables unconditionally - no XCR0 check needed there.
        f.sha = shaBit;
        // AVX2 (256-bit YMM), on the other hand, needs the same OS support
        // as AVX.
        if (avx2Bit && f.avx)
            f.avx2 = true;
        // AVX-512F (512-bit ZMM) additionally needs the OS to save/restore
        // the opmask (bit 5), ZMM_Hi256 (bit 6) and Hi16_ZMM (bit 7) state,
        // on top of the SSE/AVX bits already required above.
        if (avx512fBit && f.avx) {
            uint64_t xcr0 = xgetbv(0);
            if ((xcr0 & 0xe6ull) == 0xe6ull)
                f.avx512f = true;
        }
    }
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
    // NEON is a mandatory part of the AArch64 base architecture (unlike
    // 32-bit ARM, where it was optional), so this is set unconditionally
    // rather than actually probed for - it only exists for symmetry with
    // the other feature bits and for logging via cpuFeaturesString().
    f.neon = true;

#if defined(__APPLE__)
    // Every Apple Silicon chip (M1 and later) implements the ARMv8.2
    // Cryptography Extensions, including SHA256 - safe to assume true
    // unconditionally instead of chasing down the exact sysctlbyname() key.
    f.armSha2 = true;
#elif defined(__linux__)
    f.armSha2 = (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#elif defined(_WIN32)
    f.armSha2 = IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
#endif
#endif
    return f;
}

std::string buildFeaturesString(const CpuFeatures& f)
{
    std::string s;
    auto add = [&](bool present, const char* name) {
        if (!present)
            return;
        if (!s.empty())
            s += ' ';
        s += name;
    };
    add(f.sse2, "SSE2");
    add(f.ssse3, "SSSE3");
    add(f.sse41, "SSE4.1");
    add(f.avx, "AVX");
    add(f.avx2, "AVX2");
    add(f.avx512f, "AVX512F");
    add(f.sha, "SHA");
    add(f.neon, "NEON");
    add(f.armSha2, "ARMv8-SHA2");
    if (s.empty())
        s = "(none - portable scalar fallback only)";
    return s;
}

} // namespace

const CpuFeatures& cpuFeatures()
{
    static const CpuFeatures features = detect();
    return features;
}

const char* cpuFeaturesString()
{
    static const std::string str = buildFeaturesString(cpuFeatures());
    return str.c_str();
}

} // namespace cppminer::simd
