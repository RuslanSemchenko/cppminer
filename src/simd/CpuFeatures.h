#pragma once

// Runtime x86/x86-64 CPU feature detection (CPUID-based), used to pick the
// fastest available implementation of the sha256d/scrypt hot loops at
// startup: hardware SHA extensions and/or AVX2/SSE2 software vector paths,
// falling back to plain scalar C++ on anything older (or non-x86). This is
// the same "detect once, dispatch forever" approach the reference miner
// uses via sha256_use_4way()/sha256_use_8way()/scrypt_best_throughput(),
// just implemented with intrinsics instead of hand-written assembly.

namespace cppminer::simd {

struct CpuFeatures {
    bool sse2 = false;
    bool ssse3 = false;
    bool sse41 = false;
    bool avx = false;
    bool avx2 = false;
    bool avx512f = false; // 512-bit integer ops (Intel Ice Lake+/Zen4+/some servers)
    bool sha = false; // Intel SHA / AMD SHA extensions (SHA256RNDS2 et al.)

    // ARM/AArch64 fields (always false on x86 - this project's actual
    // build - since detect() only ever sets them under an AArch64 guard).
    bool neon = false; // always true on AArch64; this field exists for symmetry/logging only
    bool armSha2 = false; // ARMv8 Cryptography Extensions (SHA256H et al.), detected at runtime
};

// Detected once (on first use) and cached; safe to call from any thread.
const CpuFeatures& cpuFeatures();

// Human-readable summary for startup/benchmark logging, e.g.
// "SSE2 SSSE3 SSE4.1 AVX AVX2 SHA".
const char* cpuFeaturesString();

} // namespace cppminer::simd
