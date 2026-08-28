#pragma once

// Shared data structures describing "one unit of hashing work" for the two
// families of algorithms the miner supports:
//  - ClassicWork:   scrypt / sha256d, both hashing a classic 80-byte
//                   Bitcoin-style block header.
//  - WebchainWork:  lyra2web (MintMe Webchain), hashing an opaque
//                   pool-supplied job blob with an 8-byte nonce appended.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace cppminer {

enum class Algorithm {
    Scrypt,
    Sha256d,
    Lyra2Web,
    RandomX,
};

// Returns nullptr for an unrecognized value (should not happen for a
// validated Algorithm).
const char* algorithmName(Algorithm algo);

// Parses a CLI/config algorithm name. Accepts "scrypt", "scrypt:N", "sha256d"
// and "lyra2web" (case-insensitive). `scryptN` is left untouched unless the
// name has an explicit ":N" suffix.
bool algorithmFromName(const std::string& name, Algorithm& outAlgo, uint32_t& scryptN);

struct ClassicWork {
    // The true 80-byte block header, ready to feed to the hash function:
    // [0,4)=version [4,36)=prev block hash [36,68)=merkle root
    // [68,72)=ntime [72,76)=nbits [76,80)=nonce.
    std::array<uint8_t, 80> header{};
    std::array<uint32_t, 8> target{};

    std::string jobId;
    std::vector<uint8_t> extranonce2;
    // Original (wire) 4-byte ntime, echoed back verbatim on submit.
    std::array<uint8_t, 4> ntimeWire{};
    // Bumped by StratumClient every time a new job/extranonce2 is generated;
    // miner threads compare it to their locally cached value to notice
    // they need to fetch fresh work and to partition a fresh nonce range.
    uint64_t jobVersion = 0;
};

struct RandomXWork {
    // Cryptonote/Monero-style opaque blob with an embedded 4-byte nonce.
    std::vector<uint8_t> blob;
    std::array<uint8_t, 32> seedHash{};
    std::array<uint8_t, 8> target{};
    uint32_t nonceOffset = 39;

    std::string jobId;
    uint64_t jobVersion = 0;
};

struct WebchainWork {
    // Full opaque job template; the last 8 bytes are the nonce placeholder.
    std::vector<uint8_t> blob;
    std::array<uint8_t, 8> target{};
    uint32_t lyra2Tcost = 4;

    std::string jobId;
    uint64_t jobVersion = 0;
};

} // namespace cppminer
