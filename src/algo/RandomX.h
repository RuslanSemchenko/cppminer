#pragma once

#include "../BenchResult.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace cppminer::algo {

// Shared cache/dataset state. A cache is initialized once per seed and reused
// by every worker; full-memory mode additionally owns one shared ~2 GiB dataset.
class RandomXState {
public:
    // fullMemory=false uses RandomX light mode (~256 MiB shared state),
    // while true uses the faster full dataset mode (~2 GiB shared state).
    explicit RandomXState(bool fullMemory = false, bool largePages = false);
    ~RandomXState();

    RandomXState(const RandomXState&) = delete;
    RandomXState& operator=(const RandomXState&) = delete;

    // Initializes/reinitializes the shared state for a 32-byte RandomX seed.
    // Returns a human-readable error and leaves the state unchanged on failure.
    bool prepare(const uint8_t* seed, size_t seedSize, std::string& error);
    const char* modeName() const;
    size_t datasetBytes() const;

private:
    friend class RandomXContext;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Each worker owns one VM. The cache/dataset remains shared through state.
class RandomXContext {
public:
    explicit RandomXContext(RandomXState& state);
    ~RandomXContext();

    RandomXContext(const RandomXContext&) = delete;
    RandomXContext& operator=(const RandomXContext&) = delete;

    bool hash(const uint8_t* input, size_t inputSize, const uint8_t* seed, size_t seedSize,
              uint8_t output[32], std::string& error);
    bool hashPair(const uint8_t* inputA, size_t inputASize, const uint8_t* inputB, size_t inputBSize,
                  const uint8_t* seed, size_t seedSize, uint8_t outputA[32], uint8_t outputB[32],
                  std::string& error);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// RandomX's common Monero-family work format: an opaque blob containing a
// 4-byte little-endian nonce at nonceOffset, a separate 32-byte seed key, and
// a target represented by its little-endian 64-bit comparison value.
void randomXHash(RandomXContext& context, std::vector<uint8_t>& blob, size_t nonceOffset,
                 const std::array<uint8_t, 32>& seed, uint8_t output[32], std::string& error);

bool scanHashRandomX(RandomXContext& context, const std::vector<uint8_t>& blob, size_t nonceOffset,
                     const std::array<uint8_t, 32>& seed, const uint8_t target[8], uint32_t maxNonce,
                     uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone,
                     uint8_t resultHash[32], std::string& error);

// Runs the official RandomX API/example vector in light mode and checks the
// complete blob/nonce path separately. Called once before mining.
bool randomXSelfTest();
const char* randomXActiveBackendName();
const char* randomXSimdFeaturesString();
std::vector<cppminer::BackendBenchResult> randomXBenchmarkArgonBackends(double secondsPerBackend);

} // namespace cppminer::algo
