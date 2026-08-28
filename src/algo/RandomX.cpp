#include "RandomX.h"

#include "../BenchResult.h"
#include "../ByteUtils.h"

#include "randomx/argon2.h"
#include "randomx/randomx.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <shared_mutex>
#include <stdexcept>

#ifdef _WIN32
#include <stdlib.h>
#endif

namespace cppminer::algo {
namespace {

bool randomXPipelineEnabled()
{
#ifdef _WIN32
    char* value = nullptr;
    size_t length = 0;
    const bool hasValue = _dupenv_s(&value, &length, "CPPMINER_RANDOMX_PIPELINE") == 0 && value != nullptr;
    const bool enabled = !hasValue || std::strcmp(value, "0") != 0;
    if (value)
        free(value);
    return enabled;
#else
    const char* value = std::getenv("CPPMINER_RANDOMX_PIPELINE");
    return !value || std::strcmp(value, "0") != 0;
#endif
}

const char* randomXArgonBackendName(randomx_flags flags)
{
    if (flags & RANDOMX_FLAG_ARGON2_AVX2)
        return "Argon2-AVX2";
    if (flags & RANDOMX_FLAG_ARGON2_SSSE3)
        return "Argon2-SSSE3";
    return "Argon2-scalar";
}

std::string randomXDescribeFlags(randomx_flags flags)
{
    std::ostringstream oss;
    if (flags & RANDOMX_FLAG_JIT)
        oss << "JIT";
    else
        oss << "interpreted";
    if (flags & RANDOMX_FLAG_HARD_AES)
        oss << " + Hard-AES";
    else
        oss << " + soft-AES";
    oss << " + " << randomXArgonBackendName(flags);
    if (randomXPipelineEnabled())
        oss << " + 2-way pipeline";
    return oss.str();
}

} // namespace

struct RandomXState::Impl {
    explicit Impl(bool useFullMemory, bool useLargePages)
        : fullMemory(useFullMemory), largePages(useLargePages)
    {
        flags = randomx_get_flags();
        if (fullMemory)
            flags = static_cast<randomx_flags>(flags | RANDOMX_FLAG_FULL_MEM);
        if (largePages)
            flags = static_cast<randomx_flags>(flags | RANDOMX_FLAG_LARGE_PAGES);

        const randomx_flags cacheFlags = static_cast<randomx_flags>(
            flags & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_ARGON2));
        cache = randomx_alloc_cache(cacheFlags);
        if (!cache)
            throw std::runtime_error("RandomX cache allocation failed");

        if (fullMemory) {
            const randomx_flags datasetFlags = static_cast<randomx_flags>(flags & RANDOMX_FLAG_LARGE_PAGES);
            dataset = randomx_alloc_dataset(datasetFlags);
            if (!dataset)
                throw std::runtime_error("RandomX dataset allocation failed");
            datasetBytes = static_cast<size_t>(randomx_dataset_item_count()) * RANDOMX_DATASET_ITEM_SIZE;
        }
    }

    ~Impl()
    {
        if (dataset)
            randomx_release_dataset(dataset);
        if (cache)
            randomx_release_cache(cache);
    }

    bool fullMemory = false;
    bool largePages = false;
    randomx_flags flags = RANDOMX_FLAG_DEFAULT;
    randomx_cache* cache = nullptr;
    randomx_dataset* dataset = nullptr;
    size_t datasetBytes = 0;
    std::array<uint8_t, 32> seed{};
    size_t seedSize = 0;
    bool initialized = false;
    mutable std::shared_mutex mutex;
};

RandomXState::RandomXState(bool fullMemory, bool largePages)
    : impl_(std::make_unique<Impl>(fullMemory, largePages))
{
}

RandomXState::~RandomXState() = default;

bool RandomXState::prepare(const uint8_t* seed, size_t seedSize, std::string& error)
{
    if (!seed || seedSize == 0 || seedSize > 32) {
        error = "RandomX seed must contain 1..32 bytes";
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    if (impl_->initialized && impl_->seedSize == seedSize &&
        std::memcmp(impl_->seed.data(), seed, seedSize) == 0)
        return true;

    std::array<uint8_t, 32> nextSeed{};
    std::memcpy(nextSeed.data(), seed, seedSize);
    randomx_init_cache(impl_->cache, seed, seedSize);
    if (impl_->fullMemory)
        randomx_init_dataset(impl_->dataset, impl_->cache, 0, randomx_dataset_item_count());

    impl_->seed = nextSeed;
    impl_->seedSize = seedSize;
    impl_->initialized = true;
    return true;
}

const char* RandomXState::modeName() const
{
    return impl_->fullMemory ? "full-memory" : "light-memory";
}

size_t RandomXState::datasetBytes() const
{
    return impl_->datasetBytes;
}

struct RandomXContext::Impl {
    explicit Impl(RandomXState& owner) : state(owner) {}

    RandomXState& state;
    randomx_vm* vm = nullptr;
    std::array<uint8_t, 32> boundSeed{};
    size_t boundSeedSize = 0;
    bool bound = false;
};

RandomXContext::RandomXContext(RandomXState& state)
    : impl_(std::make_unique<Impl>(state))
{
}

RandomXContext::~RandomXContext()
{
    if (impl_->vm)
        randomx_destroy_vm(impl_->vm);
}

bool RandomXContext::hash(const uint8_t* input, size_t inputSize, const uint8_t* seed, size_t seedSize,
                          uint8_t output[32], std::string& error)
{
    if (!input || inputSize == 0 || !output) {
        error = "RandomX hash input/output is invalid";
        return false;
    }
    if (!impl_->state.prepare(seed, seedSize, error))
        return false;

    RandomXState::Impl& state = *impl_->state.impl_;
    std::shared_lock<std::shared_mutex> lock(state.mutex);
    if (!state.initialized) {
        error = "RandomX state is not initialized";
        return false;
    }
    if (state.seedSize != seedSize || std::memcmp(state.seed.data(), seed, seedSize) != 0) {
        lock.unlock();
        return hash(input, inputSize, seed, seedSize, output, error);
    }

    if (!impl_->vm) {
        impl_->vm = randomx_create_vm(state.flags,
                                      state.fullMemory ? nullptr : state.cache,
                                      state.fullMemory ? state.dataset : nullptr);
        if (!impl_->vm) {
            error = "RandomX virtual machine creation failed";
            return false;
        }
    }

    if (!impl_->bound || impl_->boundSeedSize != state.seedSize ||
        std::memcmp(impl_->boundSeed.data(), state.seed.data(), state.seedSize) != 0) {
        if (state.fullMemory)
            randomx_vm_set_dataset(impl_->vm, state.dataset);
        else
            randomx_vm_set_cache(impl_->vm, state.cache);
        impl_->boundSeed = state.seed;
        impl_->boundSeedSize = state.seedSize;
        impl_->bound = true;
    }

    randomx_calculate_hash(impl_->vm, input, inputSize, output);
    return true;
}

bool RandomXContext::hashPair(const uint8_t* inputA, size_t inputASize, const uint8_t* inputB, size_t inputBSize,
                              const uint8_t* seed, size_t seedSize, uint8_t outputA[32], uint8_t outputB[32],
                              std::string& error)
{
    if (!inputA || !inputB || inputASize == 0 || inputBSize == 0 || !outputA || !outputB) {
        error = "RandomX hashPair input/output is invalid";
        return false;
    }
    if (!impl_->state.prepare(seed, seedSize, error))
        return false;

    RandomXState::Impl& state = *impl_->state.impl_;
    std::shared_lock<std::shared_mutex> lock(state.mutex);
    if (!state.initialized) {
        error = "RandomX state is not initialized";
        return false;
    }
    if (state.seedSize != seedSize || std::memcmp(state.seed.data(), seed, seedSize) != 0) {
        lock.unlock();
        return hashPair(inputA, inputASize, inputB, inputBSize, seed, seedSize, outputA, outputB, error);
    }
    if (!impl_->vm) {
        impl_->vm = randomx_create_vm(state.flags,
                                      state.fullMemory ? nullptr : state.cache,
                                      state.fullMemory ? state.dataset : nullptr);
        if (!impl_->vm) {
            error = "RandomX virtual machine creation failed";
            return false;
        }
    }
    if (!impl_->bound || impl_->boundSeedSize != state.seedSize ||
        std::memcmp(impl_->boundSeed.data(), state.seed.data(), state.seedSize) != 0) {
        if (state.fullMemory)
            randomx_vm_set_dataset(impl_->vm, state.dataset);
        else
            randomx_vm_set_cache(impl_->vm, state.cache);
        impl_->boundSeed = state.seed;
        impl_->boundSeedSize = state.seedSize;
        impl_->bound = true;
    }

    randomx_calculate_hash_first(impl_->vm, inputA, inputASize);
    randomx_calculate_hash_next(impl_->vm, inputB, inputBSize, outputA);
    randomx_calculate_hash_last(impl_->vm, outputB);
    return true;
}

void randomXHash(RandomXContext& context, std::vector<uint8_t>& blob, size_t nonceOffset,
                 const std::array<uint8_t, 32>& seed, uint8_t output[32], std::string& error)
{
    if (nonceOffset > blob.size() || blob.size() - nonceOffset < 4) {
        error = "RandomX job blob is too short for a 4-byte nonce at the advertised offset";
        return;
    }
    if (!context.hash(blob.data(), blob.size(), seed.data(), seed.size(), output, error))
        return;
}

bool scanHashRandomX(RandomXContext& context, const std::vector<uint8_t>& blob, size_t nonceOffset,
                     const std::array<uint8_t, 32>& seed, const uint8_t target[8], uint32_t maxNonce,
                     uint32_t& nonceInOut, std::atomic<bool>& restart, uint64_t& hashesDone,
                     uint8_t resultHash[32], std::string& error)
{
    hashesDone = 0;
    if (!target || !resultHash || nonceOffset > blob.size() || blob.size() - nonceOffset < 4) {
        error = "RandomX job blob/target is invalid";
        return false;
    }
    if (nonceInOut > maxNonce)
        return false;

    std::vector<uint8_t> inputA = blob;
    std::vector<uint8_t> inputB = blob;
    const uint32_t firstNonce = nonceInOut;
    uint8_t hashA[32];
    uint8_t hashB[32];
    const uint64_t targetValue = util::le64dec(target);

    for (uint64_t n = firstNonce; n <= maxNonce;) {
        util::le32enc(inputA.data() + nonceOffset, static_cast<uint32_t>(n));
        if (randomXPipelineEnabled() && n < maxNonce) {
            util::le32enc(inputB.data() + nonceOffset, static_cast<uint32_t>(n + 1));
            if (!context.hashPair(inputA.data(), inputA.size(), inputB.data(), inputB.size(),
                                  seed.data(), seed.size(), hashA, hashB, error))
                return false;
            hashesDone += 2;
            if (util::le64dec(hashA) <= targetValue) {
                nonceInOut = static_cast<uint32_t>(n);
                std::memcpy(resultHash, hashA, sizeof(hashA));
                return true;
            }
            if (util::le64dec(hashB) <= targetValue) {
                nonceInOut = static_cast<uint32_t>(n + 1);
                std::memcpy(resultHash, hashB, sizeof(hashB));
                return true;
            }
            n += 2;
        } else {
            if (!context.hash(inputA.data(), inputA.size(), seed.data(), seed.size(), hashA, error))
                return false;
            ++hashesDone;
            if (util::le64dec(hashA) <= targetValue) {
                nonceInOut = static_cast<uint32_t>(n);
                std::memcpy(resultHash, hashA, sizeof(hashA));
                return true;
            }
            ++n;
        }
        if (restart.load(std::memory_order_relaxed))
            break;
    }

    nonceInOut = static_cast<uint32_t>(uint64_t(firstNonce) + (hashesDone ? hashesDone - 1 : 0));
    return false;
}

const char* randomXActiveBackendName()
{
    thread_local std::string activeBackend = randomXDescribeFlags(randomx_get_flags());
    activeBackend = randomXDescribeFlags(randomx_get_flags());
    return activeBackend.c_str();
}

const char* randomXSimdFeaturesString()
{
    thread_local std::string features;
    const randomx_flags flags = randomx_get_flags();
    std::ostringstream oss;
    oss << randomXArgonBackendName(flags);
    if (flags & RANDOMX_FLAG_HARD_AES)
        oss << " Hard-AES";
    if (flags & RANDOMX_FLAG_JIT)
        oss << " JIT";
    features = oss.str();
    return features.c_str();
}

std::vector<cppminer::BackendBenchResult> randomXBenchmarkArgonBackends(double secondsPerBackend)
{
    static constexpr char kKey[] = "RandomX benchmark seed";
    const randomx_flags baseFlags = static_cast<randomx_flags>(randomx_get_flags() & ~RANDOMX_FLAG_ARGON2);
    const randomx_flags cacheBaseFlags = static_cast<randomx_flags>(
        baseFlags & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_ARGON2));

    struct ArgonBackend {
        const char* name;
        randomx_flags argonFlag;
        bool available;
    };

    const ArgonBackend backends[] = {
        {"scalar", RANDOMX_FLAG_DEFAULT, true},
        {"SSSE3", RANDOMX_FLAG_ARGON2_SSSE3, randomx_argon2_impl_ssse3() != nullptr},
        {"AVX2", RANDOMX_FLAG_ARGON2_AVX2, randomx_argon2_impl_avx2() != nullptr},
    };

    std::vector<BackendBenchResult> results;
    for (const ArgonBackend& backend : backends) {
        if (!backend.available)
            continue;

        const randomx_flags cacheFlags = static_cast<randomx_flags>(cacheBaseFlags | backend.argonFlag);
        randomx_cache* cache = randomx_alloc_cache(cacheFlags);
        if (!cache)
            continue;

        uint64_t runs = 0;
        const auto t0 = std::chrono::steady_clock::now();
        double elapsed = 0.0;
        while (elapsed < secondsPerBackend) {
            randomx_init_cache(cache, kKey, sizeof(kKey) - 1);
            ++runs;
            elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        }

        randomx_release_cache(cache);
        results.push_back({backend.name, elapsed > 0.0 ? double(runs) / elapsed : 0.0});
    }

    return results;
}

bool randomXSelfTest()
{
    // Official RandomX API-example digest for the strings below; keeping it
    // in the binary makes this a real reference-vector test, not a same-path
    // round trip.
    static constexpr uint8_t kExpected[32] = {
        0x8a, 0x48, 0xe5, 0xf9, 0xdb, 0x45, 0xab, 0x79,
        0xd9, 0x08, 0x05, 0x74, 0xc4, 0xd8, 0x19, 0x54,
        0xfe, 0x6a, 0xc6, 0x38, 0x42, 0x21, 0x4a, 0xff,
        0x73, 0xc2, 0x44, 0xb2, 0x63, 0x30, 0xb7, 0xc9,
    };
    static constexpr char kKey[] = "RandomX example key";
    static constexpr char kInput[] = "RandomX example input";

    try {
        RandomXState state(false, false);
        RandomXContext context(state);
        uint8_t hash[32];
        std::string error;
        if (!context.hash(reinterpret_cast<const uint8_t*>(kInput), sizeof(kInput),
                          reinterpret_cast<const uint8_t*>(kKey), sizeof(kKey), hash, error))
            return false;
        if (std::memcmp(hash, kExpected, sizeof(hash)) != 0)
            return false;

        uint8_t pairA[32];
        uint8_t pairB[32];
        if (!context.hashPair(reinterpret_cast<const uint8_t*>(kInput), sizeof(kInput),
                               reinterpret_cast<const uint8_t*>(kInput), sizeof(kInput),
                               reinterpret_cast<const uint8_t*>(kKey), sizeof(kKey), pairA, pairB, error))
            return false;
        if (std::memcmp(pairA, kExpected, sizeof(pairA)) != 0 ||
            std::memcmp(pairB, kExpected, sizeof(pairB)) != 0)
            return false;

        std::vector<uint8_t> blob(43, 0);
        std::array<uint8_t, 32> seed{};
        uint8_t target[8];
        std::memset(target, 0xff, sizeof(target));
        uint8_t result[32];
        uint32_t nonce = 7;
        std::atomic<bool> restart{false};
        uint64_t done = 0;
        if (!scanHashRandomX(context, blob, 39, seed, target, nonce, nonce, restart, done, result, error))
            return false;
        return nonce == 7 && done == 1;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace cppminer::algo
