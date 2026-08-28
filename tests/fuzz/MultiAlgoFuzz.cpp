#include "algo/Lyra2Web.h"
#include "algo/Scrypt.h"
#include "algo/Sha256.h"
#include "net/RandomXJobParser.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "JsonCompat.h"

namespace {

void makeHeader(const uint8_t* data, size_t size, uint8_t header[80])
{
    for (size_t i = 0; i < 80; ++i)
        header[i] = size ? data[i % size] : 0;
}

void fuzzSha256d(const uint8_t* data, size_t size)
{
    uint8_t header[80];
    makeHeader(data, size, header);
    uint8_t digest[32];
    cppminer::algo::Sha256::hash256d(data, size, digest);

    if (size > 1 && (data[1] & 1)) {
        const uint32_t target[8] = {};
        std::atomic<bool> restart{false};
        uint32_t nonce = 0xfffffffeu;
        uint64_t done = 0;
        (void)cppminer::algo::scanHashSha256d(header, target, 0xffffffffu, nonce, restart, done);
    }
}

void fuzzScrypt(const uint8_t* data, size_t size)
{
    static cppminer::algo::ScryptEngine engine(16);
    uint8_t header[80];
    makeHeader(data, size, header);
    uint8_t digest[32];
    engine.hash(header, digest);

    if (size > 1 && (data[1] & 2)) {
        const uint32_t target[8] = {};
        std::atomic<bool> restart{false};
        uint32_t nonce = 0xfffffffeu;
        uint64_t done = 0;
        (void)cppminer::algo::scanHashScrypt(engine, header, target, 0xffffffffu, nonce, restart, done);
    }
}

void fuzzLyra2(const uint8_t* data, size_t size)
{
    static cppminer::algo::Lyra2Context context;
    const size_t inputSize = size > 256 ? 256 : size;
    std::vector<uint8_t> input(data, data + inputSize);
    uint8_t digest[32];
    cppminer::algo::lyra2WebHash(context, input.data(), input.size(), 1, digest);

    if (size > 1 && (data[1] & 4)) {
        std::vector<uint8_t> blob(43, 0);
        for (size_t i = 0; i < blob.size() && i < size; ++i)
            blob[i] = data[i];
        const uint8_t target[8] = {};
        std::atomic<bool> restart{false};
        uint64_t nonce = 0xfffffffffffffffeULL;
        uint64_t done = 0;
        (void)cppminer::algo::scanHashLyra2Web(context, blob, 1, target,
                                               0xffffffffffffffffULL, nonce, restart, done, digest);
    }
}

void fuzzRandomXJobParser(const uint8_t* data, size_t size)
{
    const auto parsed = nlohmann::json::parse(
        std::string(reinterpret_cast<const char*>(data), size), nullptr, false);
    if (parsed.is_discarded())
        return;
    cppminer::RandomXWork work;
    std::string error;
    (void)cppminer::net::parseRandomXJob(parsed, work, error);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size > (1u << 16))
        return 0;

    switch (size ? data[0] & 3 : 0) {
    case 0:
        fuzzSha256d(data, size);
        break;
    case 1:
        fuzzScrypt(data, size);
        break;
    case 2:
        fuzzLyra2(data, size);
        break;
    default:
        fuzzRandomXJobParser(data, size);
        break;
    }
    return 0;
}
