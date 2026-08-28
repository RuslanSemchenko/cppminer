#include "net/RandomXJobParser.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "JsonCompat.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Bound the parser's allocation surface even when a fuzzer supplies a
    // multi-megabyte mutation.
    if (!data || size > (1u << 20))
        return 0;

    const std::string input(reinterpret_cast<const char*>(data), size);
    const auto parsed = nlohmann::json::parse(input, nullptr, false);
    if (parsed.is_discarded())
        return 0;

    cppminer::RandomXWork work;
    std::string error;
    (void)cppminer::net::parseRandomXJob(parsed, work, error);
    return 0;
}
