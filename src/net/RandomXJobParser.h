#pragma once

#include <string>

#include "../JsonCompat.h"

#include "../Work.h"

namespace cppminer::net {

// Parses a Monero/Cryptonote-style RandomX job object. This function is pure
// with respect to network state and is intentionally fuzz-testable.
bool parseRandomXJob(const nlohmann::json& params, RandomXWork& out, std::string& error);

} // namespace cppminer::net
