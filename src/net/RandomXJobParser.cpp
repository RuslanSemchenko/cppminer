#include "RandomXJobParser.h"

#include "../ByteUtils.h"

#include <algorithm>

namespace cppminer::net {
namespace {

bool parseTarget(const std::string& hex, std::array<uint8_t, 8>& out)
{
    auto raw = util::hexToBytes(hex);
    if (raw.size() == 8) {
        std::copy(raw.begin(), raw.end(), out.begin());
        return util::le64dec(out.data()) != 0;
    }
    if (raw.size() == 4) {
        uint32_t compact = util::le32dec(raw.data());
        if (compact == 0)
            return false;
        const uint64_t target = UINT64_MAX / (UINT64_C(0xffffffff) / compact);
        util::le64enc(out.data(), target);
        return target != 0;
    }
    return false;
}

} // namespace

bool parseRandomXJob(const nlohmann::json& p, RandomXWork& out, std::string& error)
{
    if (!p.is_object()) {
        error = "RandomX job params must be an object";
        return false;
    }
    if (!p.contains("job_id") || !p["job_id"].is_string() ||
        !p.contains("blob") || !p["blob"].is_string() ||
        !p.contains("target") || !p["target"].is_string() ||
        !p.contains("seed_hash") || !p["seed_hash"].is_string()) {
        error = "RandomX job requires job_id, blob, target and seed_hash";
        return false;
    }

    const std::string blobHex = p["blob"].get<std::string>();
    if (blobHex.size() % 2 != 0 || blobHex.size() < 86 || blobHex.size() >= 4096) {
        error = "RandomX job blob has an invalid length";
        return false;
    }
    auto blob = util::hexToBytes(blobHex);
    if (blob.empty()) {
        error = "RandomX job blob is not valid hexadecimal";
        return false;
    }

    const std::string seedHex = p["seed_hash"].get<std::string>();
    if (seedHex.size() != 64) {
        error = "RandomX seed_hash must be exactly 32 bytes";
        return false;
    }

    RandomXWork work;
    work.blob = std::move(blob);
    if (!util::hex2bin(work.seedHash.data(), seedHex, work.seedHash.size())) {
        error = "RandomX seed_hash is not valid hexadecimal";
        return false;
    }
    if (!parseTarget(p["target"].get<std::string>(), work.target)) {
        error = "RandomX target must be a non-zero 4-byte or 8-byte value";
        return false;
    }
    work.nonceOffset = 39;
    if (p.contains("nonce_offset") && p["nonce_offset"].is_number_unsigned())
        work.nonceOffset = p["nonce_offset"].get<uint32_t>();
    if (work.nonceOffset > work.blob.size() || work.blob.size() - work.nonceOffset < 4) {
        error = "RandomX nonce offset is outside the job blob";
        return false;
    }
    work.jobId = p["job_id"].get<std::string>();
    out = std::move(work);
    return true;
}

} // namespace cppminer::net
