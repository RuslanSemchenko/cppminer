#include "Work.h"

#include <algorithm>
#include <cctype>

namespace cppminer {

const char* algorithmName(Algorithm algo)
{
    switch (algo) {
        case Algorithm::Scrypt:   return "scrypt";
        case Algorithm::Sha256d:  return "sha256d";
        case Algorithm::Lyra2Web: return "lyra2web";
        case Algorithm::RandomX:   return "randomx";
    }
    return nullptr;
}

bool algorithmFromName(const std::string& name, Algorithm& outAlgo, uint32_t& scryptN)
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    auto colon = lower.find(':');
    std::string base = colon == std::string::npos ? lower : lower.substr(0, colon);

    if (base == "scrypt") {
        outAlgo = Algorithm::Scrypt;
        if (colon != std::string::npos) {
            try {
                scryptN = static_cast<uint32_t>(std::stoul(lower.substr(colon + 1)));
            } catch (...) {
                return false;
            }
        }
        return true;
    }
    if (base == "sha256d") {
        outAlgo = Algorithm::Sha256d;
        return true;
    }
    if (base == "lyra2web" || base == "lyra2v2web" ||
        base == "lyra2-webchain" || base == "lyra2v2-webchain") {
        outAlgo = Algorithm::Lyra2Web;
        return true;
    }
    if (base == "randomx" || base == "rx/0" || base == "rx") {
        outAlgo = Algorithm::RandomX;
        return true;
    }
    return false;
}

} // namespace cppminer
