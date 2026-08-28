#include "UrlUtils.h"

#include <algorithm>
#include <cctype>

namespace cppminer::net {

std::string rewriteStratumUrl(const std::string& url)
{
    auto schemeEnd = url.find("://");
    // The original MintMe/Webchain miner accepts plain host:port values,
    // e.g. pool.webchain.network:3333. Treat those as unencrypted Stratum
    // TCP, matching the pool's historical endpoint and the CLI example.
    if (schemeEnd == std::string::npos)
        return "http://" + url;

    std::string scheme = url.substr(0, schemeEnd);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string rest = url.substr(schemeEnd); // includes "://..."

    if (scheme == "http" || scheme == "https")
        return url;
    if (scheme == "stratum+tcp")
        return "http" + rest;
    if (scheme == "stratum+ssl" || scheme == "stratum+tcps")
        return "https" + rest;
    return {};
}

} // namespace cppminer::net
