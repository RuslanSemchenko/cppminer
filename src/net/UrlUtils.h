#pragma once

#include <string>

namespace cppminer::net {

// Rewrites "stratum+tcp://", "stratum+ssl://" and "stratum+tcps://" URLs
// into the http(s):// form libcurl's CONNECT_ONLY mode expects (mirroring
// stratum_connect()'s `sprintf(sctx->curl_url, "http%s", url + 11)` trick in
// the repository root's util.c, generalized to also cover TLS schemes).
// Plain http(s):// URLs are returned unchanged. Returns an empty string if
// the scheme is not recognized.
std::string rewriteStratumUrl(const std::string& url);

} // namespace cppminer::net
