#pragma once

// Raw TCP (optionally TLS) socket built on top of libcurl's "connect only"
// mode - the same trick the reference cpuminer uses for its Stratum socket
// (see stratum_connect() in the repository root's util.c): let curl do the
// URL parsing, proxying, DNS and (for stratum+ssl/https) the TLS handshake,
// then take over the raw file descriptor for line-based JSON-RPC traffic.
//
// <curl/curl.h> is intentionally not included here so this header stays
// cheap to include; the CURL handle and OS socket handle are stored as
// opaque values and only cast back in RawSocket.cpp.

#include <cstddef>
#include <cstdint>
#include <string>

namespace cppminer::net {

struct TlsOptions {
    bool verifyPeer = true;
    // libcurl CURLOPT_PINNEDPUBLICKEY format, e.g. sha256//base64== or a
    // path to a PEM/DER public-key file. Empty means no pin is required.
    std::string pinnedPublicKey;
};

class RawSocket {
public:
    RawSocket();
    ~RawSocket();
    RawSocket(const RawSocket&) = delete;
    RawSocket& operator=(const RawSocket&) = delete;

    // `url` must be an http(s):// URL (see UrlUtils.h for rewriting
    // stratum+tcp/stratum+ssl into http/https). Blocks until connected or
    // failed; `connectTimeoutSeconds` bounds the connect attempt.
    bool connect(const std::string& url, int connectTimeoutSeconds, std::string& error,
                  const TlsOptions& tls = {});
    void disconnect();
    bool isConnected() const;

    // Waits up to `timeoutMs` for the socket to become readable. Returns
    // true if data is (probably) available, false on timeout or error.
    bool waitReadable(int timeoutMs) const;

    // Non-blocking-ish read: returns the number of bytes read into `buf`
    // (0 if none were available within a short retry loop), or -1 on a hard
    // error/disconnect.
    int recvSome(char* buf, size_t bufSize);

    // Blocks until all of `data` has been written, or a hard error occurs.
    bool sendAll(const char* data, size_t len);

private:
    void* curl_;          // CURL*
    std::uintptr_t sock_; // curl_socket_t
};

} // namespace cppminer::net
