#include "RawSocket.h"

#include <curl/curl.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include <chrono>
#include <thread>

namespace cppminer::net {

RawSocket::RawSocket() : curl_(nullptr), sock_(0) {}

RawSocket::~RawSocket()
{
    disconnect();
}

bool RawSocket::connect(const std::string& url, int connectTimeoutSeconds, std::string& error,
                        const TlsOptions& tls)
{
    disconnect();

    CURL* curl = curl_easy_init();
    if (!curl) {
        error = "curl_easy_init failed";
        return false;
    }

    static thread_local char errBuf[CURL_ERROR_SIZE];
    errBuf[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, static_cast<long>(connectTimeoutSeconds));
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errBuf);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
    // Certificate and hostname verification are deliberately enabled by
    // default. Disabling them turns TLS into encryption without server
    // authentication and leaves stratum credentials/shares vulnerable to MITM.
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, tls.verifyPeer ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, tls.verifyPeer ? 2L : 0L);
    if (!tls.pinnedPublicKey.empty())
        curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, tls.pinnedPublicKey.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        error = errBuf[0] ? errBuf : curl_easy_strerror(rc);
        curl_easy_cleanup(curl);
        return false;
    }

    curl_socket_t sock = CURL_SOCKET_BAD;
    curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sock);
    if (sock == CURL_SOCKET_BAD) {
        error = "could not retrieve the underlying socket from curl";
        curl_easy_cleanup(curl);
        return false;
    }

    curl_ = curl;
    sock_ = static_cast<std::uintptr_t>(sock);
    return true;
}

void RawSocket::disconnect()
{
    if (curl_) {
        curl_easy_cleanup(static_cast<CURL*>(curl_));
        curl_ = nullptr;
    }
    sock_ = 0;
}

bool RawSocket::isConnected() const
{
    return curl_ != nullptr;
}

bool RawSocket::waitReadable(int timeoutMs) const
{
    if (!curl_)
        return false;

    fd_set readSet;
    FD_ZERO(&readSet);
#ifdef _WIN32
    FD_SET(static_cast<SOCKET>(sock_), &readSet);
#else
    FD_SET(static_cast<int>(sock_), &readSet);
#endif
    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

#ifdef _WIN32
    int rc = select(0, &readSet, nullptr, nullptr, &tv);
#else
    int rc = select(static_cast<int>(sock_) + 1, &readSet, nullptr, nullptr, &tv);
#endif
    return rc > 0;
}

int RawSocket::recvSome(char* buf, size_t bufSize)
{
    if (!curl_)
        return -1;

    size_t n = 0;
    CURLcode rc = curl_easy_recv(static_cast<CURL*>(curl_), buf, bufSize, &n);
    if (rc == CURLE_OK)
        return n > 0 ? static_cast<int>(n) : -1; // 0 bytes + CURLE_OK means the peer closed the connection
    if (rc == CURLE_AGAIN)
        return 0;
    return -1;
}

bool RawSocket::sendAll(const char* data, size_t len)
{
    if (!curl_)
        return false;

    size_t sent = 0;
    int stallRetries = 0;
    while (sent < len) {
        size_t n = 0;
        CURLcode rc = curl_easy_send(static_cast<CURL*>(curl_), data + sent, len - sent, &n);
        if (rc == CURLE_OK) {
            sent += n;
            stallRetries = 0;
            continue;
        }
        if (rc == CURLE_AGAIN) {
            if (++stallRetries > 2000) // roughly 10s of retrying in 5ms steps
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        return false;
    }
    return true;
}

} // namespace cppminer::net
