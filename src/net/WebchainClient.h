#pragma once

// Webchain (MintMe) JSON-RPC protocol client, used for the lyra2web
// algorithm: a "login" call (which embeds the first job), asynchronous
// "job" push notifications, "submit" for found shares and a "keepalived"
// ping/pong kept alive during idle periods. Unlike classic Stratum this is
// a plain JSON-RPC-over-TCP protocol (XMRig-compatible), not mining.*
// methods. Runs its own background connection thread; safe to call from
// multiple miner threads.
//
// See the repository root's cpu-miner.c/util.c (stratum_webchain_login,
// stratum_webchain_parse_job, webchain_next_request_id,
// webchain_take_submit_id, submit_upstream_work's webchain branch) for the
// reference this was ported from.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../JsonCompat.h"

#include "../Work.h"
#include "RawSocket.h"

namespace cppminer::net {

struct WebchainConfig {
    std::string url;
    std::string user;
    std::string pass;
    int retries = -1;
    int retryPauseSeconds = 30;
    bool protocolDump = false;
    TlsOptions tls;
};

class WebchainClient {
public:
    WebchainClient(WebchainConfig config, std::vector<std::atomic<bool>*> restartFlags);
    ~WebchainClient();

    WebchainClient(const WebchainClient&) = delete;
    WebchainClient& operator=(const WebchainClient&) = delete;

    void start();
    void stop();

    bool isConnected() const { return running_.load(); }
    // True once the connection thread has permanently given up (exhausted
    // --retries) and exited; the caller should treat the miner as stopped.
    bool hasGivenUp() const { return gaveUp_.load(); }
    bool hasWork() const;

    // See StratumClient::snapshotWork - same contract, for the Webchain job
    // representation (WebchainWork).
    uint64_t snapshotWork(WebchainWork& out) const;

    // Submits a found 64-bit nonce plus the winning 32-byte Lyra2 hash.
    void submitShare(const WebchainWork& work, uint64_t nonce, const uint8_t hash[32]);

    uint64_t acceptedShares() const { return accepted_.load(); }
    uint64_t rejectedShares() const { return rejected_.load(); }

private:
    void threadMain();
    bool connectAndLogin(std::string& error);
    bool waitForLoginResponse(int timeoutMs, std::string& error);
    int pumpSocket(int waitMs); // -1 on hard error, else bytes read (0 = timeout)
    void handleLine(const std::string& line);
    void handleJobPush(const nlohmann::json& params);
    bool parseJobLocked(const nlohmann::json& job, std::string& error); // caller holds mutex_
    void handleKeepalivedPush(const nlohmann::json& msg);
    void handleResponse(const nlohmann::json& msg);
    void onShareResult(bool accepted, const std::string& reason);
    bool sendJson(const nlohmann::json& msg);
    void sleepInterruptible(int ms);
    int nextRequestId(bool trackAsSubmit);
    bool takeSubmitId(int id);

    WebchainConfig config_;
    std::vector<std::atomic<bool>*> restartFlags_;

    RawSocket socket_;
    std::string recvBuffer_;
    std::mutex sendMutex_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::atomic<bool> gaveUp_{false};
    std::thread thread_;

    std::atomic<uint64_t> accepted_{0};
    std::atomic<uint64_t> rejected_{0};

    mutable std::mutex mutex_; // guards everything below
    std::string rpcId_;
    int seq_ = 0;
    std::vector<int> pendingSubmitIds_;

    bool haveJob_ = false;
    WebchainWork currentWork_;
    uint64_t jobVersion_ = 0;

    // login handshake bookkeeping (only touched by the connection thread)
    bool loginPending_ = false;
    bool loginOk_ = false;
    std::string loginError_;
};

} // namespace cppminer::net
