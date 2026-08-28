#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../JsonCompat.h"

#include "../Work.h"
#include "RawSocket.h"

namespace cppminer::net {

struct RandomXConfig {
    std::string url;
    std::string user;
    std::string pass;
    int retries = -1;
    int retryPauseSeconds = 30;
    bool protocolDump = false;
    TlsOptions tls;
};

// Monero/Cryptonote-style JSON-RPC client. It intentionally lives beside the
// classic Stratum client because RandomX jobs are object-shaped blobs with an
// embedded nonce and seed_hash, not 80-byte Bitcoin headers.
class RandomXClient {
public:
    RandomXClient(RandomXConfig config, std::vector<std::atomic<bool>*> restartFlags);
    ~RandomXClient();

    RandomXClient(const RandomXClient&) = delete;
    RandomXClient& operator=(const RandomXClient&) = delete;

    void start();
    void stop();
    bool isConnected() const { return running_.load(); }
    bool hasGivenUp() const { return gaveUp_.load(); }
    bool hasWork() const;

    uint64_t snapshotWork(RandomXWork& out) const;
    void submitShare(const RandomXWork& work, uint32_t nonce, const uint8_t resultHash[32]);

    uint64_t acceptedShares() const { return accepted_.load(); }
    uint64_t rejectedShares() const { return rejected_.load(); }

private:
    void threadMain();
    bool connectAndHandshake(std::string& error);
    bool pumpSocket(int waitMs);
    void handleLine(const std::string& line);
    void handleJob(const nlohmann::json& params);
    void handleResponse(const nlohmann::json& msg);
    void onShareResult(bool accepted, const std::string& reason);
    bool sendJson(const nlohmann::json& msg);
    bool waitForResponseId(int id, int timeoutMs, std::string& error);
    void sleepInterruptible(int ms);

    RandomXConfig config_;
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

    mutable std::mutex mutex_;
    RandomXWork currentWork_;
    bool haveJob_ = false;
    uint64_t jobVersion_ = 0;

    int lastHandledResponseId_ = 0;
    bool lastResponseOk_ = false;
    std::string lastResponseError_;
};

} // namespace cppminer::net
