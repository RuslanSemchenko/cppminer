#pragma once

// Classic (Bitcoin/Litecoin-style) Stratum v1 protocol client, used for the
// scrypt and sha256d algorithms: mining.subscribe -> mining.authorize ->
// mining.notify (builds a block header + merkle root) / mining.set_difficulty
// (updates the target) -> mining.submit for found shares. Runs its own
// background connection thread; safe to call from multiple miner threads.
//
// See the repository root's cpu-miner.c/util.c (stratum_subscribe,
// stratum_authorize, stratum_notify, stratum_gen_work, submit_upstream_work,
// diff_to_target, fulltest) for the reference this was ported from.

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

struct StratumConfig {
    std::string url;
    std::string user;
    std::string pass;
    Algorithm algo = Algorithm::Scrypt; // Scrypt or Sha256d
    int retries = -1;
    int retryPauseSeconds = 30;
    bool protocolDump = false;
    TlsOptions tls;
};

class StratumClient {
public:
    StratumClient(StratumConfig config, std::vector<std::atomic<bool>*> restartFlags);
    ~StratumClient();

    StratumClient(const StratumClient&) = delete;
    StratumClient& operator=(const StratumClient&) = delete;

    // Spawns the background connection thread. Call once.
    void start();
    // Signals the background thread to stop and joins it. Safe to call
    // even if start() was never called or the thread already exited.
    void stop();

    // True once the handshake has completed and the socket is connected.
    bool isConnected() const { return running_.load(); }
    // True once the connection thread has permanently given up (exhausted
    // --retries) and exited; the caller should treat the miner as stopped.
    bool hasGivenUp() const { return gaveUp_.load(); }
    // True once at least one mining.notify has been processed.
    bool hasWork() const;

    // Copies the current job into `out` (nonce bytes left as-is - the
    // caller partitions/owns the nonce range) and returns its version
    // counter, or 0 if no job has arrived yet. Compare against the value
    // returned by a previous call to detect a new job.
    uint64_t snapshotWork(ClassicWork& out) const;

    // Advances extranonce2 and rebuilds work only if `expectedVersion` is
    // still current. This lets one worker refresh the job when its nonce
    // partition is exhausted without several workers rolling it repeatedly.
    bool rollExtranonce2(uint64_t expectedVersion);

    // Sends mining.submit for `nonce` found while mining `work`.
    void submitShare(const ClassicWork& work, uint32_t nonce);

    uint64_t acceptedShares() const { return accepted_.load(); }
    uint64_t rejectedShares() const { return rejected_.load(); }

private:
    void threadMain();
    bool connectAndHandshake(std::string& error);
    bool pumpSocket(int waitMs);
    void handleLine(const std::string& line);
    void handleNotify(const nlohmann::json& params);
    void handleSetDifficulty(const nlohmann::json& params);
    void handleResponse(const nlohmann::json& msg);
    void onShareResult(bool accepted, const std::string& reason);
    bool sendJson(const nlohmann::json& msg);
    bool waitForResponseId(int id, int timeoutMs, std::string& error);
    void sleepInterruptible(int ms);
    void buildWorkLocked(); // caller must hold mutex_

    StratumConfig config_;
    std::vector<std::atomic<bool>*> restartFlags_;

    RawSocket socket_;
    std::string recvBuffer_;
    std::mutex sendMutex_; // serializes writes to socket_ across threads

    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::atomic<bool> gaveUp_{false};
    std::thread thread_;

    std::atomic<uint64_t> accepted_{0};
    std::atomic<uint64_t> rejected_{0};

    mutable std::mutex mutex_; // guards everything below

    std::vector<uint8_t> extranonce1_;
    size_t extranonce2Size_ = 4;
    std::vector<uint8_t> extranonce2_;

    std::string jobId_;
    std::vector<uint8_t> version_, prevhash_, coinb1_, coinb2_, nbits_, ntime_;
    std::vector<std::array<uint8_t, 32>> merkleBranch_;
    double diff_ = 1.0;
    double nextDiff_ = 1.0;

    bool haveJob_ = false;
    ClassicWork currentWork_;
    uint64_t jobVersion_ = 0;

    // handshake response bookkeeping (only touched by the connection
    // thread, but declared here since handleResponse()/handleLine() are
    // members)
    int lastHandledResponseId_ = 0;
    bool lastResponseOk_ = false;
    std::string lastResponseError_;
};

} // namespace cppminer::net
