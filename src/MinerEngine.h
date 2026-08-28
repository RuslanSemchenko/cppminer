#pragma once

// Thread orchestration: owns the network client (Stratum or Webchain,
// depending on the selected algorithm) and one hashing thread per
// configured CPU thread, each with its own partition of the nonce space
// (mirroring miner_thread()'s `0xffffffffU / opt_n_threads * thr_id`
// partitioning in the repository root's cpu-miner.c) and its own restart
// flag the network client can set to abort a stale scan immediately.

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include "Config.h"
#include "algo/RandomX.h"
#include "net/StratumClient.h"
#include "net/RandomXClient.h"
#include "net/WebchainClient.h"

namespace cppminer {

class MinerEngine {
public:
    explicit MinerEngine(Config config);

    // Starts the network client and all miner threads, then blocks the
    // calling thread (periodically logging aggregate hashrate/share stats)
    // until requestStop() is called; joins everything before returning.
    void run();

    // Safe to call from a signal handler: only sets an atomic flag.
    void requestStop() { stopRequested_.store(true); }

private:
    void stop();
    void classicThreadLoop(int threadId);
    void webchainThreadLoop(int threadId);
    void randomXThreadLoop(int threadId);

    Config config_;
    std::atomic<bool> stopRequested_{false};

    std::vector<std::unique_ptr<std::atomic<bool>>> restartFlags_;
    std::vector<std::atomic<bool>*> restartFlagPtrs_;
    std::vector<double> threadHashrates_;

    std::unique_ptr<net::StratumClient> stratum_;
    std::unique_ptr<net::WebchainClient> webchain_;
    std::unique_ptr<net::RandomXClient> randomx_;
    std::unique_ptr<algo::RandomXState> randomxState_;
    std::vector<std::thread> workers_;
};

} // namespace cppminer
