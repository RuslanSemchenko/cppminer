#include "MinerEngine.h"

#include "ByteUtils.h"
#include "ConsoleInput.h"
#include "Log.h"
#include "algo/Lyra2Web.h"
#include "algo/Scrypt.h"
#include "algo/Sha256.h"

#include <algorithm>
#include <chrono>

namespace cppminer {

MinerEngine::MinerEngine(Config config) : config_(std::move(config))
{
}

uint64_t MinerEngine::acceptedShares() const
{
    if (stratum_)
        return stratum_->acceptedShares();
    if (webchain_)
        return webchain_->acceptedShares();
    if (randomx_)
        return randomx_->acceptedShares();
    return 0;
}

uint64_t MinerEngine::rejectedShares() const
{
    if (stratum_)
        return stratum_->rejectedShares();
    if (webchain_)
        return webchain_->rejectedShares();
    if (randomx_)
        return randomx_->rejectedShares();
    return 0;
}

void MinerEngine::logHashrate(bool perThread) const
{
    double total = 0.0;
    for (double h : threadHashrates_)
        total += h;
    logf(LogLevel::Notice, "speed: %.2f H/s, shares: %llu accepted / %llu rejected", total,
         static_cast<unsigned long long>(acceptedShares()),
         static_cast<unsigned long long>(rejectedShares()));
    if (perThread) {
        for (size_t i = 0; i < threadHashrates_.size(); ++i) {
            logf(LogLevel::Notice, "  thread %zu: %.2f H/s", i, threadHashrates_[i]);
        }
    }
}

void MinerEngine::classicThreadLoop(int threadId)
{
    std::atomic<bool>& restart = *restartFlagPtrs_[static_cast<size_t>(threadId)];
    ClassicWork work;
    uint64_t knownVersion = 0;

    const uint32_t threadsU = static_cast<uint32_t>(config_.threads);
    const uint32_t nonceRangeStart = (0xffffffffu / threadsU) * static_cast<uint32_t>(threadId);
    const uint32_t nonceRangeEnd = (0xffffffffu / threadsU) * (static_cast<uint32_t>(threadId) + 1) - 0x20;
    uint32_t nonce = nonceRangeStart;

    // scrypt's memory-hard core dominates its cost, so a much smaller batch
    // keeps job-change latency reasonable; sha256d is cheap enough to use a
    // large batch without noticeably delaying a job refresh.
    const uint64_t batchSize = (config_.algo == Algorithm::Scrypt)
                                    ? std::max<uint64_t>(16, 131072ull / config_.scryptN)
                                    : 2000000ull;
    std::unique_ptr<algo::ScryptEngine> scryptEngine;
    if (config_.algo == Algorithm::Scrypt)
        scryptEngine = std::make_unique<algo::ScryptEngine>(config_.scryptN);

    while (!stopRequested_.load(std::memory_order_relaxed)) {
        uint64_t v = stratum_->snapshotWork(work);
        if (v == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        if (v != knownVersion) {
            knownVersion = v;
            nonce = nonceRangeStart;
            restart.store(false, std::memory_order_relaxed);
        }
        if (nonce < nonceRangeStart || nonce > nonceRangeEnd) {
            // Once this worker exhausts its partition, roll extranonce2 so
            // the pool job can continue without waiting for a notify. The
            // version check makes this a no-op if another worker already did
            // the rollover or the pool sent a fresh job meanwhile.
            if (stratum_->rollExtranonce2(knownVersion)) {
                restart.store(true, std::memory_order_relaxed);
                nonce = nonceRangeStart;
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            continue;
        }

        uint32_t maxNonce = static_cast<uint32_t>(std::min<uint64_t>(uint64_t(nonce) + batchSize, nonceRangeEnd));

        uint64_t hashesDone = 0;
        auto t0 = std::chrono::steady_clock::now();
        bool found = (config_.algo == Algorithm::Scrypt)
                         ? algo::scanHashScrypt(*scryptEngine, work.header.data(), work.target.data(), maxNonce,
                                                 nonce, restart, hashesDone)
                         : algo::scanHashSha256d(work.header.data(), work.target.data(), maxNonce, nonce, restart,
                                                  hashesDone);
        double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (elapsed > 0.0)
            threadHashrates_[static_cast<size_t>(threadId)] = hashesDone / elapsed;

        if (found)
            stratum_->submitShare(work, nonce);
        nonce++;
    }
}

void MinerEngine::webchainThreadLoop(int threadId)
{
    std::atomic<bool>& restart = *restartFlagPtrs_[static_cast<size_t>(threadId)];
    WebchainWork work;
    uint64_t knownVersion = 0;

    const uint64_t threadsU = static_cast<uint64_t>(config_.threads);
    const uint64_t nonceRangeStart = (0xffffffffull / threadsU) * static_cast<uint64_t>(threadId);
    uint64_t nonce = nonceRangeStart;

    algo::Lyra2Context ctx;
    const uint64_t simdLanes = algo::lyra2WebSimdLanes(ctx);
    const uint64_t batchSize = simdLanes > 1 ? simdLanes * 4 : 1;
    uint8_t resultHash[32];

    while (!stopRequested_.load(std::memory_order_relaxed)) {
        uint64_t v = webchain_->snapshotWork(work);
        if (v == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        if (v != knownVersion) {
            knownVersion = v;
            nonce = nonceRangeStart;
            restart.store(false, std::memory_order_relaxed);
        }

        uint64_t maxNonce = nonce + batchSize;
        uint64_t hashesDone = 0;
        auto t0 = std::chrono::steady_clock::now();
        bool found = algo::scanHashLyra2Web(ctx, work.blob, work.lyra2Tcost, work.target.data(), maxNonce, nonce,
                                             restart, hashesDone, resultHash);
        double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (elapsed > 0.0)
            threadHashrates_[static_cast<size_t>(threadId)] = hashesDone / elapsed;

        if (found)
            webchain_->submitShare(work, nonce, resultHash);
        nonce++;
    }
}

void MinerEngine::randomXThreadLoop(int threadId)
{
    std::atomic<bool>& restart = *restartFlagPtrs_[static_cast<size_t>(threadId)];
    RandomXWork work;
    uint64_t knownVersion = 0;
    const uint32_t threads = static_cast<uint32_t>(config_.threads);
    const uint32_t rangeSize = 0xffffffffu / threads;
    const uint32_t nonceStart = rangeSize * static_cast<uint32_t>(threadId);
    const uint32_t nonceEnd = (threadId + 1 == config_.threads) ? 0xffffffffu :
                              rangeSize * static_cast<uint32_t>(threadId + 1) - 1;
    uint32_t nonce = nonceStart;
    const uint32_t batchSize = 64;
    uint8_t resultHash[32];
    algo::RandomXContext context(*randomxState_);

    while (!stopRequested_.load(std::memory_order_relaxed)) {
        const uint64_t v = randomx_->snapshotWork(work);
        if (v == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        if (v != knownVersion) {
            knownVersion = v;
            nonce = nonceStart;
            restart.store(false, std::memory_order_relaxed);
        }
        if (nonce < nonceStart || nonce > nonceEnd)
            nonce = nonceStart;

        const uint32_t maxNonce = (nonceEnd - nonce < batchSize - 1) ? nonceEnd : nonce + batchSize - 1;
        uint64_t hashesDone = 0;
        std::string error;
        const auto t0 = std::chrono::steady_clock::now();
        const bool found = algo::scanHashRandomX(context, work.blob, work.nonceOffset, work.seedHash,
                                                  work.target.data(), maxNonce, nonce, restart,
                                                  hashesDone, resultHash, error);
        const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (!error.empty()) {
            logf(LogLevel::Error, "thread %d: RandomX hash error: %s", threadId, error.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        if (elapsed > 0.0)
            threadHashrates_[static_cast<size_t>(threadId)] = hashesDone / elapsed;
        if (found)
            randomx_->submitShare(work, nonce, resultHash);
        if (nonce == 0xffffffffu)
            nonce = nonceStart;
        else
            ++nonce;
    }
}

void MinerEngine::run()
{
    restartFlags_.reserve(static_cast<size_t>(config_.threads));
    for (int i = 0; i < config_.threads; i++)
        restartFlags_.push_back(std::make_unique<std::atomic<bool>>(false));
    for (auto& f : restartFlags_)
        restartFlagPtrs_.push_back(f.get());
    threadHashrates_.assign(static_cast<size_t>(config_.threads), 0.0);

    if (config_.algo == Algorithm::Lyra2Web) {
        net::WebchainConfig wc;
        wc.url = config_.url;
        wc.user = config_.user;
        wc.pass = config_.pass;
        wc.retries = config_.retries;
        wc.retryPauseSeconds = config_.retryPauseSeconds;
        wc.protocolDump = config_.protocolDump;
        wc.tls.verifyPeer = config_.tlsVerify;
        wc.tls.pinnedPublicKey = config_.tlsPin;
        webchain_ = std::make_unique<net::WebchainClient>(wc, restartFlagPtrs_);
        webchain_->start();
    } else if (config_.algo == Algorithm::RandomX) {
        randomxState_ = std::make_unique<algo::RandomXState>(config_.randomxFullMemory, config_.randomxLargePages);
        logf(LogLevel::Notice, "RandomX mode: %s%s", randomxState_->modeName(),
             config_.randomxLargePages ? " with large pages requested" : "");
        net::RandomXConfig rc;
        rc.url = config_.url;
        rc.user = config_.user;
        rc.pass = config_.pass;
        rc.retries = config_.retries;
        rc.retryPauseSeconds = config_.retryPauseSeconds;
        rc.protocolDump = config_.protocolDump;
        rc.tls.verifyPeer = config_.tlsVerify;
        rc.tls.pinnedPublicKey = config_.tlsPin;
        randomx_ = std::make_unique<net::RandomXClient>(rc, restartFlagPtrs_);
        randomx_->start();
    } else {
        net::StratumConfig sc;
        sc.url = config_.url;
        sc.user = config_.user;
        sc.pass = config_.pass;
        sc.algo = config_.algo;
        sc.retries = config_.retries;
        sc.retryPauseSeconds = config_.retryPauseSeconds;
        sc.protocolDump = config_.protocolDump;
        sc.tls.verifyPeer = config_.tlsVerify;
        sc.tls.pinnedPublicKey = config_.tlsPin;
        stratum_ = std::make_unique<net::StratumClient>(sc, restartFlagPtrs_);
        stratum_->start();
    }

    logf(LogLevel::Notice, "starting %d miner thread(s) for algorithm %s", config_.threads,
         algorithmName(config_.algo));
    if (config_.algo == Algorithm::Lyra2Web)
        logf(LogLevel::Notice, "lyra2web backend: %s", algo::lyra2WebActiveBackendName());
    if (!config_.quiet && config_.hashrateIntervalSeconds > 0)
        logf(LogLevel::Notice, "hashrate report every %d s (press 'h' for a snapshot)", config_.hashrateIntervalSeconds);
    else if (!config_.quiet)
        logf(LogLevel::Notice, "press 'h' for a hashrate snapshot");

    startConsoleKeyWatcher([this]() { hashrateSnapshotRequested_.store(true, std::memory_order_relaxed); });

    for (int i = 0; i < config_.threads; i++) {
        if (config_.algo == Algorithm::Lyra2Web)
            workers_.emplace_back(&MinerEngine::webchainThreadLoop, this, i);
        else if (config_.algo == Algorithm::RandomX)
            workers_.emplace_back(&MinerEngine::randomXThreadLoop, this, i);
        else
            workers_.emplace_back(&MinerEngine::classicThreadLoop, this, i);
    }

    auto lastReport = std::chrono::steady_clock::now();
    while (!stopRequested_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        bool gaveUp = stratum_ ? stratum_->hasGivenUp() :
                       (webchain_ ? webchain_->hasGivenUp() : randomx_->hasGivenUp());
        if (gaveUp) {
            logf(LogLevel::Error, "network client gave up permanently, shutting down");
            break;
        }

        if (hashrateSnapshotRequested_.exchange(false, std::memory_order_relaxed))
            logHashrate(true);

        if (!config_.quiet && config_.hashrateIntervalSeconds > 0) {
            auto now = std::chrono::steady_clock::now();
            if (now - lastReport >= std::chrono::seconds(config_.hashrateIntervalSeconds)) {
                logHashrate(false);
                lastReport = now;
            }
        }
    }

    stopConsoleKeyWatcher();
    stop();
}

void MinerEngine::stop()
{
    stopRequested_ = true;
    for (auto& t : workers_)
        if (t.joinable())
            t.join();
    if (stratum_)
        stratum_->stop();
    if (webchain_)
        webchain_->stop();
    if (randomx_)
        randomx_->stop();

    uint64_t accepted = stratum_ ? stratum_->acceptedShares() :
                         (webchain_ ? webchain_->acceptedShares() : (randomx_ ? randomx_->acceptedShares() : 0));
    uint64_t rejected = stratum_ ? stratum_->rejectedShares() :
                         (webchain_ ? webchain_->rejectedShares() : (randomx_ ? randomx_->rejectedShares() : 0));
    logf(LogLevel::Notice, "stopped. final tally: %llu accepted / %llu rejected",
         static_cast<unsigned long long>(accepted), static_cast<unsigned long long>(rejected));
}

} // namespace cppminer
