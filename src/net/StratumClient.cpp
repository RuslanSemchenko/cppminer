#include "StratumClient.h"

#include "../ByteUtils.h"
#include "../Log.h"
#include "../algo/Sha256.h"
#include "UrlUtils.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace cppminer::net {

namespace {

constexpr const char* kUserAgent = "cppminer/0.1.0";

std::array<uint8_t, 32> computeMerkleRoot(const std::vector<uint8_t>& coinbase,
                                           const std::vector<std::array<uint8_t, 32>>& branch)
{
    std::array<uint8_t, 32> root{};
    algo::Sha256::hash256d(coinbase.data(), coinbase.size(), root.data());
    for (const auto& node : branch) {
        uint8_t buf[64];
        std::memcpy(buf, root.data(), 32);
        std::memcpy(buf + 32, node.data(), 32);
        algo::Sha256::hash256d(buf, 64, root.data());
    }
    return root;
}

// Builds the true 80-byte header from the wire fields. See Work.h for the
// byte layout and StratumClient.cpp's module comment / the design notes in
// the session log for the byte-order derivation: version/prevhash(per
// 4-byte chunk)/ntime/nbits are reversed relative to their wire encoding,
// the locally computed merkle root is used as-is. Bytes [76,80) (the nonce)
// are left untouched for the caller to fill in.
void buildClassicHeader(uint8_t header[80], const std::vector<uint8_t>& wireVersion,
                         const std::vector<uint8_t>& wirePrevhash, const std::array<uint8_t, 32>& merkleRoot,
                         const std::vector<uint8_t>& wireNtime, const std::vector<uint8_t>& wireNbits)
{
    for (int i = 0; i < 4; i++)
        header[i] = wireVersion[3 - i];
    for (int c = 0; c < 8; c++)
        for (int i = 0; i < 4; i++)
            header[4 + 4 * c + i] = wirePrevhash[4 * c + (3 - i)];
    std::memcpy(header + 36, merkleRoot.data(), 32);
    for (int i = 0; i < 4; i++)
        header[68 + i] = wireNtime[3 - i];
    for (int i = 0; i < 4; i++)
        header[72 + i] = wireNbits[3 - i];
}

} // namespace

StratumClient::StratumClient(StratumConfig config, std::vector<std::atomic<bool>*> restartFlags)
    : config_(std::move(config)), restartFlags_(std::move(restartFlags))
{
}

StratumClient::~StratumClient()
{
    stop();
}

void StratumClient::start()
{
    stopRequested_ = false;
    thread_ = std::thread(&StratumClient::threadMain, this);
}

void StratumClient::stop()
{
    stopRequested_ = true;
    running_ = false;
    if (thread_.joinable())
        thread_.join();
    socket_.disconnect();
}

bool StratumClient::hasWork() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return haveJob_;
}

uint64_t StratumClient::snapshotWork(ClassicWork& out) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!haveJob_)
        return 0;
    out = currentWork_;
    return currentWork_.jobVersion;
}

bool StratumClient::rollExtranonce2(uint64_t expectedVersion)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!haveJob_ || currentWork_.jobVersion != expectedVersion || extranonce2_.empty())
        return false;

    // Treat extranonce2 as a big-endian byte string for deterministic
    // rollover. Carrying from the least-significant byte preserves every
    // value in the pool-advertised fixed-width namespace.
    for (auto it = extranonce2_.rbegin(); it != extranonce2_.rend(); ++it) {
        if (++(*it) != 0)
            break;
    }
    buildWorkLocked();
    return true;
}

bool StratumClient::sendJson(const nlohmann::json& msg)
{
    std::string body = msg.dump();
    if (config_.protocolDump)
        logf(LogLevel::Debug, "stratum -> %s", body.c_str());
    body += "\n";
    std::lock_guard<std::mutex> lock(sendMutex_);
    return socket_.sendAll(body.c_str(), body.size());
}

void StratumClient::submitShare(const ClassicWork& work, uint32_t nonce)
{
    uint8_t nonceBytes[4];
    // Wire convention: little-endian encoding of the nonce integer (the
    // reverse of the true header bytes it produces - see scanHashSha256d /
    // scanHashScrypt, which fill header[76,80) with util::be32enc(n)).
    util::le32enc(nonceBytes, nonce);

    nlohmann::json req = {
        {"id", 4},
        {"method", "mining.submit"},
        {"params", nlohmann::json::array({
             config_.user,
             work.jobId,
             util::bin2hex(work.extranonce2.data(), work.extranonce2.size()),
             util::bin2hex(work.ntimeWire.data(), 4),
             util::bin2hex(nonceBytes, 4),
         })},
    };

    if (!sendJson(req))
        logf(LogLevel::Error, "failed to submit share: connection error");
}

void StratumClient::buildWorkLocked()
{
    std::vector<uint8_t> coinbase;
    coinbase.reserve(coinb1_.size() + extranonce1_.size() + extranonce2_.size() + coinb2_.size());
    coinbase.insert(coinbase.end(), coinb1_.begin(), coinb1_.end());
    coinbase.insert(coinbase.end(), extranonce1_.begin(), extranonce1_.end());
    coinbase.insert(coinbase.end(), extranonce2_.begin(), extranonce2_.end());
    coinbase.insert(coinbase.end(), coinb2_.begin(), coinb2_.end());

    auto merkleRoot = computeMerkleRoot(coinbase, merkleBranch_);

    ClassicWork w;
    buildClassicHeader(w.header.data(), version_, prevhash_, merkleRoot, ntime_, nbits_);
    // scrypt pools traditionally scale reported difficulty by 65536 - a
    // long-standing quirk inherited from the original Litecoin stratum
    // implementations (see diff_to_target()'s caller in cpu-miner.c).
    util::diffToTarget(w.target.data(), config_.algo == Algorithm::Scrypt ? diff_ / 65536.0 : diff_);
    w.jobId = jobId_;
    w.extranonce2 = extranonce2_;
    std::copy(ntime_.begin(), ntime_.end(), w.ntimeWire.begin());
    w.jobVersion = ++jobVersion_;

    currentWork_ = std::move(w);
    haveJob_ = true;
}

void StratumClient::handleNotify(const nlohmann::json& p)
{
    if (!p.is_array() || p.size() < 9) {
        logf(LogLevel::Warning, "malformed mining.notify (wrong param count), ignoring");
        return;
    }
    try {
        std::string jobId = p[0].get<std::string>();
        std::string prevhashHex = p[1].get<std::string>();
        std::string coinb1Hex = p[2].get<std::string>();
        std::string coinb2Hex = p[3].get<std::string>();
        if (!p[4].is_array()) {
            logf(LogLevel::Warning, "malformed mining.notify (merkle branch not an array), ignoring");
            return;
        }
        std::string versionHex = p[5].get<std::string>();
        std::string nbitsHex = p[6].get<std::string>();
        std::string ntimeHex = p[7].get<std::string>();
        bool clean = p[8].is_boolean() && p[8].get<bool>();

        if (prevhashHex.size() != 64 || versionHex.size() != 8 || nbitsHex.size() != 8 || ntimeHex.size() != 8) {
            logf(LogLevel::Warning, "malformed mining.notify (bad field length), ignoring");
            return;
        }

        std::vector<std::array<uint8_t, 32>> branch;
        branch.reserve(p[4].size());
        for (const auto& m : p[4]) {
            if (!m.is_string() || m.get<std::string>().size() != 64) {
                logf(LogLevel::Warning, "malformed mining.notify (bad merkle branch entry), ignoring");
                return;
            }
            std::array<uint8_t, 32> b{};
            util::hex2bin(b.data(), m.get<std::string>(), 32);
            branch.push_back(b);
        }

        std::vector<uint8_t> prevhash = util::hexToBytes(prevhashHex);
        std::vector<uint8_t> coinb1 = util::hexToBytes(coinb1Hex);
        std::vector<uint8_t> coinb2 = util::hexToBytes(coinb2Hex);
        std::vector<uint8_t> version = util::hexToBytes(versionHex);
        std::vector<uint8_t> nbits = util::hexToBytes(nbitsHex);
        std::vector<uint8_t> ntime = util::hexToBytes(ntimeHex);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            diff_ = nextDiff_;
            bool newJob = (jobId_ != jobId);
            jobId_ = jobId;
            prevhash_ = std::move(prevhash);
            coinb1_ = std::move(coinb1);
            coinb2_ = std::move(coinb2);
            merkleBranch_ = std::move(branch);
            version_ = std::move(version);
            nbits_ = std::move(nbits);
            ntime_ = std::move(ntime);

            if (newJob || extranonce2_.size() != extranonce2Size_)
                extranonce2_.assign(extranonce2Size_, 0);

            buildWorkLocked();
        }

        logf(LogLevel::Debug, "new job %s (clean=%d)", jobId.c_str(), clean ? 1 : 0);
        if (clean) {
            for (auto* f : restartFlags_)
                if (f) f->store(true, std::memory_order_relaxed);
        }
    } catch (const std::exception& e) {
        logf(LogLevel::Warning, "malformed mining.notify (%s), ignoring", e.what());
    }
}

void StratumClient::handleSetDifficulty(const nlohmann::json& p)
{
    if (!p.is_array() || p.empty() || !p[0].is_number())
        return;
    double d = p[0].get<double>();
    if (d <= 0.0)
        return;
    std::lock_guard<std::mutex> lock(mutex_);
    nextDiff_ = d;
}

void StratumClient::onShareResult(bool accepted, const std::string& reason)
{
    if (accepted) {
        accepted_++;
        logf(LogLevel::Info, "share accepted (%llu/%llu)",
             static_cast<unsigned long long>(accepted_.load()),
             static_cast<unsigned long long>(accepted_.load() + rejected_.load()));
    } else {
        rejected_++;
        logf(LogLevel::Warning, "share rejected%s%s", reason.empty() ? "" : ": ", reason.c_str());
    }
}

void StratumClient::handleResponse(const nlohmann::json& msg)
{
    if (!msg.contains("id") || msg["id"].is_null() || !msg["id"].is_number_integer())
        return;
    int id = msg["id"].get<int>();

    bool hasError = msg.contains("error") && !msg["error"].is_null();
    std::string errMsg;
    if (hasError) {
        const auto& e = msg["error"];
        if (e.is_array() && e.size() > 1 && e[1].is_string())
            errMsg = e[1].get<std::string>();
        else if (e.is_object() && e.contains("message") && e["message"].is_string())
            errMsg = e["message"].get<std::string>();
        else
            errMsg = e.dump();
    }

    if (id == 1) { // mining.subscribe
        if (!hasError && msg.contains("result") && msg["result"].is_array() && msg["result"].size() >= 3 &&
            msg["result"][1].is_string() && msg["result"][2].is_number_integer()) {
            std::string xn1Hex = msg["result"][1].get<std::string>();
            int xn2Size = msg["result"][2].get<int>();
            std::lock_guard<std::mutex> lock(mutex_);
            extranonce1_ = util::hexToBytes(xn1Hex);
            extranonce2Size_ = (xn2Size > 0 && xn2Size <= 100) ? static_cast<size_t>(xn2Size) : 4;
            lastResponseOk_ = true;
        } else {
            lastResponseOk_ = false;
            lastResponseError_ = hasError ? errMsg : "malformed mining.subscribe response";
        }
        lastHandledResponseId_ = 1;
        return;
    }
    if (id == 2) { // mining.authorize
        bool ok = !hasError && msg.contains("result") && msg["result"].is_boolean() && msg["result"].get<bool>();
        lastResponseOk_ = ok;
        lastResponseError_ = ok ? std::string() : (hasError ? errMsg : std::string("authorization rejected"));
        lastHandledResponseId_ = 2;
        return;
    }
    if (id == 4) { // mining.submit
        bool ok = !hasError && msg.contains("result") && msg["result"].is_boolean() && msg["result"].get<bool>();
        onShareResult(ok, errMsg);
        return;
    }
}

void StratumClient::handleLine(const std::string& line)
{
    if (config_.protocolDump)
        logf(LogLevel::Debug, "stratum <- %s", line.c_str());

    nlohmann::json msg;
    try {
        msg = nlohmann::json::parse(line);
    } catch (const std::exception&) {
        logf(LogLevel::Debug, "ignoring non-JSON stratum line");
        return;
    }
    if (!msg.is_object())
        return;

    if (msg.contains("method") && msg["method"].is_string()) {
        std::string method = msg["method"].get<std::string>();
        nlohmann::json params = msg.contains("params") ? msg["params"] : nlohmann::json::array();

        if (method == "mining.notify") {
            handleNotify(params);
        } else if (method == "mining.set_difficulty") {
            handleSetDifficulty(params);
        } else if (method == "client.reconnect") {
            logf(LogLevel::Notice, "pool requested a reconnect");
            socket_.disconnect();
        } else if (method == "client.get_version") {
            if (msg.contains("id") && !msg["id"].is_null())
                sendJson({{"id", msg["id"]}, {"result", kUserAgent}, {"error", nullptr}});
        } else if (method == "client.show_message") {
            std::string text = (params.is_array() && !params.empty() && params[0].is_string())
                                    ? params[0].get<std::string>()
                                    : std::string();
            logf(LogLevel::Notice, "pool message: %s", text.c_str());
            if (msg.contains("id") && !msg["id"].is_null())
                sendJson({{"id", msg["id"]}, {"result", true}, {"error", nullptr}});
        }
        return;
    }

    handleResponse(msg);
}

bool StratumClient::pumpSocket(int waitMs)
{
    if (!socket_.waitReadable(waitMs))
        return true; // just a timeout, connection still fine

    char buf[4096];
    int n = socket_.recvSome(buf, sizeof(buf));
    if (n < 0)
        return false;
    if (n == 0)
        return true;

    recvBuffer_.append(buf, static_cast<size_t>(n));
    size_t pos;
    while ((pos = recvBuffer_.find('\n')) != std::string::npos) {
        std::string line = recvBuffer_.substr(0, pos);
        recvBuffer_.erase(0, pos + 1);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            handleLine(line);
    }
    return true;
}

bool StratumClient::waitForResponseId(int id, int timeoutMs, std::string& error)
{
    lastHandledResponseId_ = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!pumpSocket(200)) {
            error = "connection closed while waiting for a response";
            return false;
        }
        if (lastHandledResponseId_ == id) {
            error = lastResponseError_;
            return lastResponseOk_;
        }
    }
    error = "timed out waiting for a response";
    return false;
}

bool StratumClient::connectAndHandshake(std::string& error)
{
    std::string url = rewriteStratumUrl(config_.url);
    if (url.empty()) {
        error = "unsupported URL scheme in '" + config_.url + "'";
        return false;
    }

    if (!socket_.connect(url, 30, error, config_.tls))
        return false;

    recvBuffer_.clear();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        extranonce1_.clear();
        extranonce2Size_ = 4;
        haveJob_ = false;
    }

    nlohmann::json subscribeReq = {
        {"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array({kUserAgent})},
    };
    if (!sendJson(subscribeReq)) {
        error = "failed to send mining.subscribe";
        return false;
    }
    if (!waitForResponseId(1, 15000, error)) {
        error = "mining.subscribe failed: " + error;
        return false;
    }

    nlohmann::json authReq = {
        {"id", 2}, {"method", "mining.authorize"}, {"params", nlohmann::json::array({config_.user, config_.pass})},
    };
    if (!sendJson(authReq)) {
        error = "failed to send mining.authorize";
        return false;
    }
    if (!waitForResponseId(2, 15000, error)) {
        error = "mining.authorize failed: " + error;
        return false;
    }

    return true;
}

void StratumClient::sleepInterruptible(int ms)
{
    int waited = 0;
    while (waited < ms && !stopRequested_.load()) {
        int step = std::min(200, ms - waited);
        std::this_thread::sleep_for(std::chrono::milliseconds(step));
        waited += step;
    }
}

void StratumClient::threadMain()
{
    int attempt = 0;
    while (!stopRequested_.load()) {
        std::string error;
        logf(LogLevel::Info, "connecting to %s", config_.url.c_str());

        if (!connectAndHandshake(error)) {
            logf(LogLevel::Error, "%s", error.c_str());
            socket_.disconnect();
            running_ = false;
            attempt++;
            if (config_.retries >= 0 && attempt > config_.retries) {
                logf(LogLevel::Error, "giving up after %d connection attempt(s)", attempt);
                gaveUp_ = true;
                return;
            }
            sleepInterruptible(config_.retryPauseSeconds * 1000);
            continue;
        }

        attempt = 0;
        running_ = true;
        logf(LogLevel::Notice, "connected to %s, authorized as %s", config_.url.c_str(), config_.user.c_str());
        for (auto* f : restartFlags_)
            if (f) f->store(true, std::memory_order_relaxed);

        bool alive = true;
        while (alive && !stopRequested_.load())
            alive = pumpSocket(1000);

        running_ = false;
        if (!stopRequested_.load())
            logf(LogLevel::Warning, "disconnected from pool, reconnecting...");
        socket_.disconnect();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            haveJob_ = false;
        }
    }
}

} // namespace cppminer::net
