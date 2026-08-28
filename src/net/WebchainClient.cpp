#include "WebchainClient.h"

#include "../ByteUtils.h"
#include "../Log.h"
#include "UrlUtils.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace cppminer::net {

WebchainClient::WebchainClient(WebchainConfig config, std::vector<std::atomic<bool>*> restartFlags)
    : config_(std::move(config)), restartFlags_(std::move(restartFlags))
{
}

WebchainClient::~WebchainClient()
{
    stop();
}

void WebchainClient::start()
{
    stopRequested_ = false;
    thread_ = std::thread(&WebchainClient::threadMain, this);
}

void WebchainClient::stop()
{
    stopRequested_ = true;
    running_ = false;
    if (thread_.joinable())
        thread_.join();
    socket_.disconnect();
}

bool WebchainClient::hasWork() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return haveJob_;
}

uint64_t WebchainClient::snapshotWork(WebchainWork& out) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!haveJob_)
        return 0;
    out = currentWork_;
    return currentWork_.jobVersion;
}

bool WebchainClient::sendJson(const nlohmann::json& msg)
{
    std::string body = msg.dump();
    if (config_.protocolDump)
        logf(LogLevel::Debug, "webchain -> %s", body.c_str());
    body += "\n";
    std::lock_guard<std::mutex> lock(sendMutex_);
    return socket_.sendAll(body.c_str(), body.size());
}

int WebchainClient::nextRequestId(bool trackAsSubmit)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int id = ++seq_;
    if (trackAsSubmit) {
        if (pendingSubmitIds_.size() < 64)
            pendingSubmitIds_.push_back(id);
        else
            logf(LogLevel::Warning, "Webchain submit queue is full; response tracking degraded");
    }
    return id;
}

bool WebchainClient::takeSubmitId(int id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find(pendingSubmitIds_.begin(), pendingSubmitIds_.end(), id);
    if (it == pendingSubmitIds_.end())
        return false;
    pendingSubmitIds_.erase(it);
    return true;
}

void WebchainClient::submitShare(const WebchainWork& work, uint64_t nonce, const uint8_t hash[32])
{
    uint8_t nonceBytes[8];
    // Same raw (native little-endian) byte order scanHashLyra2Web patches
    // into the blob's last 8 bytes - see Lyra2Web.h.
    std::memcpy(nonceBytes, &nonce, 8);
    std::string nonceHex = util::bin2hex(nonceBytes, 8);
    std::string hashHex = util::bin2hex(hash, 32);

    std::string rpcId;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        rpcId = rpcId_;
    }

    int id = nextRequestId(true);
    nlohmann::json req = {
        {"id", id},
        {"jsonrpc", "2.0"},
        {"method", "submit"},
        {"worker", config_.user},
        {"params", {{"id", rpcId}, {"job_id", work.jobId}, {"nonce", nonceHex}, {"result", hashHex}}},
    };

    if (!sendJson(req)) {
        takeSubmitId(id); // do not wait forever for a response that will never arrive
        logf(LogLevel::Error, "failed to submit Webchain share: connection error");
    }
}

bool WebchainClient::parseJobLocked(const nlohmann::json& job, std::string& error)
{
    if (!job.is_object() || !job.contains("blob") || !job["blob"].is_string() ||
        !job.contains("job_id") || !job["job_id"].is_string() ||
        !job.contains("target") || !job["target"].is_string()) {
        error = "malformed Webchain job (missing blob/job_id/target)";
        return false;
    }

    std::string blobHex = job["blob"].get<std::string>();
    std::string jobId = job["job_id"].get<std::string>();
    std::string targetHex = job["target"].get<std::string>();

    // MintMe pool emits common.ToHex(diff.Bytes()), which is a variable-
    // width hex string without leading zeroes. The original Webchain miner
    // accepts up to 16 hex digits and decodes the value as a little-endian
    // 64-bit target, so pad the pool value on the left before decoding.
    if (targetHex.empty() || targetHex.size() > 16 || (targetHex.size() & 1) != 0) {
        error = "malformed Webchain job (target must contain 1-16 even hex digits)";
        return false;
    }
    std::string normalizedTarget(16 - targetHex.size(), '0');
    normalizedTarget += targetHex;
    if (blobHex.size() % 2 != 0 || blobHex.size() / 2 < 8 || blobHex.size() / 2 > 65536) {
        error = "malformed Webchain job (bad blob size)";
        return false;
    }

    uint32_t tcost = 4;
    if (job.contains("algo") && job["algo"].is_string()) {
        std::string a = job["algo"].get<std::string>();
        std::string lower = a;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower.find("lyra2v2") != std::string::npos)
            tcost = 1;
        else if (lower.find("lyra2") != std::string::npos)
            tcost = 4;
        else {
            error = "unsupported Webchain algorithm '" + a + "'";
            return false;
        }
    }

    WebchainWork w;
    w.blob = util::hexToBytes(blobHex);
    if (!util::hex2bin(w.target.data(), normalizedTarget, 8)) {
        error = "malformed Webchain job (target is not hexadecimal)";
        return false;
    }
    bool targetIsZero = true;
    for (uint8_t byte : w.target)
        targetIsZero = targetIsZero && byte == 0;
    if (targetIsZero) {
        error = "malformed Webchain job (target must be non-zero)";
        return false;
    }
    w.lyra2Tcost = tcost;
    w.jobId = jobId;
    w.jobVersion = ++jobVersion_;

    currentWork_ = std::move(w);
    haveJob_ = true;
    return true;
}

void WebchainClient::handleJobPush(const nlohmann::json& params)
{
    std::string error;
    bool ok;
    std::string jobId;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ok = parseJobLocked(params, error);
        if (ok)
            jobId = currentWork_.jobId;
    }
    if (!ok) {
        logf(LogLevel::Warning, "%s, ignoring job push", error.c_str());
        return;
    }
    logf(LogLevel::Debug, "new Webchain job %s", jobId.c_str());
    // Webchain jobs have no clean_jobs flag - every push is effectively a
    // fresh block template, so always abort any in-flight scan.
    for (auto* f : restartFlags_)
        if (f) f->store(true, std::memory_order_relaxed);
}

void WebchainClient::handleKeepalivedPush(const nlohmann::json& msg)
{
    int echoId = 1;
    if (msg.contains("id") && msg["id"].is_number_integer())
        echoId = msg["id"].get<int>();
    std::string rpcId;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        rpcId = rpcId_;
    }
    nlohmann::json resp = {
        {"id", echoId}, {"error", nullptr}, {"result", true}, {"params", {{"id", rpcId}}},
    };
    sendJson(resp);
}

void WebchainClient::onShareResult(bool accepted, const std::string& reason)
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

void WebchainClient::handleResponse(const nlohmann::json& msg)
{
    if (loginPending_) {
        loginPending_ = false;

        bool hasError = msg.contains("error") && !msg["error"].is_null();
        if (hasError) {
            const auto& e = msg["error"];
            loginOk_ = false;
            loginError_ = e.is_object() && e.contains("message") && e["message"].is_string()
                              ? e["message"].get<std::string>()
                              : e.dump();
            return;
        }
        if (!msg.contains("result") || !msg["result"].is_object()) {
            loginOk_ = false;
            loginError_ = "malformed login response";
            return;
        }

        const auto& result = msg["result"];
        std::string jobError;
        bool jobOk;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (result.contains("id") && result["id"].is_string())
                rpcId_ = result["id"].get<std::string>();
            jobOk = result.contains("job") ? parseJobLocked(result["job"], jobError) : false;
            if (!result.contains("job"))
                jobError = "login response has no job";
            if (jobOk) {
                seq_ = 1; // login consumed id 1; the next generated id is 2
                pendingSubmitIds_.clear();
            }
        }
        loginOk_ = jobOk;
        loginError_ = jobOk ? std::string() : jobError;
        return;
    }

    if (!msg.contains("id") || msg["id"].is_null() || !msg["id"].is_number_integer())
        return;
    int id = msg["id"].get<int>();
    if (!takeSubmitId(id))
        return; // not one of our pending submits (e.g. a stray keepalive echo)

    bool hasError = msg.contains("error") && !msg["error"].is_null();
    if (hasError) {
        const auto& e = msg["error"];
        std::string em = e.is_object() && e.contains("message") && e["message"].is_string()
                              ? e["message"].get<std::string>()
                              : e.dump();
        onShareResult(false, em);
        return;
    }
    if (msg.contains("result") && msg["result"].is_object()) {
        const auto& r = msg["result"];
        std::string status = r.contains("status") && r["status"].is_string() ? r["status"].get<std::string>() : "";
        std::string lowerStatus = status;
        std::transform(lowerStatus.begin(), lowerStatus.end(), lowerStatus.begin(),
                        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        bool ok = lowerStatus == "ok";
        std::string err = ok ? std::string()
                              : (r.contains("error") && r["error"].is_string() ? r["error"].get<std::string>() : status);
        onShareResult(ok, err);
        return;
    }
    if (msg.contains("result") && msg["result"].is_boolean()) {
        onShareResult(msg["result"].get<bool>(), std::string());
    }
}

void WebchainClient::handleLine(const std::string& line)
{
    if (config_.protocolDump)
        logf(LogLevel::Debug, "webchain <- %s", line.c_str());

    nlohmann::json msg;
    try {
        msg = nlohmann::json::parse(line);
    } catch (const std::exception&) {
        logf(LogLevel::Debug, "ignoring non-JSON webchain line");
        return;
    }
    if (!msg.is_object())
        return;

    if (msg.contains("method") && msg["method"].is_string()) {
        std::string method = msg["method"].get<std::string>();
        if (method == "job") {
            handleJobPush(msg.contains("params") ? msg["params"] : msg);
        } else if (method == "keepalived") {
            handleKeepalivedPush(msg);
        }
        return;
    }

    handleResponse(msg);
}

int WebchainClient::pumpSocket(int waitMs)
{
    if (!socket_.waitReadable(waitMs))
        return 0; // timeout, connection still fine

    char buf[4096];
    int n = socket_.recvSome(buf, sizeof(buf));
    if (n < 0)
        return -1;
    if (n == 0)
        return 0;

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
    return n;
}

bool WebchainClient::waitForLoginResponse(int timeoutMs, std::string& error)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pumpSocket(200) < 0) {
            error = "connection closed while logging in";
            return false;
        }
        if (!loginPending_) {
            error = loginError_;
            return loginOk_;
        }
    }
    error = "timed out waiting for the login response";
    return false;
}

bool WebchainClient::connectAndLogin(std::string& error)
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
        haveJob_ = false;
        rpcId_.clear();
        seq_ = 0;
        pendingSubmitIds_.clear();
    }

    nlohmann::json loginReq = {
        {"id", 1},
        {"jsonrpc", "2.0"},
        {"method", "login"},
        {"worker", config_.user},
        // "agent" intentionally mirrors the reference miner's string for
        // maximum compatibility with pool-side agent allow-lists.
        {"params", {{"login", config_.user}, {"pass", config_.pass}, {"agent", "cpuminer"}}},
    };

    loginPending_ = true;
    loginOk_ = false;
    loginError_.clear();
    if (!sendJson(loginReq)) {
        error = "failed to send login request";
        return false;
    }

    return waitForLoginResponse(15000, error);
}

void WebchainClient::sleepInterruptible(int ms)
{
    int waited = 0;
    while (waited < ms && !stopRequested_.load()) {
        int step = std::min(200, ms - waited);
        std::this_thread::sleep_for(std::chrono::milliseconds(step));
        waited += step;
    }
}

void WebchainClient::threadMain()
{
    int attempt = 0;
    while (!stopRequested_.load()) {
        std::string error;
        logf(LogLevel::Info, "connecting to %s", config_.url.c_str());

        if (!connectAndLogin(error)) {
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
        logf(LogLevel::Notice, "connected to %s, logged in as %s", config_.url.c_str(), config_.user.c_str());
        for (auto* f : restartFlags_)
            if (f) f->store(true, std::memory_order_relaxed);

        auto lastActivity = std::chrono::steady_clock::now();
        bool alive = true;
        while (alive && !stopRequested_.load()) {
            int n = pumpSocket(1000);
            if (n < 0) {
                alive = false;
                break;
            }
            auto now = std::chrono::steady_clock::now();
            if (n > 0) {
                lastActivity = now;
            } else if (now - lastActivity >= std::chrono::seconds(15)) {
                std::string rpcId;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    rpcId = rpcId_;
                }
                int id = nextRequestId(false);
                nlohmann::json params = rpcId.empty() ? nlohmann::json::object() : nlohmann::json{{"id", rpcId}};
                sendJson({{"id", id}, {"jsonrpc", "2.0"}, {"method", "keepalived"}, {"params", params}});
                lastActivity = now;
            }
        }

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
