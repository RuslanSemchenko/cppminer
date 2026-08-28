#include "RandomXClient.h"

#include "../ByteUtils.h"
#include "../Log.h"
#include "RandomXJobParser.h"
#include "UrlUtils.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace cppminer::net {
namespace {

constexpr const char* kUserAgent = "cppminer/0.1.0";

} // namespace

RandomXClient::RandomXClient(RandomXConfig config, std::vector<std::atomic<bool>*> restartFlags)
    : config_(std::move(config)), restartFlags_(std::move(restartFlags))
{
}

RandomXClient::~RandomXClient()
{
    stop();
}

void RandomXClient::start()
{
    stopRequested_ = false;
    gaveUp_ = false;
    thread_ = std::thread(&RandomXClient::threadMain, this);
}

void RandomXClient::stop()
{
    stopRequested_ = true;
    running_ = false;
    socket_.disconnect();
    if (thread_.joinable())
        thread_.join();
}

bool RandomXClient::hasWork() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return haveJob_;
}

uint64_t RandomXClient::snapshotWork(RandomXWork& out) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!haveJob_)
        return 0;
    out = currentWork_;
    return currentWork_.jobVersion;
}

bool RandomXClient::sendJson(const nlohmann::json& msg)
{
    std::string body = msg.dump();
    if (config_.protocolDump)
        logf(LogLevel::Debug, "randomx -> %s", body.c_str());
    body += '\n';
    std::lock_guard<std::mutex> lock(sendMutex_);
    return socket_.sendAll(body.c_str(), body.size());
}

void RandomXClient::submitShare(const RandomXWork& work, uint32_t nonce, const uint8_t resultHash[32])
{
    uint8_t nonceBytes[4];
    util::le32enc(nonceBytes, nonce);
    nlohmann::json req = {
        {"id", 4},
        {"method", "submit"},
        {"params", {
             {"id", config_.user},
             {"job_id", work.jobId},
             {"nonce", util::bin2hex(nonceBytes, sizeof(nonceBytes))},
             {"result", util::bin2hex(resultHash, 32)},
         }},
    };
    if (!sendJson(req))
        logf(LogLevel::Error, "failed to submit RandomX share: connection error");
}

void RandomXClient::handleJob(const nlohmann::json& params)
{
    RandomXWork work;
    std::string error;
    if (!parseRandomXJob(params, work, error)) {
        logf(LogLevel::Warning, "ignoring malformed RandomX job: %s", error.c_str());
        return;
    }

    const std::string jobId = work.jobId;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        work.jobVersion = ++jobVersion_;
        currentWork_ = std::move(work);
        haveJob_ = true;
    }
    for (auto* f : restartFlags_)
        if (f) f->store(true, std::memory_order_relaxed);
    logf(LogLevel::Debug, "new RandomX job %s", jobId.c_str());
}

void RandomXClient::onShareResult(bool accepted, const std::string& reason)
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

void RandomXClient::handleResponse(const nlohmann::json& msg)
{
    if (!msg.contains("id") || msg["id"].is_null() || !msg["id"].is_number_integer())
        return;
    const int id = msg["id"].get<int>();
    const bool hasError = msg.contains("error") && !msg["error"].is_null();
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

    if (id == 1) {
        bool ok = !hasError && msg.contains("result") && msg["result"].is_object();
        if (ok && msg["result"].contains("job"))
            handleJob(msg["result"]["job"]);
        lastResponseOk_ = ok;
        lastResponseError_ = ok ? std::string() : (hasError ? errMsg : "malformed login response");
        lastHandledResponseId_ = 1;
    } else if (id == 4) {
        bool ok = !hasError && msg.contains("result") &&
                  ((msg["result"].is_boolean() && msg["result"].get<bool>()) ||
                   (msg["result"].is_object() && msg["result"].value("status", "") == "OK"));
        onShareResult(ok, errMsg);
    }
}

void RandomXClient::handleLine(const std::string& line)
{
    if (config_.protocolDump)
        logf(LogLevel::Debug, "randomx <- %s", line.c_str());
    nlohmann::json msg;
    try {
        msg = nlohmann::json::parse(line);
    } catch (...) {
        logf(LogLevel::Debug, "ignoring non-JSON RandomX line");
        return;
    }
    if (!msg.is_object())
        return;

    if (msg.contains("method") && msg["method"].is_string()) {
        const std::string method = msg["method"].get<std::string>();
        if (method == "job" || method == "mining.notify") {
            handleJob(msg.contains("params") ? msg["params"] : nlohmann::json());
        } else if (method == "client.get_version" && msg.contains("id")) {
            sendJson({{"id", msg["id"]}, {"result", kUserAgent}, {"error", nullptr}});
        } else if (method == "client.show_message") {
            const auto& p = msg.contains("params") ? msg["params"] : nlohmann::json();
            if (p.is_object() && p.contains("message") && p["message"].is_string())
                logf(LogLevel::Notice, "pool message: %s", p["message"].get<std::string>().c_str());
        }
        return;
    }
    handleResponse(msg);
}

bool RandomXClient::pumpSocket(int waitMs)
{
    if (!socket_.waitReadable(waitMs))
        return true;
    char buf[8192];
    const int n = socket_.recvSome(buf, sizeof(buf));
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

bool RandomXClient::waitForResponseId(int id, int timeoutMs, std::string& error)
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

bool RandomXClient::connectAndHandshake(std::string& error)
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
    }

    nlohmann::json login = {
        {"id", 1},
        {"method", "login"},
        {"params", {{"login", config_.user}, {"pass", config_.pass}, {"agent", kUserAgent}}},
    };
    if (!sendJson(login)) {
        error = "failed to send RandomX login";
        return false;
    }
    if (!waitForResponseId(1, 15000, error)) {
        error = "RandomX login failed: " + error;
        return false;
    }
    return true;
}

void RandomXClient::sleepInterruptible(int ms)
{
    int waited = 0;
    while (waited < ms && !stopRequested_.load()) {
        const int step = std::min(200, ms - waited);
        std::this_thread::sleep_for(std::chrono::milliseconds(step));
        waited += step;
    }
}

void RandomXClient::threadMain()
{
    int attempt = 0;
    while (!stopRequested_.load()) {
        std::string error;
        logf(LogLevel::Info, "connecting to %s", config_.url.c_str());
        if (!connectAndHandshake(error)) {
            logf(LogLevel::Error, "%s", error.c_str());
            socket_.disconnect();
            running_ = false;
            ++attempt;
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
        logf(LogLevel::Notice, "connected to RandomX pool %s, authorized as %s", config_.url.c_str(), config_.user.c_str());
        for (auto* f : restartFlags_)
            if (f) f->store(true, std::memory_order_relaxed);

        bool alive = true;
        while (alive && !stopRequested_.load())
            alive = pumpSocket(1000);
        running_ = false;
        if (!stopRequested_.load())
            logf(LogLevel::Warning, "disconnected from RandomX pool, reconnecting...");
        socket_.disconnect();
        std::lock_guard<std::mutex> lock(mutex_);
        haveJob_ = false;
    }
}

} // namespace cppminer::net
