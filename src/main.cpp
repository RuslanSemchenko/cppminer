#include "Benchmark.h"
#include "Config.h"
#include "Log.h"
#include "MinerEngine.h"
#include "algo/Lyra2Web.h"
#include "algo/RandomX.h"
#include "algo/Scrypt.h"
#include "algo/Sha256.h"
#include "simd/CpuFeatures.h"

#include <curl/curl.h>

#include <csignal>

namespace {

cppminer::MinerEngine* g_engine = nullptr;

void handleSignal(int)
{
    if (g_engine)
        g_engine->requestStop();
}

} // namespace

int main(int argc, char** argv)
{
    cppminer::Config config;
    int exitCode = 0;
    if (!cppminer::Config::parse(argc, argv, config, exitCode))
        return exitCode;

    cppminer::logSetDebug(config.debug);
    cppminer::logSetQuiet(config.quiet);

    cppminer::logf(cppminer::LogLevel::Info, "CPU features: %s", cppminer::simd::cpuFeaturesString());

    std::string shaBackendError;
    if (!cppminer::algo::sha256SelectBackend(config.sha256Backend, shaBackendError)) {
        cppminer::logf(cppminer::LogLevel::Error, "%s", shaBackendError.c_str());
        return 1;
    }
    cppminer::logf(cppminer::LogLevel::Info, "sha256d backend: %s", cppminer::algo::sha256ActiveBackendName());

    std::string lyraBackendError;
    if (!cppminer::algo::lyra2WebSelectBackend(config.lyraBackend, lyraBackendError)) {
        cppminer::logf(cppminer::LogLevel::Error, "%s", lyraBackendError.c_str());
        return 1;
    }
    if (config.algo == cppminer::Algorithm::Lyra2Web || config.benchmark)
        cppminer::logf(cppminer::LogLevel::Info, "lyra2web backend: %s", cppminer::algo::lyra2WebActiveBackendName());

    if (config.benchmark)
        return cppminer::runBenchmark(config);

    bool selfTestOk = true;
    switch (config.algo) {
    case cppminer::Algorithm::Lyra2Web:
        cppminer::logf(cppminer::LogLevel::Info, "running the Lyra2-webchain self-test...");
        selfTestOk = cppminer::algo::lyra2WebSelfTest();
        break;
    case cppminer::Algorithm::Sha256d:
        cppminer::logf(cppminer::LogLevel::Info, "running the sha256d self-test (backend: %s)...",
                        cppminer::algo::sha256ActiveBackendName());
        selfTestOk = cppminer::algo::sha256SimdSelfTest();
        break;
    case cppminer::Algorithm::RandomX:
        cppminer::logf(cppminer::LogLevel::Info, "running the RandomX self-test (SIMD: %s)...",
                        cppminer::algo::randomXSimdFeaturesString());
        selfTestOk = cppminer::algo::randomXSelfTest();
        break;
    case cppminer::Algorithm::Scrypt:
        cppminer::logf(cppminer::LogLevel::Info, "running the scrypt self-test (backend: %s)...",
                        cppminer::algo::scryptActiveBackendName());
        selfTestOk = cppminer::algo::scryptSimdSelfTest();
        break;
    }
    if (!selfTestOk) {
        cppminer::logf(cppminer::LogLevel::Error,
                        "%s self-test FAILED against the reference vectors, refusing to mine",
                        cppminer::algorithmName(config.algo));
        return 1;
    }
    cppminer::logf(cppminer::LogLevel::Info, "self-test OK");

    curl_global_init(CURL_GLOBAL_DEFAULT);

    {
        cppminer::MinerEngine engine(config);
        g_engine = &engine;
        std::signal(SIGINT, handleSignal);
        std::signal(SIGTERM, handleSignal);

        engine.run();
        g_engine = nullptr;
    }

    curl_global_cleanup();
    return 0;
}
