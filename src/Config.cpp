#include "Config.h"

#include "JsonCompat.h"

#include <fstream>
#include <iostream>
#include <thread>

namespace cppminer {

namespace {

const char kUsage[] =
    "Usage: cppminer -o URL -u USER -p PASS [options]\n"
    "\n"
    "Options:\n"
    "  -o, --url=URL          stratum+tcp://host:port (lyra2web pools use their\n"
    "                         plain json-rpc host:port the same way)\n"
    "  -u, --user=USERNAME    pool username / worker name\n"
    "  -p, --pass=PASSWORD    pool password\n"
    "  -O, --userpass=U:P     username:password combined\n"
    "  -a, --algo=ALGO        scrypt (default), scrypt:N, sha256d, lyra2web or randomx\n"
    "  -t, --threads=N        number of miner threads (default: number of CPUs)\n"
    "  -r, --retries=N        connect retries, -1 = infinite (default: -1)\n"
    "  -R, --retry-pause=N    seconds between retries (default: 30)\n"
    "  -c, --config=FILE      load options from a JSON config file\n"
    "  -q, --quiet            disable periodic hashrate reports\n"
    "  -P, --protocol-dump    verbose dump of the stratum/webchain protocol\n"
    "  -D, --debug            enable debug output\n"
    "  --no-tls-verify        disable TLS certificate/hostname verification\n"
    "  --tls-pin=KEY          pin libcurl public key (sha256//... or key file)\n"
    "  --sha256-backend=NAME  auto, scalar, sse2, avx2, avx512 or sha-ni\n"
    "  --lyra-backend=NAME    auto, scalar, sse2, avx2 or avx512\n"
    "  --hashrate-interval=N  seconds between hashrate reports (default: 30, 0=off)\n"
    "  --randomx-full-mem     use the faster ~2 GiB shared RandomX dataset (default)\n"
    "  --randomx-light        use the slower ~256 MiB RandomX light mode\n"
    "  --randomx-large-pages  request large pages for RandomX allocations\n"
    "  --benchmark            offline SIMD/hashrate benchmark, no pool needed\n"
    "                         (benchmarks all four algorithms unless -a is\n"
    "                         also given)\n"
    "  --bench-seconds=N      seconds per backend in --benchmark (default: 3)\n"
    "  -V, --version          display version information and exit\n"
    "  -h, --help             display this help text and exit\n";

const char kVersion[] = "cppminer 0.1.0 (scrypt, sha256d, lyra2web, randomx)";

bool applyOption(Config& cfg, const std::string& name, const std::string& value, std::string& error)
{
    try {
        if (name == "url") {
            cfg.url = value;
        } else if (name == "user") {
            cfg.user = value;
        } else if (name == "pass") {
            cfg.pass = value;
        } else if (name == "userpass") {
            auto pos = value.find(':');
            if (pos == std::string::npos) {
                error = "--userpass expects USER:PASS";
                return false;
            }
            cfg.user = value.substr(0, pos);
            cfg.pass = value.substr(pos + 1);
        } else if (name == "algo") {
            if (!algorithmFromName(value, cfg.algo, cfg.scryptN)) {
                error = "unknown algorithm '" + value + "'";
                return false;
            }
            cfg.algoExplicit = true;
        } else if (name == "threads") {
            cfg.threads = std::stoi(value);
        } else if (name == "retries") {
            cfg.retries = std::stoi(value);
        } else if (name == "retry-pause") {
            cfg.retryPauseSeconds = std::stoi(value);
        } else if (name == "quiet") {
            cfg.quiet = (value == "true" || value == "1");
        } else if (name == "protocol-dump" || name == "protocol") {
            cfg.protocolDump = (value == "true" || value == "1");
        } else if (name == "debug") {
            cfg.debug = (value == "true" || value == "1");
        } else if (name == "tls-verify") {
            cfg.tlsVerify = (value == "true" || value == "1");
        } else if (name == "tls-pin") {
            cfg.tlsPin = value;
        } else if (name == "sha256-backend") {
            cfg.sha256Backend = value;
        } else if (name == "lyra-backend") {
            cfg.lyraBackend = value;
        } else if (name == "hashrate-interval") {
            cfg.hashrateIntervalSeconds = std::stoi(value);
        } else if (name == "randomx-full-mem") {
            cfg.randomxFullMemory = (value == "true" || value == "1");
        } else if (name == "randomx-large-pages") {
            cfg.randomxLargePages = (value == "true" || value == "1");
        } else if (name == "benchmark") {
            cfg.benchmark = (value == "true" || value == "1");
        } else if (name == "bench-seconds") {
            cfg.benchSeconds = std::stod(value);
        } else {
            error = "unknown option '" + name + "'";
            return false;
        }
    } catch (const std::exception&) {
        error = "invalid value for --" + name + ": '" + value + "'";
        return false;
    }
    return true;
}

bool loadConfigFile(const std::string& path, Config& cfg, std::string& error)
{
    std::ifstream in(path);
    if (!in) {
        error = "cannot open config file '" + path + "'";
        return false;
    }
    nlohmann::json j;
    try {
        in >> j;
    } catch (const std::exception& e) {
        error = std::string("invalid JSON in '") + path + "': " + e.what();
        return false;
    }
    if (!j.is_object()) {
        error = "config file '" + path + "' must contain a JSON object";
        return false;
    }
    for (auto it = j.begin(); it != j.end(); ++it) {
        if (!it.key().empty() && it.key()[0] == '_')
            continue; // "_comment"-style keys, same convention as example-cfg.json
        std::string value;
        if (it->is_string())
            value = it->get<std::string>();
        else if (it->is_boolean())
            value = it->get<bool>() ? "true" : "false";
        else if (it->is_number_integer())
            value = std::to_string(it->get<long long>());
        else if (it->is_number_float())
            value = std::to_string(it->get<double>());
        else
            continue;
        if (!applyOption(cfg, it.key(), value, error))
            return false;
    }
    return true;
}

} // namespace

bool Config::parse(int argc, char** argv, Config& out, int& exitCode)
{
    exitCode = 0;

    // Pass 1: apply a config file first (wherever -c appears in argv) so
    // plain CLI flags below always take precedence over it.
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        std::string path;
        if (arg == "-c" || arg == "--config") {
            if (i + 1 >= argc) {
                std::cerr << "cppminer: --config requires a file path\n";
                exitCode = 1;
                return false;
            }
            path = argv[i + 1];
        } else if (arg.rfind("--config=", 0) == 0) {
            path = arg.substr(9);
        } else {
            continue;
        }
        std::string error;
        if (!loadConfigFile(path, out, error)) {
            std::cerr << "cppminer: " << error << "\n";
            exitCode = 1;
            return false;
        }
    }

    // Pass 2: CLI flags, overriding whatever the config file set.
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            std::cout << kUsage;
            return false;
        }
        if (arg == "-V" || arg == "--version") {
            std::cout << kVersion << "\n";
            return false;
        }
        if (arg == "-c" || arg == "--config") { i++; continue; } // handled in pass 1
        if (arg.rfind("--config=", 0) == 0) continue;

        if (arg == "-q" || arg == "--quiet") { out.quiet = true; continue; }
        if (arg == "-P" || arg == "--protocol-dump") { out.protocolDump = true; continue; }
        if (arg == "-D" || arg == "--debug") { out.debug = true; continue; }
        if (arg == "--no-tls-verify") { out.tlsVerify = false; continue; }
        if (arg == "--benchmark") { out.benchmark = true; continue; }
        if (arg == "--randomx-full-mem") { out.randomxFullMemory = true; continue; }
        if (arg == "--randomx-light") { out.randomxFullMemory = false; continue; }
        if (arg == "--randomx-large-pages") { out.randomxLargePages = true; continue; }

        std::string name, value;
        bool needsValue = true;
        if (arg == "-o" || arg == "--url") name = "url";
        else if (arg == "-u" || arg == "--user") name = "user";
        else if (arg == "-p" || arg == "--pass") name = "pass";
        else if (arg == "-O" || arg == "--userpass") name = "userpass";
        else if (arg == "-a" || arg == "--algo") name = "algo";
        else if (arg == "-t" || arg == "--threads") name = "threads";
        else if (arg == "-r" || arg == "--retries") name = "retries";
        else if (arg == "-R" || arg == "--retry-pause") name = "retry-pause";
        else if (arg.rfind("--", 0) == 0 && arg.find('=') != std::string::npos) {
            auto eq = arg.find('=');
            name = arg.substr(2, eq - 2);
            value = arg.substr(eq + 1);
            needsValue = false;
        } else {
            std::cerr << "cppminer: unrecognized option '" << arg << "'\n";
            exitCode = 1;
            return false;
        }

        if (needsValue) {
            if (i + 1 >= argc) {
                std::cerr << "cppminer: option '" << arg << "' requires a value\n";
                exitCode = 1;
                return false;
            }
            value = argv[++i];
        }

        std::string error;
        if (!applyOption(out, name, value, error)) {
            std::cerr << "cppminer: " << error << "\n";
            exitCode = 1;
            return false;
        }
    }

    if (out.url.empty() && !out.benchmark) {
        std::cerr << "cppminer: missing -o/--url\n\n" << kUsage;
        exitCode = 1;
        return false;
    }
    if (out.threads <= 0) {
        unsigned hw = std::thread::hardware_concurrency();
        out.threads = hw > 0 ? static_cast<int>(hw) : 1;
    }
    return true;
}

} // namespace cppminer
