# cppminer

Standalone C++ CPU miner for **scrypt**, **SHA-256d (double SHA-256)**, **Lyra2 Webchain (lyra2web)**, and **RandomX**. It connects to Stratum or pool-specific JSON-RPC endpoints, picks the fastest SIMD backend available on your CPU at runtime, and runs a reference-vector self-test before mining.

Built with **C++23**, **Clang 22+**, **CMake**, **libcurl**, **OpenSSL**, and **nlohmann/json**. RandomX is embedded from upstream sources with platform-specific JIT support (x86-64 and AArch64).

## Features

- Four mining algorithms behind one binary (`-a` / `--algo`)
- Runtime CPU feature detection and SIMD dispatch (SSE2, AVX2, AVX-512, SHA-NI where applicable)
- RandomX: JIT, hardware AES, Argon2 SSSE3/AVX2, optional full dataset and large pages
- Stratum client for scrypt / SHA-256d; dedicated clients for Lyra2 Webchain and RandomX pools
- TLS verification and optional public-key pinning
- Offline `--benchmark` mode with per-backend SIMD comparison
- JSON config file support (`-c` / `--config`)
- Cross-platform CI: Linux, Windows, macOS (ARM64)

## Supported algorithms

| Algorithm | Pool protocol | Notes |
|-----------|---------------|-------|
| `scrypt` (default) | Stratum | Optional cost factor: `scrypt:1024`, `scrypt:2048`, … |
| `sha256d` | Stratum | Bitcoin-style 80-byte block header |
| `lyra2web` | Webchain JSON-RPC | MintMe Webchain; opaque job blob + 8-byte nonce |
| `randomx` | RandomX JSON-RPC | Monero-style blob; light (~256 MiB) or full (~2 GiB) dataset |

On startup the miner prints detected CPU features and runs algorithm-specific self-tests. Mining does not start if a self-test fails.

## Requirements

### Toolchain

- **Clang 22 or newer** (C, C++, and assembler)
- **CMake 3.20+**
- **Ninja** (recommended)

### Libraries

| Platform | Packages |
|----------|----------|
| **Linux** | `cmake`, `ninja-build`, `libcurl4-openssl-dev`, `libssl-dev`, `nlohmann-json3-dev` |
| **macOS** | `cmake`, `ninja`, `nlohmann-json`, `openssl@3` (Homebrew); LLVM 22 from Homebrew for CI parity |
| **Windows** | Visual Studio build tools, [vcpkg](https://vcpkg.io/) with `curl`, `nlohmann-json`, `openssl` (`x64-windows`) |

### RandomX memory

| Mode | Approx. RAM | Flag |
|------|-------------|------|
| Full dataset (default) | ~2 GiB shared + per-thread VM | `--randomx-full-mem` |
| Light mode | ~256 MiB shared | `--randomx-light` |

Use `--randomx-large-pages` when your OS account can lock large pages (improves RandomX performance).

## Building

### Linux / macOS

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++

cmake --build build --parallel
```

The binary is `build/cppminer`.

On macOS, if the default `clang` is too old, use Homebrew LLVM 22:

```bash
export CC="$(brew --prefix llvm@22)/bin/clang"
export CXX="$(brew --prefix llvm@22)/bin/clang++"
```

### Windows (clang-cl + vcpkg)

From a **x64 Native Tools** / VS Developer shell:

```powershell
cmake -S . -B build -G Ninja `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_ASM_COMPILER=clang-cl `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows `
  -DCMAKE_BUILD_TYPE=Release

cmake --build build --parallel
```

The binary is `build\cppminer.exe`. vcpkg runtime DLLs are copied next to the executable by CMake on Windows.

### Install (optional)

```bash
cmake --install build --prefix ./staging
```

Use `scripts/run-cppminer.sh` (Unix) or `scripts/run-cppminer.cmd` (Windows) from the install prefix so bundled libraries are found automatically.

## Quick start

### Stratum (scrypt or SHA-256d)

```bash
./build/cppminer \
  -o stratum+tcp://pool.example.com:3333 \
  -u YOUR_WALLET_OR_WORKER \
  -p x \
  -a scrypt \
  -t 4
```

```bash
./build/cppminer \
  -o stratum+tcp://pool.example.com:3333 \
  -u worker \
  -p x \
  -a sha256d
```

### Lyra2 Webchain

```bash
./build/cppminer \
  -o pool.example.com:8080 \
  -u YOUR_ADDRESS \
  -p x \
  -a lyra2web
```

### RandomX

```bash
./build/cppminer \
  -o pool.example.com:443 \
  -u YOUR_ADDRESS \
  -p x \
  -a randomx \
  --randomx-light
```

Omit `--randomx-light` on machines with enough RAM for the faster full-dataset mode (default).

## Offline benchmark

Benchmark all algorithms (no pool connection):

```bash
./build/cppminer --benchmark --bench-seconds=3
```

Benchmark a single algorithm:

```bash
./build/cppminer --benchmark -a randomx --bench-seconds=0.5 --randomx-light
```

The benchmark runs self-tests, compares SIMD backends where applicable (e.g. Argon2 scalar/SSSE3/AVX2 for RandomX, SHA-NI/AVX2 for SHA-256d), then reports a multi-threaded hashrate sample.

## Configuration file

Options can be loaded from JSON. Keys match long option names (without `--`). CLI flags override the file.

```json
{
  "_comment": "Keys starting with _ are ignored",
  "url": "stratum+tcp://pool.example.com:3333",
  "user": "worker",
  "pass": "x",
  "algo": "scrypt",
  "threads": 8,
  "sha256-backend": "auto",
  "randomx-light": true,
  "quiet": false
}
```

```bash
./build/cppminer -c miner.json
```

## Command-line options

```
Usage: cppminer -o URL -u USER -p PASS [options]

  -o, --url=URL          Stratum or pool URL
  -u, --user=USERNAME    Pool username / worker name
  -p, --pass=PASSWORD    Pool password
  -O, --userpass=U:P     username:password combined
  -a, --algo=ALGO        scrypt, scrypt:N, sha256d, lyra2web, randomx
  -t, --threads=N        Miner threads (default: CPU count)
  -r, --retries=N        Connect retries, -1 = infinite (default)
  -R, --retry-pause=N    Seconds between retries (default: 30)
  -c, --config=FILE      JSON config file
  -q, --quiet            Disable per-thread hashrate logging
  -P, --protocol-dump    Verbose protocol dump
  -D, --debug            Debug logging
  --no-tls-verify        Disable TLS certificate verification
  --tls-pin=KEY          Pin libcurl public key (sha256//… or file)
  --sha256-backend=NAME  auto, scalar, sse2, avx2, avx512, sha-ni
  --randomx-full-mem     Full RandomX dataset (~2 GiB, default)
  --randomx-light        Light RandomX mode (~256 MiB)
  --randomx-large-pages  Request large pages for RandomX
  --benchmark            Offline SIMD/hashrate benchmark
  --bench-seconds=N      Seconds per benchmark stage (default: 3)
  -V, --version          Show version
  -h, --help             Show help
```

## Environment variables

| Variable | Effect |
|----------|--------|
| `CPPMINER_RANDOMX_PIPELINE` | Set to `0` to disable the 2-way RandomX hash pipeline (default: enabled) |
| `CPPMINER_LYRA_BACKEND` | Force Lyra2 backend: `auto`, `scalar`, `sse2`, `avx2`, or `avx512` |

## SIMD backends

At startup the miner logs detected CPU features, for example:

```
CPU features: SSE2 SSSE3 SSE4.1 AVX AVX2 SHA
sha256d backend: SHA-NI
```

Each algorithm selects the best safe backend for your CPU and falls back to scalar code on older hardware. Per-backend rates are visible in `--benchmark` output.

## Project layout

```
src/
  algo/          Hash algorithms (Sha256, Scrypt, Lyra2Web, RandomX)
  net/           Stratum, Webchain, and RandomX pool clients
  simd/          CPU feature detection and SIMD implementations
  MinerEngine.*  Thread orchestration and work distribution
tests/fuzz/      libFuzzer targets (optional build)
```

## Development

Optional CMake flags:

| Flag | Purpose |
|------|---------|
| `CPPMINER_ENABLE_SANITIZERS=ON` | AddressSanitizer + UBSan |
| `CPPMINER_BUILD_FUZZING=ON` | Build fuzz targets (Clang only) |
| `CPPMINER_REQUIRE_CLANG=OFF` | Allow non-Clang compilers (not recommended) |

CI builds with Clang 22 on Linux, Windows, and macOS, runs algorithm smoke benchmarks, ASan/UBSan tests, and fuzzing on Linux.

## License

[MIT](LICENSE) — Copyright (c) 2026 Ruslan

RandomX sources retain their original BSD-style license in `src/algo/randomx/` and `src/simd/randomx/`.
