cmake_minimum_required(VERSION 3.20)

# Allow a plain `cmake -B build -S miner` to work without an explicit
# -DCMAKE_TOOLCHAIN_FILE, by falling back to VCPKG_ROOT or the local vcpkg
# checkout this project was set up against (nlohmann-json + curl).
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED ENV{VCPKG_ROOT} AND EXISTS "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
    elseif(EXISTS "C:/Users/Ruslan/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "C:/Users/Ruslan/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
    endif()
endif()

project(cppminer
    VERSION 0.1.0
    DESCRIPTION "Standalone C++ CPU miner (scrypt, sha256d, lyra2 webchain) built on nlohmann-json and libcurl"
    LANGUAGES C CXX ASM
)

option(CPPMINER_REQUIRE_CLANG "Require Clang for project builds" ON)
option(CPPMINER_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(CPPMINER_BUILD_FUZZING "Build libFuzzer targets" OFF)

if(CPPMINER_REQUIRE_CLANG)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang" OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "cppminer requires Clang C and C++ compilers; configure with clang-22/clang++-22")
    endif()
    if(CMAKE_C_COMPILER_VERSION VERSION_LESS 22 OR CMAKE_CXX_COMPILER_VERSION VERSION_LESS 22)
        message(FATAL_ERROR "cppminer requires Clang 22 or newer (found C=${CMAKE_C_COMPILER_VERSION}, CXX=${CMAKE_CXX_COMPILER_VERSION})")
    endif()
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(GNUInstallDirs)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

set(cppminer_sources
    src/main.cpp
    src/Config.cpp
    src/ConsoleInput.cpp
    src/Log.cpp
    src/ByteUtils.cpp
    src/Work.cpp
    src/MinerEngine.cpp
    src/Benchmark.cpp
    src/algo/Sha256.cpp
    src/algo/Scrypt.cpp
    src/algo/Lyra2Web.cpp
    src/algo/RandomX.cpp
    src/algo/lyra2/Lyra2.c
    src/algo/lyra2/Sponge.c
    src/simd/CpuFeatures.cpp
    src/simd/Sha256Scalar.cpp
    src/simd/Sha256ArmNeon.cpp
    src/simd/Sha256ArmCrypto.cpp
    src/simd/ScryptCoreScalar.cpp
    src/net/UrlUtils.cpp
    src/net/RawSocket.cpp
    src/net/StratumClient.cpp
    src/net/RandomXClient.cpp
    src/net/RandomXJobParser.cpp
    src/net/WebchainClient.cpp
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|i[3-6]86)$")
    list(APPEND cppminer_sources
        src/simd/Sha256Sse2.cpp
        src/simd/Sha256Avx2.cpp
        src/simd/Sha256Avx512.cpp
        src/simd/Sha256Shani.cpp
        src/simd/ScryptCoreSse2.cpp
        src/simd/ScryptCoreAvx2.cpp
        src/simd/ScryptCoreAvx512.cpp
        src/simd/Lyra2Sse2.cpp
        src/simd/Lyra2Avx2.cpp
        src/simd/Lyra2Avx512.cpp
    )
else()
    list(APPEND cppminer_sources
        src/simd/SimdFallback.cpp
        src/simd/Lyra2SimdFallback.cpp
    )
endif()

add_library(randomx STATIC
    src/algo/randomx/aes_hash.cpp
    src/algo/randomx/argon2_ref.c
    src/simd/randomx/argon2_ssse3.c
    src/simd/randomx/argon2_avx2.c
    src/algo/randomx/bytecode_machine.cpp
    src/algo/randomx/cpu.cpp
    src/algo/randomx/dataset.cpp
    src/algo/randomx/soft_aes.cpp
    src/algo/randomx/virtual_memory.c
    src/algo/randomx/vm_interpreted.cpp
    src/algo/randomx/allocator.cpp
    src/algo/randomx/assembly_generator_x86.cpp
    src/algo/randomx/instruction.cpp
    src/algo/randomx/randomx.cpp
    src/algo/randomx/superscalar.cpp
    src/algo/randomx/vm_compiled.cpp
    src/algo/randomx/vm_interpreted_light.cpp
    src/algo/randomx/argon2_core.c
    src/algo/randomx/blake2_generator.cpp
    src/algo/randomx/instructions_portable.cpp
    src/algo/randomx/reciprocal.c
    src/algo/randomx/virtual_machine.cpp
    src/algo/randomx/vm_compiled_light.cpp
    src/algo/randomx/blake2/blake2b.c
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|i[3-6]86)$")
    target_sources(randomx PRIVATE
        src/simd/randomx/jit_compiler_x86.cpp
        src/simd/randomx/jit_compiler_x86_static.S
    )
    set_source_files_properties(
        src/simd/randomx/jit_compiler_x86_static.S
        PROPERTIES LANGUAGE ASM
    )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    target_sources(randomx PRIVATE
        src/algo/randomx/jit_compiler_a64.cpp
        src/algo/randomx/jit_compiler_a64_static.S
    )
    # Keep preprocessed AArch64 assembly in ASM mode. Clang handles the .S
    # preprocessing pass itself; forcing C mode treats assembler comments as
    # invalid C preprocessor directives on macOS.
    set_source_files_properties(
        src/algo/randomx/jit_compiler_a64_static.S
        PROPERTIES LANGUAGE ASM
    )
endif()

target_include_directories(randomx PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/algo/randomx"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/simd/randomx"
)
set_property(TARGET randomx PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET randomx PROPERTY CXX_STANDARD 23)
set_property(TARGET randomx PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET randomx PROPERTY CXX_EXTENSIONS OFF)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|i[3-6]86)$")
    if(MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # clang-cl uses the MSVC ABI but still requires explicit feature flags
        # for Clang's AES, SSSE3, and AVX2 intrinsics.
        target_compile_options(randomx PRIVATE -clang:-maes)
        set_source_files_properties(
            src/simd/randomx/argon2_ssse3.c
            PROPERTIES COMPILE_OPTIONS "-clang:-mssse3"
        )
        set_source_files_properties(
            src/simd/randomx/argon2_avx2.c
            PROPERTIES COMPILE_OPTIONS "-clang:-mavx2"
        )
    elseif(NOT MSVC)
        target_compile_options(randomx PRIVATE -maes)
        set_source_files_properties(
            src/simd/randomx/argon2_ssse3.c
            PROPERTIES COMPILE_OPTIONS "-mssse3"
        )
        set_source_files_properties(
            src/simd/randomx/argon2_avx2.c
            PROPERTIES COMPILE_OPTIONS "-mavx2"
        )
    endif()
endif()

add_executable(cppminer ${cppminer_sources})

if(CPPMINER_ENABLE_SANITIZERS)
    target_compile_options(cppminer PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(cppminer PRIVATE -fsanitize=address,undefined)
endif()

target_include_directories(cppminer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

# The AVX2/AVX-512F SIMD backends and the SHA-NI backend use instruction
# sets beyond this project's compiler default, so each needs its own
# codegen flag - but only that one file; everything else, including the
# runtime dispatcher in simd/CpuFeatures.cpp, stays on the default
# baseline (SSE2 on x64) so the resulting binary still runs correctly
# (falling back to a slower backend) on CPUs without AVX2/AVX-512F/SHA.
# See simd/CpuFeatures.h. The ARM backends (Sha256ArmNeon.cpp,
# Sha256ArmCrypto.cpp) need no flags here: their entire body is guarded by
# `#if defined(__aarch64__)`, so on this project's actual x64 build they
# compile down to an empty translation unit.
if(MSVC)
    set_source_files_properties(
        src/simd/Sha256Avx2.cpp
        src/simd/ScryptCoreAvx2.cpp
        src/simd/Lyra2Avx2.cpp
        PROPERTIES COMPILE_OPTIONS "/arch:AVX2"
    )
    set_source_files_properties(
        src/simd/Lyra2Avx512.cpp
        PROPERTIES COMPILE_OPTIONS "/arch:AVX512"
    )
    set_source_files_properties(
        src/simd/Sha256Avx512.cpp
        src/simd/ScryptCoreAvx512.cpp
        PROPERTIES COMPILE_OPTIONS "/arch:AVX512"
    )
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # Unlike MSVC, clang-cl enforces the ISA requirements of the SHA-NI
        # and SSSE3/SSE4.1 intrinsics used by this translation unit.
        set_source_files_properties(
            src/simd/Sha256Shani.cpp
            PROPERTIES COMPILE_OPTIONS "-clang:-msse4.1;-clang:-mssse3;-clang:-msha"
        )
    endif()
else()
    set_source_files_properties(
        src/simd/Sha256Avx2.cpp
        src/simd/ScryptCoreAvx2.cpp
        src/simd/Lyra2Avx2.cpp
        PROPERTIES COMPILE_OPTIONS "-mavx2"
    )
    set_source_files_properties(
        src/simd/Lyra2Avx512.cpp
        PROPERTIES COMPILE_OPTIONS "-mavx512f"
    )
    set_source_files_properties(
        src/simd/Sha256Avx512.cpp
        src/simd/ScryptCoreAvx512.cpp
        PROPERTIES COMPILE_OPTIONS "-mavx512f"
    )
    set_source_files_properties(
        src/simd/Sha256Shani.cpp
        PROPERTIES COMPILE_OPTIONS "-msse4.1;-mssse3;-msha"
    )
endif()

target_link_libraries(cppminer PRIVATE
    CURL::libcurl
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    Threads::Threads
    randomx
)

if(APPLE)
    set_target_properties(cppminer PROPERTIES INSTALL_RPATH "@loader_path/../lib")
elseif(UNIX)
    set_target_properties(cppminer PROPERTIES INSTALL_RPATH "$ORIGIN/../lib")
endif()

if(WIN32)
    target_link_libraries(cppminer PRIVATE ws2_32)
    target_compile_definitions(cppminer PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

if(CPPMINER_BUILD_FUZZING)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "libFuzzer target requires Clang")
    endif()
    add_executable(randomx_job_fuzz
        tests/fuzz/RandomXJobFuzz.cpp
        src/net/RandomXJobParser.cpp
        src/ByteUtils.cpp
    )
    target_include_directories(randomx_job_fuzz PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_compile_options(randomx_job_fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(randomx_job_fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined
    )

    set(multi_algo_fuzz_sources
        tests/fuzz/MultiAlgoFuzz.cpp
        src/net/RandomXJobParser.cpp
        src/ByteUtils.cpp
        src/algo/Sha256.cpp
        src/algo/Scrypt.cpp
        src/algo/Lyra2Web.cpp
        src/algo/lyra2/Lyra2.c
        src/algo/lyra2/Sponge.c
        src/simd/CpuFeatures.cpp
        src/simd/Sha256Scalar.cpp
        src/simd/ScryptCoreScalar.cpp
    )
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|i[3-6]86)$")
        list(APPEND multi_algo_fuzz_sources
            src/simd/Sha256Sse2.cpp
            src/simd/Sha256Avx2.cpp
            src/simd/Sha256Avx512.cpp
            src/simd/Sha256Shani.cpp
            src/simd/ScryptCoreSse2.cpp
            src/simd/ScryptCoreAvx2.cpp
            src/simd/ScryptCoreAvx512.cpp
            src/simd/Lyra2Sse2.cpp
            src/simd/Lyra2Avx2.cpp
            src/simd/Lyra2Avx512.cpp
        )
        set_source_files_properties(
            src/simd/Sha256Avx2.cpp src/simd/ScryptCoreAvx2.cpp src/simd/Lyra2Avx2.cpp
            PROPERTIES COMPILE_OPTIONS "-mavx2"
        )
        set_source_files_properties(
            src/simd/Sha256Avx512.cpp src/simd/ScryptCoreAvx512.cpp src/simd/Lyra2Avx512.cpp
            PROPERTIES COMPILE_OPTIONS "-mavx512f"
        )
        set_source_files_properties(
            src/simd/Sha256Shani.cpp
            PROPERTIES COMPILE_OPTIONS "-msse4.1;-mssse3;-msha"
        )
    else()
        list(APPEND multi_algo_fuzz_sources src/simd/SimdFallback.cpp src/simd/Lyra2SimdFallback.cpp)
    endif()
    add_executable(multi_algo_fuzz ${multi_algo_fuzz_sources})
    target_include_directories(multi_algo_fuzz PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_compile_options(multi_algo_fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(multi_algo_fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined
    )
    target_link_libraries(multi_algo_fuzz PRIVATE
        OpenSSL::Crypto
        Threads::Threads
    )
endif()

install(TARGETS cppminer RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DOCDIR}")
