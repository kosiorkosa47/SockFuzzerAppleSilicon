# SockFuzzer — Apple Silicon Edition

> **Based on the original [SockFuzzer](https://github.com/googleprojectzero/SockFuzzer)
> by Ned Williamson (Google Project Zero).**
>
> This fork builds on the **original CMake/libFuzzer architecture** (pre-v3) and extends
> it with Apple Silicon support, hardened kernel stubs, expanded attack surface coverage,
> and a modern CI pipeline. The upstream project has since moved to a different architecture
> (Bazel + Centipede); this fork intentionally stays on the proven CMake + libFuzzer +
> libprotobuf-mutator stack for portability and simplicity.

## What is SockFuzzer?

SockFuzzer is a structure-aware fuzzer for Apple's XNU kernel network stack.
It compiles the **real XNU BSD networking code** into a userland library, links it
with lightweight stubs for kernel subsystems it doesn't need, and drives it
through [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator)
and [libFuzzer](https://llvm.org/docs/LibFuzzer.html). This lets you fuzz
socket syscalls, packet parsing, and ioctl handling on macOS and Linux without
a VM or kernel debug setup.

## What's different in this fork

| Area | Original (pre-v3) | This fork |
|---|---|---|
| **Platform** | x86-64 Linux only | Apple Silicon (arm64) native + Linux |
| **copyin/copyout** | Raw pointer casts, magic values | Named constants, null guards, ASAN validation |
| **Kernel time** | All time functions return 0 | Progressive counter (+100us/call) for timer code paths |
| **NECP subsystem** | 5 operations disabled | All 5 enabled (match_policy, open, client_action, session_open, session_action) |
| **State reset** | Timers only | + mbuf page pool reset via `kmem_mb_reset_pages()` |
| **Stub debugging** | Silent `assert(false)` | `STUB_ABORT` prints function name before crashing |
| **FuzzedDataProvider** | Missing null guards | `get_fuzzed_int32`/`get_fuzzed_uint32` null-safe |
| **ntohl/ntohs** | Functions in header (ODR violation) | `static inline` |
| **Build system** | CMake (basic) | CMake modernized, Homebrew LLVM, `nmedit` symbol hiding |
| **CI** | None | GitHub Actions: macOS-14 + Ubuntu, smoke test |
| **Tests** | None for stubs | 8 unit tests for copyin/copyout/zalloc |
| **Dependencies** | Old protobuf | protobuf v4+, abseil-cpp, fuzztest as submodules |

## Building

### Prerequisites

**Clone with submodules:**

```bash
git clone --recursive https://github.com/kosiorkosa47/SockFuzzerAppleSillicon.git
cd SockFuzzerAppleSillicon
```

### macOS (Apple Silicon)

Tested on macOS 15.3.1, Apple M3 Pro.

```bash
brew install cmake protobuf abseil llvm
```

Apple's Xcode Clang does not ship with libFuzzer, so we use the Homebrew LLVM
toolchain which includes it.

```bash
mkdir build && cd build
cmake .. -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang \
         -DCMAKE_CXX_COMPILER=$(brew --prefix llvm)/bin/clang++
make -j$(sysctl -n hw.ncpu)
```

### Linux (Debian / Ubuntu)

A Dockerfile is included which shows how to prepare a Debian environment.

```bash
mkdir build && cd build
CC=clang CXX=clang++ cmake -GNinja ..
ninja
```

### Docker

```bash
docker build --pull -t sockfuzzer-builder .
docker run -t -i -v $PWD:/source sockfuzzer-builder /bin/bash
# Inside the container:
cd /source && mkdir -p build && cd build
CC=clang CXX=clang++ cmake -GNinja .. && ninja
```

## Running the Fuzzer

```bash
mkdir -p corpus crashes
ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0 \
  ./net_fuzzer corpus/ -artifact_prefix=crashes/ -max_total_time=3600
```

> **ASAN options explained:**
> - `detect_container_overflow=0` — XNU uses fixed-size C arrays inside structs
>   that trigger false-positive container-overflow reports.
> - `halt_on_error=0` — continue past non-fatal ASAN warnings to collect
>   multiple crash artifacts in a single run.

See the [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html) for all
available flags (`-jobs`, `-workers`, `-max_len`, etc.).

## Architecture

```
                    protobuf input (Session)
                            |
                    net_fuzzer.cc (C++)
                   /        |        \
          syscall_wrappers  |   packet injection
          (socket, bind,    |   (ip_input, ip6_input)
           connect, ...)    |
                    \       |       /
                     libxnu (real XNU BSD code)
                    /       |       \
              fakes/     zalloc.c   mbuf.c
           (fake_impls,  (zones →   (mbuf creation,
            stubs,        malloc)    refcount mgmt)
            osfmk_stubs)
```

**Key design decisions:**
- XNU symbols are localized via `nmedit -s` (macOS) or `objcopy --localize-hidden`
  (Linux) to prevent collisions with libc
- `fuzz/include/` overrides XNU headers that contain x86 assembly or kernel-only
  constructs (proc_reg.h, cpu_data.h, startup.h)
- All lock operations are no-ops (single-threaded fuzzing model)
- Zone allocations fall back to `malloc`/`calloc` with ASAN instrumentation

## Extending the Fuzzer

1. **Add a new syscall:** Create wrapper in `syscall_wrappers.c`, add proto
   message to `net_fuzzer.proto`, add handler case in `net_fuzzer.cc`, export
   symbol in `cmake/xnu_exported_symbols.txt`
2. **Add a new packet type:** Define proto message, implement builder function,
   add to `Packet` oneof and `DoIpInput()` switch
3. **Add a new ioctl:** Add to `IoctlReal` oneof with structured message,
   implement handler in `HandleIoctlReal()`

## Coverage Reports

On Linux, a `net_cov` binary is built with LLVM source-based coverage:

```bash
./net_cov corpus
llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov show -format=html -output-dir=report -instr-profile=default.profdata net_cov
```

## Importing Upstream XNU Releases

A macOS environment is needed to generate new headers. Unpack the new XNU source
tarball into `third_party/xnu`, then:

```bash
# From inside third_party/xnu
make SDKROOT=macosx11.1 ARCH_CONFIGS=X86_64 KERNEL_CONFIGS=DEBUG
git add BUILD/obj/EXPORT_HDRS EXTERNAL_HEADERS
```

Update `CMakeLists.txt` if source paths changed.

## Roadmap

See the [milestones](https://github.com/kosiorkosa47/SockFuzzerAppleSillicon/milestones)
and [open issues](https://github.com/kosiorkosa47/SockFuzzerAppleSillicon/issues)
for planned improvements including:

- Expanded protobuf grammar (IPv6 extension headers, PF firewall, MPTCP)
- Realistic kernel stubs (crypto, permissions, threading)
- Comprehensive state reset between iterations
- Seed corpus and dictionary for faster bootstrap
- Fork-based snapshot isolation
- Automatic crash-to-PoC translation

## License

This project inherits the [Apple Public Source License 2.0](LICENSE) from the
XNU kernel sources and the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
from the original SockFuzzer project by Google.

This is not an official Google product.
