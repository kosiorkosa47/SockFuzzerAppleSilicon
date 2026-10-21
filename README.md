# SockFuzzer — Apple Silicon Edition

> **Based on the original [SockFuzzer](https://github.com/googleprojectzero/SockFuzzer)
> by Ned Williamson (Google Project Zero).**
>
> This fork builds on the **original CMake/libFuzzer architecture** (pre-v3) and extends
> it with Apple Silicon support, hardened kernel stubs, expanded attack surface coverage,
> and production-grade tooling. The upstream project has since moved to Bazel + Centipede;
> this fork stays on the proven CMake + libFuzzer + libprotobuf-mutator stack.

## What is SockFuzzer?

SockFuzzer compiles the **real XNU BSD networking code** into a userland library and
drives it with [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator)
and [libFuzzer](https://llvm.org/docs/LibFuzzer.html). This lets you fuzz socket
syscalls, packet parsing, and ioctl handling on macOS and Linux — no VM, no kernel
debug setup, no jailbreak needed.

## Architecture

```mermaid
graph TD
    A["Protobuf Input<br/>(Session message)"] --> B["net_fuzzer.cc<br/>Command Dispatcher"]

    B --> C["Syscall Wrappers<br/>socket, bind, connect,<br/>setsockopt, ioctl, kevent64"]
    B --> D["Packet Injection<br/>ip_input, ip6_input"]
    B --> E["State Operations<br/>TcpSession, ContentFilter,<br/>FlowDivert, kqueue"]

    C --> F["libxnu<br/>(Real XNU BSD Code)"]
    D --> F
    E --> F

    F --> G["Zone Allocator<br/>UAF / double-free /<br/>zone confusion tracking"]
    F --> H["Fake Impls<br/>copyin/copyout, time,<br/>crypto, permissions"]
    F --> I["mbuf Subsystem<br/>Chained mbufs,<br/>split-point fuzzing"]

    G --> J["ASAN<br/>+ quarantine poisoning"]
    H --> J
    I --> J

    J --> K{"Crash?"}
    K -- Yes --> L["crashes/ directory<br/>+ crash_pipeline.sh"]
    K -- No --> M["Corpus grows<br/>coverage feedback"]

    style A fill:#4a9eff,color:#fff
    style F fill:#ff6b6b,color:#fff
    style J fill:#ffa726,color:#fff
    style K fill:#66bb6a,color:#fff
```

## In Action

**Build (macOS Apple Silicon):**

![Build](docs/screenshots/build.png)

**Fuzzer startup — loading corpus and discovering new coverage:**

![Fuzzer Startup](docs/screenshots/fuzzer_startup.png)

**24/7 campaign — 8.5M+ executions, corpus optimization:**

![Fuzzer Campaign](docs/screenshots/fuzzer_campaign.png)

## What's different in this fork

| Area | Original (pre-v3) | This fork |
|---|---|---|
| **Platform** | x86-64 Linux only | **Apple Silicon (arm64) native + Linux** |
| **Stubs** | ~350 `assert(false)` traps | **Zero trapping stubs** — all safe no-ops or real impls |
| **Zone allocator** | Simple malloc/free | **UAF, double-free, zone confusion detection** with ASAN quarantine |
| **copyin/copyout** | Raw pointer casts | Named constants, null guards, EFAULT simulation |
| **Kernel time** | Returns 0 | Progressive counter (+100us/call) |
| **Permissions** | Always root | **Fuzzed** — kauth_cred_issuser, priv_check_cred return random |
| **Crypto** | Missing | Fuzzed digests (SHA1/MD5), AES key copy |
| **Byte order** | Host order | **Network byte order** on all wire-format fields |
| **Socket options** | Flat enum | **Per-level enums** (SOL_SOCKET, TCP, IP, IPv6) |
| **Packet types** | TCP/UDP/ICMP | + **IPv6 ext headers, MPTCP, PF firewall, NECP** |
| **kqueue** | Not supported | **kevent64 syscall** fully wired |
| **CI** | None | **GitHub Actions** — macOS + Linux, smoke test, coverage |
| **Scripts** | None | 11 scripts — crash pipeline, triage, coverage, PoC generator |
| **Tests** | None | **5 CVE regression tests** + stub unit tests |
| **Commits** | — | **112+ commits** of improvements |

## Building

### macOS (Apple Silicon)

Tested on macOS 15.x, Apple M3 Pro.

```bash
git clone --recursive https://github.com/kosiorkosa47/SockFuzzerAppleSilicon.git
cd SockFuzzerAppleSilicon
brew install cmake protobuf abseil llvm

mkdir build && cd build
cmake .. -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang \
         -DCMAKE_CXX_COMPILER=$(brew --prefix llvm)/bin/clang++
make -j$(sysctl -n hw.ncpu)
```

Apple's Xcode Clang does not ship with libFuzzer — Homebrew LLVM is required.

If even a trivial program fails to link with `tapi error: malformed file ...
unknown architecture arm64e.x1`, the Command Line Tools SDK is newer than the
`ld` from the selected Xcode. Point the toolchain at the Command Line Tools for
the build, or switch permanently with
`sudo xcode-select -s /Library/Developer/CommandLineTools`:

```bash
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
```

### Unit tests

```bash
cmake .. -DBUILD_TESTS=ON   # plus the compiler flags above
cmake --build . && ctest --output-on-failure
```

### Linux (Debian / Ubuntu)

```bash
apt-get install -y clang llvm cmake ninja-build protobuf-compiler libprotobuf-dev \
  libabsl-dev pkg-config
git clone --recursive https://github.com/kosiorkosa47/SockFuzzerAppleSilicon.git
cd SockFuzzerAppleSilicon

mkdir build && cd build
CC=clang CXX=clang++ cmake -GNinja ..
ninja
```

## Running

### Basic fuzzing

```bash
mkdir -p corpus crashes
ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0:detect_leaks=0 \
  ./net_fuzzer corpus/ -artifact_prefix=crashes/ -max_len=4096
```

### Continuous campaign (recommended)

```bash
./scripts/campaign.sh -j 8 campaign/          # until Ctrl-C
./scripts/campaign.sh -j 8 -t 86400 campaign/ # or for a day
```

A crash never ends the run: libFuzzer runs in fork mode with
`-ignore_crashes`, and new crash files are grouped by signature every few
minutes. `campaign/` keeps the corpus, raw crashes, `triage/` (one directory
per signature with a reproducer and report) and `fuzzer.log`, so the same
directory continues a campaign. Signatures listed in `campaign/known.txt` are
counted but no longer announced; it stays out of the repository so it can name
bugs that are not public yet.

`./scripts/triage.sh <crashes_dir>` groups any directory of crash files the
same way. A signature is the bug kind plus the first three frames that are not
sanitizer, libFuzzer or assertion plumbing.

### ASAN options explained

| Option | Why |
|---|---|
| `detect_container_overflow=0` | XNU uses fixed-size C arrays inside structs — false positives |
| `halt_on_error=0` | Continue past non-fatal ASAN warnings to find more bugs |
| `detect_leaks=0` | XNU intentionally "leaks" (kernel memory model) |

## Zone Tracking

The zone allocator (`fuzz/fakes/zalloc.c`) implements three classes of bug detection
beyond what standard ASAN provides:

```mermaid
graph LR
    A["zalloc()"] --> B["Hash Table<br/>8192 slots"]
    B --> C{"zfree()"}
    C -- "Already freed?" --> D["DOUBLE-FREE<br/>detected"]
    C -- "Wrong zone?" --> E["ZONE CONFUSION<br/>detected"]
    C -- "OK" --> F["Quarantine<br/>4096 ring buffer"]
    F --> G["ASAN poison<br/>freed memory"]
    G -- "Later access?" --> H["USE-AFTER-FREE<br/>ASAN report"]

    style D fill:#ff5252,color:#fff
    style E fill:#ff5252,color:#fff
    style H fill:#ff5252,color:#fff
```

- **UAF detection**: Freed allocations enter a quarantine ring buffer. Memory is
  ASAN-poisoned — any access triggers an immediate ASAN report.
- **Double-free detection**: Each allocation has a `freed` flag. Freeing twice
  aborts at the second free, so the crash file and stack point at it.
- **Zone confusion**: `zfree()` validates that the pointer is returned to the
  same zone it was allocated from, and aborts on a mismatch.

XNU assertions, panics and zone bugs all write to stderr and abort, so
libFuzzer saves the input like any other crash.

Overhead: ~35% exec/sec — acceptable tradeoff for catching bugs worth $100K+.

## Attack Surface

| Subsystem | Source | Status |
|---|---|---|
| TCP (v4/v6) | tcp_input, tcp_output, tcp_subr, tcp_timer | Active. The loopback handshake completes over IPv4 and IPv6 (`::1` is configured on lo0), so states that need an accepted child socket are reachable in both families |
| UDP (v4/v6) | udp_usrreq, udp6_usrreq, udp6_output | Active |
| ICMP (v4/v6) | ip_icmp, icmp6 | Active |
| IPv6 ext headers | frag6, dest6, route6 | Active |
| PF firewall | pf, pf_ioctl, pf_norm, pf_table | Active. Reaches `pfioctl` through a narrow bridge with the real `pfioc_rule` and `pfioc_state_kill` structures. Previously every PF ioctl went through a socket descriptor and never reached PF at all |
| NECP | necp, necp_client | Active — all 5 operations |
| MPTCP | mptcp, mptcp_opt, mptcp_subr | Active |
| Socket lifecycle | uipc_socket, uipc_socket2, uipc_syscalls | Active |
| UNIX domain | uipc_usrreq | Active |
| Pipes | sys_pipe | Active |
| kqueue | kern_event (kevent64) | Active |
| Content filter | content_filter | Active — cfil gate enabled |
| Flow divert | flow_divert | Partial |
| IPsec | ipsec, esp_*, ah_* | Partial — crypto stubs |

## Performance

Measured on Apple M3 Pro, 24/7 campaign:

| Metric | Value |
|---|---|
| Exec/sec (without zone tracking) | ~6,800 |
| Exec/sec (with zone tracking) | ~5,200 |
| Edge coverage | 9,100+ |
| Feature coverage | 44,700+ |
| Corpus | ~4,700 files |

### Reproducible cold start

Campaign figures depend on how long the corpus has been growing, so they cannot
be compared against each other. This one starts from an empty directory and is
the same command every time:

```bash
mkdir -p /tmp/cold && ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0:detect_leaks=0 \
  ./net_fuzzer /tmp/cold -runs=4000 -max_len=4096
```

| Metric | Value |
|---|---|
| Edge coverage | 7,100 to 7,800 |
| Feature coverage | 15,700 to 17,900 |

The range is the spread across three separate runs, not a margin of error. For
reference, the same measurement returned 1,754 edges before the harness and
grammar fixes described in ROADMAP.md.

> **Corpus note:** `InAddr` and `Port` changed from protobuf enums to messages,
> which changes their wire type. Corpus entries recorded before that change still
> load, but no longer parse those two fields.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/crash_pipeline.sh` | Minimize, triage, generate PoC, prepare Apple report |
| `scripts/campaign.sh` | Continuous fork-mode campaign with periodic triage |
| `scripts/triage.sh` | Group crashes by kind and top meaningful frames |
| `scripts/coverage_report.sh` | Per-input XNU coverage of a corpus, with a per-subsystem table |
| `scripts/coverage_analysis.sh` | Uncovered functions and corpus minimization |
| `scripts/benchmark.sh` | Measure exec/sec and coverage metrics |
| `scripts/minimize.sh` | Corpus minimization |
| `scripts/reproduce.sh` | Reproduce a specific crash |
| `scripts/poc_generator.py` | Crash to kernel PoC C code |
| `scripts/frida_verify.py` | Generate Frida script for on-device crash replay |
| `scripts/ai_corpus_guide.py` | Coverage gap analysis with proto command mapping |
| `scripts/generate_seeds.sh` | Generate seed corpus from proto definitions |
| `scripts/diff_fuzz.sh` | Patch-diff targeted fuzzing |

## CVE Regression Tests

The `tests/regression/` directory contains reproducer inputs for known XNU CVEs:

| CVE | Component | Bug Class |
|---|---|---|
| CVE-2019-8605 | Socket (SockPuppet) | Use-after-free |
| CVE-2020-3911 | mDNSResponder | Buffer overflow |
| CVE-2020-9839 | IOKit | Race condition |
| CVE-2021-1782 | Mach vouchers | Type confusion |
| CVE-2022-32893 | WebKit (via net) | OOB write |

## Coverage

Line coverage of the XNU sources over the committed seed set
(`corpus/seeds/`, 1086 inputs), measured with `net_cov`:

| Area | Lines covered | Line % |
|---|---|---|
| bsd/netinet | 12400/50315 | 24.6% |
| bsd/netinet6 | 5220/38843 | 13.4% |
| bsd/net | 9982/82477 | 12.1% |
| bsd/kern | 7330/38087 | 19.2% |
| All instrumented code | 45580/312044 | 14.6% |

CI recomputes this table on every push to main and shows it in the macOS
job summary, with the HTML report as the `coverage-report-macos` artifact.
To reproduce locally:

```bash
./scripts/coverage_report.sh corpus/seeds build/net_cov coverage_report
open coverage_report/html/index.html
```

Each input runs in its own process. In one process, state from earlier
inputs can make a later one abort, and an abort loses the whole profile.

## Extending

1. **New syscall**: wrapper in `syscall_wrappers.c` + proto message + handler in
   `net_fuzzer.cc` + export in `cmake/xnu_exported_symbols.txt`
2. **New packet type**: proto message + builder function + add to `Packet` oneof
3. **New ioctl**: add to `IoctlReal` oneof + handler in `HandleIoctlReal()`
4. **New socket option**: add enum value to per-level `SolSocketOpt`/`TcpOpt`/`IpOpt`/`Ipv6Opt`

## Importing Upstream XNU

A macOS environment is needed to generate new headers:

```bash
# From inside third_party/xnu
make SDKROOT=macosx ARCH_CONFIGS=ARM64 KERNEL_CONFIGS=DEBUG
git add BUILD/obj/EXPORT_HDRS EXTERNAL_HEADERS
```

Update `CMakeLists.txt` if source paths changed.

## Bugs Found

This fuzzer is actively used for XNU kernel security research. Any findings
will be reported to Apple through their [Security Bounty](https://security.apple.com/bounty/)
program and listed here after responsible disclosure periods expire.

## License

This project inherits the [Apple Public Source License 2.0](LICENSE) from the
XNU kernel sources and the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
from the original SockFuzzer project by Google.

This is not an official Google product.
