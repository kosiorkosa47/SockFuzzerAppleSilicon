# SockFuzzer Roadmap — Path to 11/10

Comprehensive issue tracker for bringing this XNU network stack fuzzer to
world-class quality. Every item has a concrete description, affected files,
and the rationale for why it matters.

**Current score: ~7.5/10** (solid P0-level fork with expanded attack surface).

---

## A. Bugs & Correctness (fix immediately)

### A1 — `current_thread()` returns NULL

| | |
|---|---|
| **File** | `fuzz/fakes/thread.c:36` |
| **Problem** | `return NULL` — XNU kernel code dereferences `current_thread()` in hundreds of places. NULL causes instant crash instead of coverage. |
| **Fix** | `return (thread_t)fake_thread;` |
| **Impact** | Unblocks dozens of code paths in scheduling, credential checks, thread-local storage. |

### A2 — `proc_pidversion` and `proc_limitgetcur` (non-NOFILE) crash

| | |
|---|---|
| **File** | `fuzz/fakes/fake_impls.c:604,614` |
| **Problem** | `assert(false)` on any `which` other than `RLIMIT_NOFILE`, and on `proc_pidversion`. Any code path that queries a different resource limit crashes the fuzzer. |
| **Fix** | `proc_limitgetcur` → return sensible defaults per `which` (RLIMIT_DATA=unlimited, etc.). `proc_pidversion` → return 1. |

### A3 — `timeout()` crashes instead of no-op

| | |
|---|---|
| **File** | `fuzz/fakes/fake_impls.c:155` |
| **Problem** | Kernel timer scheduling hits `assert(false)`. Blocks timer-driven code paths. |
| **Fix** | No-op. Timers are drained in `clear_all()` via `tcp_fuzzer_reset` etc. |

### A4 — Three clock functions are STUB_ABORT

| | |
|---|---|
| **File** | `fuzz/fakes/stubs.c:125,129,652` |
| **Problem** | `clock_get_calendar_microtime`, `clock_get_uptime`, `clock_get_system_microtime` — block timestamp-dependent paths despite progressive time being implemented elsewhere. |
| **Fix** | Use `g_fake_time_counter` from `fake_impls.c`. Export it or create a `fake_time_get()` helper. |

### A5 — `net_flowhash_mh3_x86_32` crashes

| | |
|---|---|
| **File** | `fuzz/fakes/stubs.c:672-676` |
| **Problem** | Flow hashing is critical for XNU packet distribution. `assert(false)` blocks multi-socket scenarios. |
| **Fix** | Implement FNV-1a hash or return fuzzed data via `get_fuzzed_uint32()`. |

### A6 — `net_flowhash` is STUB_ABORT

| | |
|---|---|
| **File** | `fuzz/fakes/stubs.c:689` |
| **Fix** | Wrapper around `net_flowhash_mh3_x86_32`. |

### A7 — `cc_clear` and `cc_cmp_safe` are STUB_ABORT

| | |
|---|---|
| **File** | `fuzz/fakes/stubs.c:678,680` |
| **Problem** | Constant-time crypto primitives — trivial to implement, block crypto paths. |
| **Fix** | `cc_clear` → `memset(dst, 0, len)`. `cc_cmp_safe` → `memcmp`. |

### A8 — AES stubs are inconsistent (split brain)

| | |
|---|---|
| **File** | `fuzz/fakes/fake_impls.c:468` vs `stubs.c:620-650` |
| **Problem** | `aes_encrypt_key128` is a no-op but `aes_encrypt_cbc`, `aes_decrypt_cbc` and 15 other AES functions are STUB_ABORTs. Init succeeds → operation crashes. |
| **Fix** | Either make all AES operations no-op (skip encryption, pass through plaintext) or make init return failure. |

### A9 — `san.c` crashes on unhandled access type

| | |
|---|---|
| **File** | `fuzz/fakes/san.c:57` |
| **Problem** | If XNU code uses an unknown access type, the fuzzer crashes on infrastructure instead of on a real bug. |
| **Fix** | `printf("Unhandled kasan access type %d\n", access); return;` |

### A10 — `enable_testing()` placement in CMake

| | |
|---|---|
| **File** | `CMakeLists.txt:783` |
| **Problem** | `enable_testing()` is after `add_test()` — CMake best practice requires the reverse order. |
| **Fix** | Move `enable_testing()` before `add_executable(fake_impls_test ...)`. |

---

## B. Fuzzing Effectiveness (new attack surface)

### B1 — TCP wire-format options

| | |
|---|---|
| **Files** | `fuzz/net_fuzzer.proto`, `fuzz/net_fuzzer.cc` |
| **Problem** | TCP options (SACK, timestamps, window scale, MSS, MPTCP) are not generated in packets. `th_off` is fuzzed but the payload after the TCP header is empty. TCP option parsing is manual pointer arithmetic in C — a classic source of off-by-one and overflow bugs. |
| **What to do** | Add `repeated TcpOption options = 12` to `TcpHdr`. Each `TcpOption` has `kind` and `data`. In the harness: serialize options after TCP header, set `th_off = (sizeof(tcphdr) + options_size) / 4`. |
| **Impact** | HUGE — TCP options are where many real CVEs have been found. |

### B2 — Mbuf chain fuzzing

| | |
|---|---|
| **Files** | `fuzz/fakes/mbuf.c`, `fuzz/api/backend.c`, `fuzz/net_fuzzer.proto` |
| **Problem** | All packets are single contiguous mbufs. Real kernel traffic uses multi-segment chains. `m_pullup`, `m_pulldown`, `m_copydata` have historically had bugs at mbuf boundaries. |
| **What to do** | Add `optional MbufLayout mbuf_layout` to `Packet` with `repeated uint32 segment_sizes`. In `get_mbuf_data`: if layout is set, split data across N mbufs and chain via `m_next`. |
| **Impact** | HUGE — enables discovery of a completely new bug class. |

### B3 — Structured PF ioctl data

| | |
|---|---|
| **Files** | `fuzz/net_fuzzer.proto`, `fuzz/net_fuzzer.cc` |
| **Problem** | 120 PF ioctls pass `(caddr_t)1` + random copyin. `pfioc_rule` is 1400+ bytes with nested `pf_rule`. Random bytes never pass validation. |
| **What to do** | Add `PfRule`, `PfIoctlAddRule`, `PfIoctlKillStates` etc. as proto messages. Add DIOCADDRULE, DIOCCHANGERULE, DIOCINSERTRULE, DIOCDELETERULE, DIOCKILLSTATES to `IoctlReal` oneof. |
| **Impact** | HIGH — PF has had CVE after CVE. Currently ~120 ioctls are effectively dead code. |

### B4 — kqueue/kevent syscall

| | |
|---|---|
| **Files** | `fuzz/api/syscall_wrappers.c`, `fuzz/net_fuzzer.proto`, `fuzz/net_fuzzer.cc` |
| **Problem** | Event notification is completely unfuzzed. This is how real apps (Safari, Mail) interact with sockets — EVFILT_READ, EVFILT_WRITE, EVFILT_SOCK. The XNU kqueue code (`kern_event.c`) is compiled but unreachable. |
| **What to do** | Add `kqueue_wrapper()` and `kevent_wrapper()`. Proto: `message Kevent { fd, filter, flags, fflags, data, udata }`. Command oneof: `kqueue` (creates kqueue fd) + `kevent` (registers/polls events). |
| **Impact** | HIGH — event-driven code path is entirely untested. |

### B5 — `sockaddr_ctl` (kernel control sockets)

| | |
|---|---|
| **Files** | `fuzz/types.h`, `fuzz/net_fuzzer.proto`, `fuzz/net_fuzzer.cc` |
| **Problem** | `AF_SYSTEM` + `SYSPROTO_CONTROL` opens kernel control sockets. content_filter, flow_divert, netagent — all use this. Major attack surface on iOS. |
| **What to do** | Add `SockAddrCtl` message with `sc_id` and `sc_unit`. Add to `SockAddr` oneof. |
| **Impact** | MEDIUM-HIGH — kernel control sockets are a privileged iOS attack surface. |

### B6 — Dual-interface: fake Ethernet interface

| | |
|---|---|
| **Files** | `fuzz/api/backend.c` |
| **Problem** | All packets arrive on `lo_ifp` (loopback). Many code paths check `if_flags & IFF_LOOPBACK` and skip processing (ARP, multicast, VLAN, bridge). |
| **What to do** | In `initialize_network()` create a second ifnet with `IFF_BROADCAST|IFF_MULTICAST|IFF_RUNNING`. Add `optional bool use_ethernet` to `Packet` in the proto. In `get_mbuf_data` use the appropriate ifp. |
| **Impact** | MEDIUM — unlocks ARP, multicast snooping, VLAN, bridge code paths. |

### B7 — Uncomment RecvmsgX / SendmsgX / SendtoNocancel

| | |
|---|---|
| **File** | `fuzz/net_fuzzer.proto:222-230` |
| **Problem** | 5 commented-out syscall wrappers. The wrappers exist in `syscall_wrappers.c` but are not wired to the proto. Extended msg operations (recvmsg_x, sendmsg_x) handle multiple messages in one call — unique code paths. |
| **Fix** | Uncomment, add handlers in `net_fuzzer.cc`. |

### B8 — IOV (scatter-gather) in recvmsg/sendmsg

| | |
|---|---|
| **File** | `fuzz/net_fuzzer.cc`, `fuzz/net_fuzzer.proto` |
| **Problem** | `sendmsg` and `recvmsg` pass empty `user64_msghdr`. No `msg_iov` means no scatter-gather fuzzing. IOV bugs are a historically rich source of kernel vulnerabilities. |
| **What to do** | Add `MsgHdr` proto message with `repeated bytes iov` and `optional bytes control` (for ancillary data). |

### B9 — Ancillary data (cmsg) in sendmsg

| | |
|---|---|
| **Problem** | `SCM_RIGHTS` (fd passing), `IP_PKTINFO`, `IPV6_PKTINFO`, `IP_RECVDSTADDR` — all transmitted via cmsg in sendmsg/recvmsg. Completely unfuzzed. |
| **What to do** | Add `optional bytes control` to `MsgHdr` and generate structured cmsg headers with proper `cmsg_level`, `cmsg_type`, `cmsg_len`. |

### B10 — IP options in IPv4 header

| | |
|---|---|
| **File** | `fuzz/net_fuzzer.cc:248` |
| **Problem** | `ip_hl = 5` is hardcoded (no options). IP option parsing (LSRR, SSRR, record route, timestamp) is ancient code with multiple historical CVEs. |
| **What to do** | Add `repeated bytes ip_options` to `IpHdr`. In harness: `ip_hl = 5 + options_size/4`. |

---

## C. State Management & Isolation

### C1 — Fork-server integration

| | |
|---|---|
| **Files** | `fuzz/snapshot/fork_server.c`, `fuzz/net_fuzzer.cc` |
| **Problem** | Fork server is implemented but not integrated with the main fuzzer loop. Each iteration shares state with the previous one. |
| **What to do** | In `DEFINE_BINARY_PROTO_FUZZER`: after `initialize_network()`, fork. Child executes commands, parent waits and resets. Requires a non-fork mode for debugging. |

### C2 — NECP session/client cleanup in clear_all()

| | |
|---|---|
| **File** | `fuzz/api/backend.c` |
| **Problem** | NECP sessions and clients created during an iteration leak state. No `necp_session_close` / `necp_client_remove` in cleanup. |
| **Fix** | Track NECP fds separately and close in `clear_all()`, or drain via `close_wrapper` on all `open_fds`. |

### C3 — PF state cleanup in clear_all()

| | |
|---|---|
| **File** | `fuzz/api/backend.c` |
| **Problem** | If `DIOCSTART` was called, PF remains enabled into the next iteration. Rules, state tables, NAT — everything leaks. |
| **Fix** | Add `ioctl_wrapper(pf_fd, DIOCSTOP, ...)` to `clear_all()`, or reset PF state via `DIOCXROLLBACK`. |

### C4 — Routing table flush

| | |
|---|---|
| **File** | `fuzz/api/backend.c` |
| **Problem** | `in_rtqtimo` and `in6_rtqtimo` expire old routes but do not flush the routing table. Routes added by bind/connect persist across iterations. |
| **Fix** | Add `rtflush()` or equivalent to `clear_all()`. |

### C5 — Interface address cleanup

| | |
|---|---|
| **Problem** | `SIOCAIFADDR_IN6_64` adds addresses to interfaces. These addresses persist between iterations, affecting the next iteration's behavior. |
| **Fix** | Track added addresses and remove via `SIOCDIFADDR_IN6` in `clear_all()`. |

---

## D. CI & Infrastructure

### D1 — Run unit tests in CI

| | |
|---|---|
| **File** | `.github/workflows/build.yml` |
| **Problem** | `fake_impls_test` compiles but CI never runs `ctest`. Tests are dead code in CI. |
| **Fix** | Add step: `cd build && ctest --output-on-failure`. |

### D2 — Coverage report in CI

| | |
|---|---|
| **Problem** | No coverage metrics. Nobody knows what % of XNU code is reached by the fuzzer. |
| **What to do** | Linux job: build `net_cov`, run corpus, `llvm-profdata merge`, `llvm-cov report` → upload as artifact. Add badge to README. |

### D3 — Seed corpus generation in CI

| | |
|---|---|
| **Problem** | `scripts/generate_seeds.sh` exists but is never run. The corpus has only 1 file. |
| **Fix** | CI step that generates seeds, measures coverage, and optionally commits if coverage improved. |

### D4 — Crash dedup in CI

| | |
|---|---|
| **Problem** | No automatic crash triage. One bug produces thousands of crash files in the `crashes/` directory. |
| **Fix** | `scripts/triage.sh` should deduplicate via ASAN stack hash. CI reports unique crashes only. |

### D5 — Cache dependencies in CI

| | |
|---|---|
| **Problem** | Every CI run installs dependencies from scratch (~2-5 min overhead). |
| **Fix** | Use `actions/cache` on brew/apt cache directories. |

### D6 — OSS-Fuzz integration

| | |
|---|---|
| **Problem** | The docs mention OSS-Fuzz but no configuration exists. |
| **What to do** | Create `project.yaml` and `build.sh` in OSS-Fuzz format. Submit to `google/oss-fuzz`. Free 24/7 fuzzing on Google infrastructure. |

---

## E. Documentation

### E1 — Coverage report in README

| | |
|---|---|
| **Problem** | No "Current coverage" section with numbers. |
| **Fix** | After D2, add a badge and a table: `TCP: 65%, UDP: 40%, ICMP: 35%, PF: 15%...` |

### E2 — Known bugs found section

| | |
|---|---|
| **Problem** | No proof that the fuzzer finds anything. Even rediscovery of known CVEs would be valuable. |
| **Fix** | Add a "Bugs Found" section with: CVE ID (if known), stack trace, reproducer path. |

### E3 — Comparison table with syzkaller/Fuzzilli

| | |
|---|---|
| **Problem** | No context for how this fuzzer compares to other tools. |
| **Fix** | Add a table: SockFuzzer vs syzkaller vs Fuzzilli — what each targets, what bugs it has found. |

### E4 — SECURITY.md

| | |
|---|---|
| **Problem** | No policy on what to do with found bugs (responsible disclosure). |
| **Fix** | "Found a bug? Report to Apple via https://security.apple.com/research/bounty" |

---

## F. Advanced Techniques (9 → 10/10)

### F1 — TCP state machine aware grammar

| | |
|---|---|
| **Problem** | Commands are random — the probability of hitting a SYN→SYN-ACK→ACK→DATA→FIN sequence is ~(1/35)^5. Deep TCP states (FIN-WAIT-2, TIME-WAIT, CLOSE-WAIT) are virtually unreachable. |
| **What to do** | Add `message TcpSession` with ordered stages, or implement a custom mutator that prefers valid TCP state transitions. |

### F2 — Custom libFuzzer mutator

| | |
|---|---|
| **Problem** | Default libprotobuf-mutator mutates blindly — e.g., changes fd to nonsense, changes socket domain after connect. |
| **What to do** | Implement `LLVMFuzzerCustomMutator` that: mutates only packets for existing sockets, prefers commands in valid order (socket → bind → listen → accept), and increases probability of data-heavy mutations (payloads, options). |

### F3 — Coverage-guided corpus management

| | |
|---|---|
| **Problem** | The fuzzer generates a corpus but nobody analyzes it. |
| **What to do** | Script that: (1) runs `llvm-cov` per testcase → function coverage, (2) identifies uncovered functions, (3) generates targeted seeds for uncovered paths, (4) minimizes corpus (`-merge=1`), (5) reports coverage delta. |

### F4 — Continuous fuzzing dashboard

| | |
|---|---|
| **Problem** | One-shot `max_total_time=3600` is not enough. P0 fuzzes for weeks. |
| **What to do** | GitHub Actions scheduled workflow (cron: daily), cloud VM with persistent corpus, simple HTML dashboard with: executions/sec, unique crashes, coverage over time. |

### F5 — Automatic crash-to-PoC translation

| | |
|---|---|
| **Problem** | `scripts/poc_generator.py` exists but the crash → PoC pipeline is not automated end-to-end. |
| **What to do** | Crash artifact → decode protobuf → generate standalone C program that reproduces the syscall sequence → compile → verify it still crashes. |

---

## G. Novel Research (10 → 11/10)

### G1 — Concurrence integration (race condition fuzzing)

| | |
|---|---|
| **Files** | `third_party/concurrence/`, `fuzz/net_fuzzer.cc` |
| **Problem** | Single-threaded model means zero race condition bugs can be found. Kernel races account for ~30% of all kernel CVEs. |
| **What to do** | Use the concurrence scheduler for deterministic interleaving. Two "threads": one performs syscalls, the other injects packets. Scheduler decisions are fuzzed. This is what Ned Williamson intended by adding concurrence — but never integrated it. |

### G2 — Concolic execution hybrid

| | |
|---|---|
| **Problem** | The fuzzer cannot pass deep checksums, magic value comparisons, or complex state predicates. |
| **What to do** | Run QSYM/SymCC on libxnu. Collect constraints from path exploration → solve with SMT → generate inputs → feed back to the fuzzer. Requires instrumenting libxnu with a symbolic execution engine. |

### G3 — Patch-diff → auto-target generation

| | |
|---|---|
| **Problem** | The fuzzer targets the "entire" network stack instead of focusing on freshly patched functions. |
| **What to do** | Pipeline: (1) `ipsw diff` between iOS versions, (2) identify changed functions in the network stack, (3) map to proto grammar elements, (4) boost mutation weight for those elements. Result: you fuzz what Apple just patched. |

### G4 — Memory corruption oracle (info-leak detection)

| | |
|---|---|
| **Problem** | ASAN catches crashes (write-after-free, heap-overflow-write). It does NOT catch info-leaks (read-after-free, uninitialized-read → copyout to userspace). These are worth $25K-$100K on Apple's bounty program. |
| **What to do** | Custom ASAN callbacks + taint tracking on `copyout`: tag kernel memory regions; in `copyout`, check whether copied data contains freed/uninitialized memory markers; report as info-leak. |

### G5 — Multi-protocol session fuzzing

| | |
|---|---|
| **Problem** | Each iteration is an isolated sequence. Real attacks combine TCP + UDP + ICMP + PF rules simultaneously. |
| **What to do** | Add `message MultiSession` with interleaved protocol operations: multiple concurrent socket sessions, interleaved packet injection, and PF rule changes during traffic. |

### G6 — Regression suite from historical CVEs

| | |
|---|---|
| **Problem** | No proof the fuzzer rediscovers known bugs. |
| **What to do** | For each XNU networking CVE from 2019-2024: (1) check if affected code is in compiled XNU sources, (2) create a testcase reproducing the bug class, (3) verify the fuzzer can trigger it, (4) add to regression suite. Target CVEs: CVE-2019-8605, CVE-2020-9839, CVE-2021-1782, CVE-2022-32893, CVE-2023-42824, and more. |

### G7 — Hardware-in-the-loop (fuzz real iPhone via USB)

| | |
|---|---|
| **Problem** | The userland fuzzer tests compiled XNU code, not the actual kernel on a device. |
| **What to do** | SockFuzzer generates a command sequence → translate to Frida script → execute on real iPhone via USB → compare behavior with userland fuzzer → divergence indicates a potential false negative in the fuzzer. |

---

## Summary

| Level | Items | Estimated Effort |
|-------|-------|-----------------|
| **8/10** — Publishable P0 fork | A1-A10 (correctness fixes) | ~4 hours |
| **8.5/10** — Verified quality | D1-D5 (CI improvements) | ~6 hours |
| **9/10** — Better than original P0 | B1-B10 (attack surface), C1-C5 (state mgmt) | ~3 weeks |
| **10/10** — State of the art | F1-F5 (intelligence), E1-E4 (docs) | ~3-4 weeks |
| **11/10** — Novel research | G1-G7 (concolic, races, patch-diff) | ~2-3 months |

**Total: 52 items** from A1 to G7.
