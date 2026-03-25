# Concurrent Syscall Fuzzing via Coroutines

## Motivation

XNU's networking stack has numerous race conditions that only manifest
under concurrent access. Single-threaded fuzzing cannot find these bugs.
The CoroutineExecutor already exists in `fuzz/executor/` — this document
describes how to integrate it into the main fuzzer loop.

## Architecture

```
       Session (protobuf)
              │
    ┌─────────┴──────────┐
    │                    │
 commands_a[]        commands_b[]
    │                    │
    ▼                    ▼
 Coroutine A         Coroutine B
    │                    │
    ├── socket()         ├── socket()
    │   ↕ switch         │
    │                    ├── connect()
    ├── send()           │   ↕ switch
    │   ↕ switch         │
    │                    ├── close()  ← race with send!
    ├── recv()           │
    └── close()          └──
```

## Protobuf Extension

```protobuf
message ConcurrentSession {
  repeated Command stream_a = 1;
  repeated Command stream_b = 2;
  required bytes data_provider = 3;
}
```

## Scheduling Strategy

The fuzzer controls when coroutines switch using fuzzed data:
1. Execute one command from stream A
2. Use `get_fuzzed_bool()` to decide whether to switch to B
3. Repeat until both streams are exhausted

This creates deterministic interleavings that libFuzzer can explore
via coverage feedback.

## TSAN Integration

Build with `-fsanitize=thread` instead of `-fsanitize=address` to
detect data races. Requires:
- Replacing no-op lock stubs with real pthread mutexes
- Adding TSAN annotations for XNU-specific synchronization

## Known Race-Prone Areas

| Area | Functions | Historical CVEs |
|---|---|---|
| Socket close + send | `soclose()` + `sosend()` | CVE-2019-8605 |
| Accept + close | `soaccept()` + `soclose()` | CVE-2020-3911 |
| TCP state + timer | `tcp_input()` + `tcp_timer()` | CVE-2018-4407 |
| NECP client + close | `necp_client_action()` | CVE-2021-1782 |

## Implementation Status

Design phase. The CoroutineExecutor is functional (with tests).
Integration into `net_fuzzer.cc` requires:
1. New proto message for concurrent sessions
2. Scheduler loop in DEFINE_BINARY_PROTO_FUZZER
3. Lock stub replacement for TSAN mode
4. Coverage verification that interleavings are explored
