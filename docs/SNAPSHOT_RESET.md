# Fork-Based Snapshot Reset

## Design

Instead of incrementally cleaning up kernel state via `clear_all()`, use
`fork()` to create an isolated child process for each fuzzer iteration.

```
                  initialize_network()
                         │
                    fork() ──► snapshot
                         │
              ┌──────────┴──────────┐
              │                     │
          [parent]              [child]
          waits...          runs fuzzer iteration
              │                 │
              │             crash/exit
              │                 │
              ◄─────────────────┘
              │
          fork() again ──► next iteration
```

## Benefits

- **Perfect isolation**: child process has a copy-on-write snapshot of the
  initialized kernel state. No cleanup needed — process exit frees everything.
- **No state leaks**: mathematically impossible for state to leak between
  iterations (separate address spaces).
- **Crash resilience**: child crash doesn't affect parent.

## Challenges

- **libFuzzer compatibility**: libFuzzer's coverage counters must be in shared
  memory (`MAP_SHARED`) for the parent to see coverage from children.
- **Performance**: `fork()` overhead per iteration. Modern Linux uses COW so
  the overhead is small (~50us), but it adds up at 10K+ exec/sec.
- **ASAN**: ASAN's shadow memory must be handled carefully across fork.

## Implementation Status

This is currently a design document. Implementation requires:
1. Custom `LLVMFuzzerTestOneInput` that forks per iteration
2. Shared memory region for coverage counters
3. Signal handler in parent to collect crash artifacts
4. Fallback to `clear_all()` mode when fork overhead is too high

## Alternative: Persistent Mode with Checkpointing

Instead of forking per iteration, checkpoint the kernel state after
`initialize_network()` using `mmap` snapshots of key data structures.
Restore the snapshot between iterations. Lower overhead than fork but
requires identifying all mutable state (fragile).
