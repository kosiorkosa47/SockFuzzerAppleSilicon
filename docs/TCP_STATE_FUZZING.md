# TCP State Machine-Guided Fuzzing

## TCP State Diagram

```
                              ┌───────────┐
                    ┌────────►│  CLOSED   │◄────────┐
                    │         └─────┬─────┘         │
                    │               │ socket()      │
                    │               ▼               │
                    │         ┌───────────┐         │
                    │    ┌───►│  LISTEN   │         │
                    │    │    └─────┬─────┘         │
                    │    │          │ SYN recv      │
                    │    │          ▼               │
               close│    │    ┌───────────┐         │
                    │    │    │ SYN_RCVD  │         │timeout
                    │    │    └─────┬─────┘         │
                    │    │          │ ACK recv      │
    socket() ──►    │    │          ▼               │
    connect() ──►   │    │    ┌───────────┐         │
                    │    │    │ESTABLISHED│         │
           ┌───────────┐│    └──┬──────┬──┘         │
           │ SYN_SENT  ││       │      │            │
           └───────────┘│  close│      │FIN recv    │
                    │    │      ▼      ▼            │
                    │    │ ┌────────┐ ┌──────────┐  │
                    │    │ │FIN_WAIT│ │CLOSE_WAIT│  │
                    │    │ │   1    │ │          │  │
                    │    │ └───┬────┘ └────┬─────┘  │
                    │    │     │           │close   │
                    │    │     ▼           ▼        │
                    │    │ ┌────────┐ ┌──────────┐  │
                    │    │ │FIN_WAIT│ │ LAST_ACK │──┘
                    │    │ │   2    │ └──────────┘
                    │    │ └───┬────┘
                    │    │     │
                    │    │     ▼
                    │    │ ┌──────────┐
                    └────┘ │TIME_WAIT │──► 2MSL timeout ──► CLOSED
                           └──────────┘
```

## Fuzzing Strategy

### Phase 1: Seed Corpus for Each State

Create protobuf Sessions that intentionally reach each TCP state:

| Target State | Command Sequence |
|---|---|
| LISTEN | socket(TCP) → bind → listen |
| SYN_SENT | socket(TCP) → connect(non-routable) |
| SYN_RCVD | socket → bind → listen → inject SYN packet |
| ESTABLISHED | socket → bind → listen → inject SYN → inject ACK |
| CLOSE_WAIT | ESTABLISHED → inject FIN |
| LAST_ACK | CLOSE_WAIT → close |
| FIN_WAIT_1 | ESTABLISHED → close (before FIN recv) |
| FIN_WAIT_2 | FIN_WAIT_1 → inject ACK (not FIN+ACK) |
| TIME_WAIT | FIN_WAIT_2 → inject FIN |
| CLOSING | FIN_WAIT_1 → inject FIN (simultaneous close) |

### Phase 2: State-Specific Mutation

Once in a target state, the fuzzer should:
1. Inject malformed packets (wrong seq, wrong flags, truncated options)
2. Call socket operations (setsockopt, ioctl, shutdown, sendmsg)
3. Exercise timer-driven transitions (keepalive, retransmit)

### Phase 3: Coverage-Guided Discovery

Instrument `tcp_input.c` state transition code to track which
(state, event) pairs have been seen. Prioritize seeds that
reach unexplored transitions.

### Historical Vulnerabilities by State

| State | CVE | Type |
|---|---|---|
| TIME_WAIT | CVE-2019-6600 | Use-after-free |
| CLOSE_WAIT | CVE-2020-1971 | Memory corruption |
| LAST_ACK | CVE-2019-8605 | Type confusion |
| SYN_RCVD | CVE-2018-6924 | Resource exhaustion |
| ESTABLISHED | CVE-2020-9839 | Heap overflow |

## Implementation Notes

The current fuzzer reaches CLOSED, SYN_SENT, and ESTABLISHED naturally.
To reach other states, the seed corpus must include carefully sequenced
socket + packet injection commands. Use `scripts/generate_seeds.sh` as
a starting point and manually craft additional seeds.
