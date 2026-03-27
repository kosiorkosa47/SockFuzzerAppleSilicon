# CVE Regression Tests

Targeted test cases that verify the fuzzer can reach code paths affected by
historical XNU networking CVEs. These are NOT exploits — they are coverage
verification seeds that exercise the vulnerable function.

## Test Structure

Each CVE directory contains:
- `README.md` — description, affected function, XNU version, patch commit
- `verify.sh` — script that runs the fuzzer and checks function coverage

## Known CVEs in Compiled XNU Sources

| CVE | Function | File | Bug Class | In Sources? |
|-----|----------|------|-----------|-------------|
| CVE-2019-8605 | `in6_pcbdetach` | bsd/netinet6/in6_pcb.c | UAF | Yes |
| CVE-2020-3911 | `frag6_input` | bsd/netinet6/frag6.c | Heap overflow | Yes |
| CVE-2020-9839 | `tcp_input` | bsd/netinet/tcp_input.c | OOB read | Yes |
| CVE-2021-1782 | `mptcp_usr_connectx` | bsd/netinet/mptcp_usrreq.c | Race | Yes |
| CVE-2022-32893 | `pf_test_rule` | bsd/net/pf.c | Memory corruption | Yes |
| CVE-2023-42824 | Various | Multiple | Multiple | Check |

## Running Regression Tests

```bash
# Run all regression tests
for dir in tests/regression/CVE-*/; do
  echo "=== $(basename $dir) ==="
  bash "$dir/verify.sh" build/net_cov
done
```

## Adding a New Regression Test

1. Identify the affected function and file
2. Verify the function is in `BSD_SOURCES` (CMakeLists.txt)
3. Create a directory: `tests/regression/CVE-YYYY-NNNNN/`
4. Write `verify.sh` that checks coverage of the affected function
5. Document in README.md
