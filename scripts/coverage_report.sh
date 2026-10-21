#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Measure XNU source coverage of a corpus.
#
# Usage: ./scripts/coverage_report.sh [corpus_dir] [cov_binary] [out_dir]
#   defaults: corpus/seeds  build/net_cov  coverage_report
#
# Each input runs in its own process and the profiles are merged. In one
# process, state left by earlier inputs can make a later one abort, and an
# abort never reaches the profile writer, so the whole profile was lost.
#
# Writes summary.txt, subsystems.md (Markdown, for CI job summaries) and html/.

set -eu

CORPUS="${1:-corpus/seeds}"
COV="${2:-build/net_cov}"
OUT="${3:-coverage_report}"

tool() {
  if command -v "$1" >/dev/null 2>&1; then command -v "$1"; return; fi
  local b="$(brew --prefix llvm 2>/dev/null)/bin/$1"
  [ -x "$b" ] && { echo "$b"; return; }
  echo "Error: $1 not found" >&2; exit 1
}
PROFDATA=$(tool llvm-profdata)
LLVMCOV=$(tool llvm-cov)

[ -x "$COV" ] || { echo "Error: coverage binary not found: $COV" >&2; exit 1; }
[ -d "$CORPUS" ] || { echo "Error: corpus not found: $CORPUS" >&2; exit 1; }

COV=$(cd "$(dirname "$COV")" && pwd)/$(basename "$COV")
CPUS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 2)
PROF=$(mktemp -d); trap 'rm -rf "$PROF"' EXIT
mkdir -p "$OUT"

INPUTS=$(find "$CORPUS" -type f ! -name 'README*' | wc -l | tr -d ' ')
echo "Running $INPUTS inputs from $CORPUS, $CPUS at a time..."
export COV PROF
find "$CORPUS" -type f ! -name 'README*' -print0 | xargs -0 -P "$CPUS" -I{} \
  env ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0:detect_leaks=0 \
      LLVM_PROFILE_FILE="$PROF/%p.profraw" \
      sh -c '"$COV" -timeout=10 "$1" >/dev/null 2>&1 || true' _ {}

"$PROFDATA" merge -sparse "$PROF"/*.profraw -o "$OUT/cov.profdata"
"$LLVMCOV" report -instr-profile="$OUT/cov.profdata" "$COV" > "$OUT/summary.txt" 2>/dev/null
"$LLVMCOV" show -format=html -output-dir="$OUT/html" \
  -instr-profile="$OUT/cov.profdata" "$COV" >/dev/null 2>&1 || true

# Per-subsystem line coverage table, plus the overall TOTAL row.
{
  echo "| Area | Lines covered | Line % |"
  echo "|---|---|---|"
  for d in bsd/netinet bsd/netinet6 bsd/net bsd/kern; do
    grep "third_party/xnu/$d/" "$OUT/summary.txt" | awk -v d="$d" '
      { t += $8; m += $9 }
      END { if (t > 0) printf "| %s | %d/%d | %.1f%% |\n", d, t-m, t, 100*(t-m)/t }'
  done
  # TOTAL also counts the harness and generated protobuf code.
  tail -1 "$OUT/summary.txt" | awk '{ printf "| **All instrumented code** | %d/%d | %s |\n", $8-$9, $8, $10 }'
} > "$OUT/subsystems.md"

cat "$OUT/subsystems.md"
TOTAL_LINE=$(tail -1 "$OUT/summary.txt" | awk '{print $10}')
echo ""
echo "Overall line coverage: $TOTAL_LINE"
echo "Reports in $OUT/ (summary.txt, subsystems.md, html/index.html)"
