#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Continuous fuzzing campaign. A crash never ends the run: libFuzzer runs in
# fork mode with -ignore_crashes, and new crash files are grouped by signature
# with triage.sh while the campaign is going.
#
# Usage: ./scripts/campaign.sh [-b binary] [-j jobs] [-t seconds] [-i seconds] [-T seconds] <workdir> [-- libFuzzer flags]
#
#   -b binary   fuzzer to run (default build/net_fuzzer)
#   -j jobs     parallel fork jobs (default: CPUs - 1)
#   -t seconds  stop after this long (default: run until interrupted)
#   -i seconds  triage interval (default 300)
#   -T seconds  per-input timeout (default 10). An input runs in
#               milliseconds; libFuzzer's own default of 1200 let one hung
#               input stall a fork job for twenty minutes.
#
# Layout of <workdir>, which can be reused to continue a campaign:
#   corpus/      the growing corpus
#   crashes/     raw artifacts written by libFuzzer
#   triage/      one directory per crash signature, plus index.tsv
#   known.txt    signatures you have already looked at, one per line. They are
#                counted but not announced again. It lives here rather than in
#                the repository so it can name bugs that are not public yet.
#   fuzzer.log   libFuzzer output

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BIN="build/net_fuzzer"
JOBS=""
TOTAL_TIME=0
INTERVAL=300
INPUT_TIMEOUT=10
while getopts "b:j:t:i:T:" opt; do
  case $opt in
    b) BIN=$OPTARG ;;
    j) JOBS=$OPTARG ;;
    t) TOTAL_TIME=$OPTARG ;;
    i) INTERVAL=$OPTARG ;;
    T) INPUT_TIMEOUT=$OPTARG ;;
    *) sed -n '9,18p' "$0"; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
WORK="${1:?Usage: $0 [-b binary] [-j jobs] [-t seconds] [-i seconds] [-T seconds] <workdir> [-- libFuzzer flags]}"
shift
[ "${1:-}" = "--" ] && shift

if [ ! -x "$BIN" ]; then
  echo "Error: fuzzer binary not found: $BIN" >&2
  exit 1
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

if [ -z "$JOBS" ]; then
  CPUS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 2)
  JOBS=$((CPUS > 1 ? CPUS - 1 : 1))
fi

mkdir -p "$WORK/corpus" "$WORK/crashes" "$WORK/triage"
touch "$WORK/known.txt"
WORK=$(cd "$WORK" && pwd)
LOG="$WORK/fuzzer.log"

TIME_FLAG=""
[ "$TOTAL_TIME" -gt 0 ] && TIME_FLAG="-max_total_time=$TOTAL_TIME"

echo "=== SockFuzzer campaign ==="
echo "Binary:   $BIN"
echo "Workdir:  $WORK"
echo "Jobs:     $JOBS"
echo "Duration: $([ "$TOTAL_TIME" -gt 0 ] && echo "${TOTAL_TIME}s" || echo "until interrupted")"
echo ""

# libFuzzer writes into the current directory in fork mode, so run from the
# workdir to keep those files out of the caller's tree.
(
  cd "$WORK" &&
  ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0:detect_leaks=0 \
    exec "$BIN" "$WORK/corpus" \
      -fork="$JOBS" -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
      -artifact_prefix="$WORK/crashes/" -max_len=4096 \
      -timeout="$INPUT_TIMEOUT" \
      $TIME_FLAG "$@"
) >> "$LOG" 2>&1 &
FUZZER_PID=$!

triage() {
  "$SCRIPT_DIR/triage.sh" -q -o "$WORK/triage" -k "$WORK/known.txt" \
    "$WORK/crashes" "$BIN"
}

status() {
  local line
  line=$(grep -E '^#[0-9]+: cov:' "$LOG" | tail -1)
  [ -n "$line" ] && echo "[$(date +%H:%M:%S)] $line"
}

stop() {
  kill -INT "$FUZZER_PID" 2>/dev/null
}
trap stop INT TERM

next=$(( $(date +%s) + INTERVAL ))
while kill -0 "$FUZZER_PID" 2>/dev/null; do
  sleep 5
  if [ "$(date +%s)" -ge "$next" ]; then
    status
    triage
    next=$(( $(date +%s) + INTERVAL ))
  fi
done
wait "$FUZZER_PID" 2>/dev/null

echo ""
echo "=== Campaign finished ==="
status
triage
"$SCRIPT_DIR/triage.sh" -o "$WORK/triage" -k "$WORK/known.txt" \
  "$WORK/crashes" "$BIN" | sed -n '/^---$/,$p'
echo "Corpus: $(find "$WORK/corpus" -type f | wc -l | tr -d ' ') files"
