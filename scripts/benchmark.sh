#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Performance benchmark for SockFuzzer.
# Measures iterations/sec, coverage, and memory usage.
#
# Usage: ./scripts/benchmark.sh [fuzzer_binary] [duration_seconds]

set -e

FUZZER="${1:-build/net_fuzzer}"
DURATION="${2:-60}"
RESULTS_DIR="benchmarks"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="$RESULTS_DIR/bench_$TIMESTAMP.json"
TEMP_CORPUS=$(mktemp -d)

if [ ! -x "$FUZZER" ]; then
  echo "Error: fuzzer binary not found: $FUZZER"
  exit 1
fi

mkdir -p "$RESULTS_DIR"

echo "=== SockFuzzer Benchmark ==="
echo "Binary:   $FUZZER"
echo "Duration: ${DURATION}s"
echo "Output:   $RESULT_FILE"
echo ""

# Run fuzzer and capture output
ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0 \
  "$FUZZER" "$TEMP_CORPUS" \
  -dict=net_fuzzer.dict \
  -max_total_time="$DURATION" \
  -print_final_stats=1 \
  2>&1 | tee /tmp/bench_output.txt

# Parse results
EXECS=$(grep "stat::number_of_executed_units:" /tmp/bench_output.txt | awk '{print $2}' || echo "0")
COVERAGE=$(grep "stat::new_units_added:" /tmp/bench_output.txt | awk '{print $2}' || echo "0")
PEAK_RSS=$(grep "stat::peak_rss_mb:" /tmp/bench_output.txt | awk '{print $2}' || echo "0")
EXECS_PER_SEC=$((EXECS / DURATION))
CORPUS_SIZE=$(find "$TEMP_CORPUS" -type f | wc -l | tr -d ' ')

# Write JSON results
cat > "$RESULT_FILE" <<ENDJSON
{
  "timestamp": "$TIMESTAMP",
  "duration_seconds": $DURATION,
  "total_executions": $EXECS,
  "executions_per_second": $EXECS_PER_SEC,
  "new_units_added": $COVERAGE,
  "corpus_size": $CORPUS_SIZE,
  "peak_rss_mb": $PEAK_RSS,
  "fuzzer_binary": "$FUZZER"
}
ENDJSON

rm -rf "$TEMP_CORPUS"

echo ""
echo "=== Results ==="
echo "  Executions:     $EXECS"
echo "  Exec/sec:       $EXECS_PER_SEC"
echo "  New coverage:   $COVERAGE units"
echo "  Corpus size:    $CORPUS_SIZE"
echo "  Peak RSS:       ${PEAK_RSS} MB"
echo "  Saved to:       $RESULT_FILE"

# Compare with previous benchmark if exists
PREV=$(ls -t "$RESULTS_DIR"/bench_*.json 2>/dev/null | head -2 | tail -1)
if [ -n "$PREV" ] && [ "$PREV" != "$RESULT_FILE" ]; then
  PREV_EPS=$(python3 -c "import json; print(json.load(open('$PREV'))['executions_per_second'])" 2>/dev/null || echo "0")
  if [ "$PREV_EPS" -gt 0 ] 2>/dev/null; then
    CHANGE=$(( (EXECS_PER_SEC - PREV_EPS) * 100 / PREV_EPS ))
    echo ""
    echo "  vs previous:    ${CHANGE}% change in exec/sec"
    if [ "$CHANGE" -lt -10 ]; then
      echo "  WARNING: >10% performance regression detected!"
    fi
  fi
fi
