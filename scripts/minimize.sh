#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Minimize a crash artifact to the smallest reproducing input.
# Usage: ./scripts/minimize.sh <crash_file> [fuzzer_binary]

set -e

CRASH_FILE="${1:?Usage: $0 <crash_file> [fuzzer_binary]}"
FUZZER="${2:-build/net_fuzzer}"
MINIMIZED="$(dirname "$CRASH_FILE")/minimized_$(basename "$CRASH_FILE")"

if [ ! -f "$CRASH_FILE" ]; then
  echo "Error: crash file not found: $CRASH_FILE"
  exit 1
fi

if [ ! -x "$FUZZER" ]; then
  echo "Error: fuzzer binary not found: $FUZZER"
  exit 1
fi

echo "Minimizing: $CRASH_FILE"
echo "Output:     $MINIMIZED"
echo "---"

ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0 \
  "$FUZZER" \
  -minimize_crash=1 \
  -exact_artifact_path="$MINIMIZED" \
  -max_total_time=60 \
  "$CRASH_FILE"

if [ -f "$MINIMIZED" ]; then
  ORIG_SIZE=$(wc -c < "$CRASH_FILE")
  MIN_SIZE=$(wc -c < "$MINIMIZED")
  echo "---"
  echo "Original:  $ORIG_SIZE bytes"
  echo "Minimized: $MIN_SIZE bytes ($(( 100 - MIN_SIZE * 100 / ORIG_SIZE ))% reduction)"
  echo "Saved to:  $MINIMIZED"
fi
