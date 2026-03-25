#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Deduplicate crash artifacts by unique stack trace hash.
# Usage: ./scripts/triage.sh <crashes_dir> [fuzzer_binary]

set -e

CRASHES_DIR="${1:?Usage: $0 <crashes_dir> [fuzzer_binary]}"
FUZZER="${2:-build/net_fuzzer}"

if [ ! -d "$CRASHES_DIR" ]; then
  echo "Error: crashes directory not found: $CRASHES_DIR"
  exit 1
fi

if [ ! -x "$FUZZER" ]; then
  echo "Error: fuzzer binary not found: $FUZZER"
  exit 1
fi

CRASH_FILES=$(find "$CRASHES_DIR" -type f -name "crash-*" -o -name "oom-*" -o -name "timeout-*" | sort)
TOTAL=$(echo "$CRASH_FILES" | grep -c . || true)

if [ "$TOTAL" -eq 0 ]; then
  echo "No crash files found in $CRASHES_DIR"
  exit 0
fi

echo "Triaging $TOTAL crash files..."
echo "---"

declare -A SEEN_HASHES
UNIQUE=0
DUPES=0

for f in $CRASH_FILES; do
  # Get top 5 stack frames as dedup key
  STACK=$(ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=1 \
    "$FUZZER" "$f" 2>&1 | grep "^    #[0-4]" | head -5 || true)
  HASH=$(echo "$STACK" | md5sum | cut -c1-12)

  if [ -z "${SEEN_HASHES[$HASH]+x}" ]; then
    SEEN_HASHES[$HASH]="$f"
    UNIQUE=$((UNIQUE + 1))
    echo "[$HASH] UNIQUE: $(basename "$f")"
    echo "$STACK" | sed 's/^/  /'
    echo ""
  else
    DUPES=$((DUPES + 1))
  fi
done

echo "---"
echo "Total:  $TOTAL crashes"
echo "Unique: $UNIQUE"
echo "Dupes:  $DUPES"
