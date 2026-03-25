#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Reproduce a crash from a fuzzer artifact file.
# Usage: ./scripts/reproduce.sh <crash_file> [fuzzer_binary]

set -e

CRASH_FILE="${1:?Usage: $0 <crash_file> [fuzzer_binary]}"
FUZZER="${2:-build/net_fuzzer}"

if [ ! -f "$CRASH_FILE" ]; then
  echo "Error: crash file not found: $CRASH_FILE"
  exit 1
fi

if [ ! -x "$FUZZER" ]; then
  echo "Error: fuzzer binary not found: $FUZZER"
  echo "Build with: mkdir build && cd build && cmake .. && make -j"
  exit 1
fi

echo "Reproducing crash with: $CRASH_FILE"
echo "Fuzzer binary: $FUZZER"
echo "---"

ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0 \
  "$FUZZER" "$CRASH_FILE"
