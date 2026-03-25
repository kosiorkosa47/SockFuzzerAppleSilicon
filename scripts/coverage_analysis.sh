#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Coverage analysis pipeline (F3):
# 1. Run corpus through coverage binary
# 2. Generate coverage report
# 3. Identify uncovered functions
# 4. Minimize corpus
#
# Usage: ./scripts/coverage_analysis.sh [corpus_dir] [cov_binary]

set -e

CORPUS="${1:-corpus}"
COV_BINARY="${2:-build/net_cov}"
REPORT_DIR="coverage_report"

if [ ! -x "$COV_BINARY" ]; then
  echo "Error: coverage binary not found: $COV_BINARY"
  echo "Build with coverage: mkdir build && cd build && cmake .. && make net_cov"
  exit 1
fi

if [ ! -d "$CORPUS" ]; then
  echo "Error: corpus directory not found: $CORPUS"
  exit 1
fi

CORPUS_SIZE=$(find "$CORPUS" -type f | wc -l | tr -d ' ')
echo "=== Coverage Analysis ==="
echo "Corpus:   $CORPUS ($CORPUS_SIZE files)"
echo "Binary:   $COV_BINARY"
echo ""

# Step 1: Run corpus
echo "Step 1: Running corpus through coverage binary..."
rm -f default.profraw
ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0 \
  "$COV_BINARY" "$CORPUS" -runs=0 2>/dev/null || true

if [ ! -f default.profraw ]; then
  echo "Error: no profraw generated"
  exit 1
fi

# Step 2: Merge profile data
echo "Step 2: Merging profile data..."
llvm-profdata merge -sparse default.profraw -o default.profdata

# Step 3: Generate reports
echo "Step 3: Generating reports..."
mkdir -p "$REPORT_DIR"

# Summary
echo ""
echo "=== Coverage Summary ==="
llvm-cov report -instr-profile=default.profdata "$COV_BINARY" 2>/dev/null | tee "$REPORT_DIR/summary.txt"

# HTML report
llvm-cov show -format=html -output-dir="$REPORT_DIR/html" \
  -instr-profile=default.profdata "$COV_BINARY" 2>/dev/null
echo ""
echo "HTML report: $REPORT_DIR/html/index.html"

# Step 4: Find uncovered functions
echo ""
echo "=== Top 20 Uncovered Functions (by region count) ==="
llvm-cov report -instr-profile=default.profdata "$COV_BINARY" \
  -show-functions 2>/dev/null | \
  grep "0.00%" | sort -t'|' -k4 -rn | head -20 | \
  tee "$REPORT_DIR/uncovered.txt"

# Step 5: Minimize corpus
echo ""
echo "Step 5: Minimizing corpus..."
MINIMIZED="${CORPUS}_minimized"
mkdir -p "$MINIMIZED"
ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0 \
  "$COV_BINARY" -merge=1 "$MINIMIZED" "$CORPUS" 2>&1 | tail -3

NEW_SIZE=$(find "$MINIMIZED" -type f | wc -l | tr -d ' ')
echo ""
echo "=== Results ==="
echo "  Original corpus: $CORPUS_SIZE files"
echo "  Minimized:       $NEW_SIZE files"
echo "  Reduction:       $(( (CORPUS_SIZE - NEW_SIZE) * 100 / (CORPUS_SIZE + 1) ))%"
echo "  Reports in:      $REPORT_DIR/"
