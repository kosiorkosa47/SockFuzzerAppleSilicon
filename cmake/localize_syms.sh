#!/bin/bash
# Localize all symbols in a raw relocatable object except those in the export list.
#
# Usage: localize_syms.sh EXPORT_LIST [RAW_INPUT] [OUTPUT]
#   EXPORT_LIST  file listing the symbols to keep global (required)
#   RAW_INPUT    input relocatable object  (default: libxnu_relocatable_raw.o)
#   OUTPUT       localized output object   (default: libxnu_relocatable.o)
#
# RAW_INPUT and OUTPUT are parameters, and the scratch files are derived from
# OUTPUT, so that concurrent invocations do not clobber each other. The ASAN
# (net_fuzzer) and coverage (net_cov) pipelines both call this script and run
# in parallel under `ninja` / `make -j`; when both used the same hard-coded
# file names, whichever finished second stole or truncated the other's object
# and the net_fuzzer link failed with "no such file or directory:
# libxnu_relocatable.o".
#
# Tries nmedit first (Apple toolchain). Falls back to llvm-objcopy if nmedit
# fails (e.g., Homebrew LLVM's ld -r produces objects with different string
# table layout).
set -e
EXPORT_LIST="$1"
RAW_INPUT="${2:-libxnu_relocatable_raw.o}"
OUTPUT="${3:-libxnu_relocatable.o}"

# Scratch files are namespaced per output object so parallel invocations of
# this script never share state.
TMP_PREFIX="_$(basename "$OUTPUT" .o)"
ALL_SYMS="${TMP_PREFIX}_all_syms.txt"
FILTERED_SYMS="${TMP_PREFIX}_filtered_syms.txt"

if [ ! -f "$RAW_INPUT" ]; then
  echo "ERROR: $RAW_INPUT not found in $(pwd)" >&2
  exit 1
fi

# Build filtered symbol list (only symbols actually present in the object).
nm -gU "$RAW_INPUT" | awk '{print $NF}' | sort -u > "$ALL_SYMS"
grep -Fx -f "$EXPORT_LIST" "$ALL_SYMS" > "$FILTERED_SYMS" 2>/dev/null || cp "$EXPORT_LIST" "$FILTERED_SYMS"

# Try nmedit (Apple toolchain, works with Xcode ld output).
if nmedit -s "$FILTERED_SYMS" -p "$RAW_INPUT" -o "$OUTPUT" 2>/dev/null; then
  exit 0
fi

# Fallback: llvm-objcopy --localize-hidden (works with LLVM ld output).
# First, mark everything hidden, then globalize the exports.
echo "nmedit failed, falling back to llvm-objcopy..." >&2
OBJCOPY=$(command -v llvm-objcopy || echo "$(brew --prefix llvm 2>/dev/null)/bin/llvm-objcopy")
if [ -x "$OBJCOPY" ]; then
  cp "$RAW_INPUT" "$OUTPUT"
  # Build --globalize-symbol args from the export list
  GLOBAL_ARGS=""
  while IFS= read -r sym; do
    GLOBAL_ARGS="$GLOBAL_ARGS --globalize-symbol=$sym"
  done < "$FILTERED_SYMS"
  $OBJCOPY --localize-hidden $GLOBAL_ARGS "$OUTPUT" 2>/dev/null || {
    echo "WARNING: llvm-objcopy failed, using raw object without symbol localization" >&2
    cp "$RAW_INPUT" "$OUTPUT"
  }
else
  echo "WARNING: neither nmedit nor llvm-objcopy available, using raw object" >&2
  cp "$RAW_INPUT" "$OUTPUT"
fi
