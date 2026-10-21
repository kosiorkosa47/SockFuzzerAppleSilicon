#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Group crash artifacts by signature.
#
# Usage: ./scripts/triage.sh [-o out_dir] [-k known_file] [-q] <crashes_dir> [fuzzer_binary]
#
#   -o out_dir     Keep results here and only look at crash files not seen
#                  before. Each new signature gets out_dir/<sig>/ with the
#                  first reproducer and its report; out_dir/index.tsv maps
#                  every crash file to its signature. Without -o a scratch
#                  directory is used and everything is triaged afresh.
#   -k known_file  Signatures already looked at, first word per line, '#'
#                  starts a comment. They are counted but not announced.
#   -q             Only print signatures that are new and not known.
#
# A signature is the bug kind plus the first three frames that are not
# sanitizer, libFuzzer or assertion plumbing. Assertions all reach libFuzzer
# through abort(), so the raw top frames would put every one of them in the
# same bucket.
#
# Written for the bash 3.2 that ships with macOS: no associative arrays.

set -u

OUT=""
KNOWN=""
QUIET=0
while getopts "o:k:q" opt; do
  case $opt in
    o) OUT=$OPTARG ;;
    k) KNOWN=$OPTARG ;;
    q) QUIET=1 ;;
    *) sed -n '7,17p' "$0"; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

CRASHES_DIR="${1:?Usage: $0 [-o out_dir] [-k known_file] [-q] <crashes_dir> [fuzzer_binary]}"
FUZZER="${2:-build/net_fuzzer}"

if [ ! -d "$CRASHES_DIR" ]; then
  echo "Error: crashes directory not found: $CRASHES_DIR" >&2
  exit 1
fi
if [ ! -x "$FUZZER" ]; then
  echo "Error: fuzzer binary not found: $FUZZER" >&2
  exit 1
fi

if [ -z "$OUT" ]; then
  OUT=$(mktemp -d)
  trap 'rm -rf "$OUT"' EXIT
fi
mkdir -p "$OUT"
INDEX="$OUT/index.tsv"
touch "$INDEX"

hash12() {
  if command -v md5sum >/dev/null 2>&1; then
    md5sum | cut -c1-12
  else
    md5 -q | cut -c1-12
  fi
}

is_known() {
  [ -n "$KNOWN" ] && [ -f "$KNOWN" ] &&
    sed 's/#.*//' "$KNOWN" | awk '{print $1}' | grep -qx "$1"
}

# Prints "kind<TAB>frame1 < frame2 < frame3" for one fuzzer report on stdin.
signature() {
  awk '
    /^ASSERT: /                  { if (kind == "") kind = "assert" }
    /^KERNEL PANIC: /            { if (kind == "") kind = "panic" }
    /^ZONE BUG: double-free/     { if (kind == "") kind = "zone-double-free" }
    /^ZONE BUG: zone confusion/  { if (kind == "") kind = "zone-confusion" }
    /^SUMMARY: AddressSanitizer: / { if (asan == "") asan = $3 }
    /deadly signal/              { sig = 1 }
    /^ *#[0-9]+ 0x[0-9a-f]+ in / {
      idx = substr($1, 2) + 0
      # A report can hold more than one stack (allocation and free sites).
      # Only the first one is the crash.
      if (idx == 0 && seen > 0) done = 1
      seen++
      if (done || n >= 3) next
      line = $0
      sub(/^ *#[0-9]+ 0x[0-9a-f]+ in /, "", line)
      split(line, parts, " ")
      fn = parts[1]
      sub(/\(.*/, "", fn)
      sub(/\+0x[0-9a-f]+$/, "", fn)
      if (fn ~ /^(__sanitizer_|__asan_|__interceptor_|___interceptor_|wrap_|fuzzer::)/) next
      if (fn ~ /^(_sigtramp|abort|__abort|raise|pthread_kill|__pthread_kill|Assert|assfail|panic|zt_fatal|__assert_rtn|LLVMFuzzerTestOneInput|main|start|_start)$/) next
      frames = (n == 0) ? fn : frames " < " fn
      n++
    }
    END {
      if (asan != "") kind = (kind == "") ? "asan:" asan : kind "/asan:" asan
      if (kind == "") kind = sig ? "signal" : "no-repro"
      if (frames == "") frames = "-"
      printf "%s\t%s\n", kind, frames
    }'
}

NEW=0
FILES=$(find "$CRASHES_DIR" -maxdepth 1 -type f \
  \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' -o -name 'leak-*' \) | sort)

for f in $FILES; do
  base=$(basename "$f")
  if awk -F'\t' -v b="$base" '$1 == b { found = 1 } END { exit !found }' "$INDEX"; then
    continue
  fi

  report="$OUT/.report.$$"
  case $base in
    timeout-*) printf 'timeout\t-\n' > "$report.sig"; : > "$report" ;;
    oom-*)     printf 'oom\t-\n' > "$report.sig"; : > "$report" ;;
    *)
      # The subshell keeps bash's "Abort trap" job message out of the output.
      (ASAN_OPTIONS=detect_container_overflow=0:detect_leaks=0:halt_on_error=1 \
        "$FUZZER" -timeout=60 "$f") > "$report" 2>&1
      signature < "$report" > "$report.sig"
      ;;
  esac

  kind=$(cut -f1 "$report.sig")
  frames=$(cut -f2 "$report.sig")
  sig=$(printf '%s|%s' "$kind" "$frames" | hash12)
  printf '%s\t%s\t%s\t%s\n' "$base" "$sig" "$kind" "$frames" >> "$INDEX"

  if [ ! -d "$OUT/$sig" ]; then
    mkdir -p "$OUT/$sig"
    cp "$f" "$OUT/$sig/"
    mv "$report" "$OUT/$sig/report.txt"
    if is_known "$sig"; then
      [ "$QUIET" -eq 0 ] && echo "[$sig] known  $kind  $frames"
    else
      NEW=$((NEW + 1))
      echo "[$sig] NEW    $kind  $frames"
      echo "         reproducer: $OUT/$sig/$base"
    fi
  fi
  rm -f "$report" "$report.sig"
done

if [ "$QUIET" -eq 0 ]; then
  echo "---"
  awk -F'\t' '
    { count[$2]++; kind[$2] = $3; frames[$2] = $4 }
    END {
      for (s in count) printf "%6d  [%s] %s  %s\n", count[s], s, kind[s], frames[s]
    }' "$INDEX" | sort -rn
  awk -F'\t' '
    { if (!($2 in seen)) { seen[$2] = 1; sigs++ } total++ }
    END { printf "%d crash files, %d signatures\n", total, sigs }' "$INDEX"
fi
exit 0
