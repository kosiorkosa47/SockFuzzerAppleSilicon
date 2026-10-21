#!/bin/bash -eu
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# OSS-Fuzz build script.
# Environment variables set by OSS-Fuzz:
#   $SRC     - source directory
#   $OUT     - output directory for fuzzer binaries
#   $WORK    - work directory
#   $CC, $CXX, $CFLAGS, $CXXFLAGS - compiler and flags
#   $LIB_FUZZING_ENGINE - fuzzing engine library
#   $SANITIZER - address, undefined, ...; CMakeLists.txt reads it to switch
#                to the flags above instead of its own

SRC_DIR=$SRC/sockfuzzer

# protobuf comes from the distribution, built against libstdc++. OSS-Fuzz adds
# -stdlib=libc++ for C++, which would give the fuzzer a different std::string
# ABI from libprotobuf and fail the link. Only address and undefined are
# enabled in project.yaml; neither needs an instrumented libc++ the way
# memory does, so build the C++ side against libstdc++ too.
export CXXFLAGS="${CXXFLAGS//-stdlib=libc++/}"

# Build out of tree in $WORK, so a build/ directory already in the source
# tree (for example a local macOS build mounted in) is never touched.
cmake -S "$SRC_DIR" -B "$WORK/build" -GNinja \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX"

ninja -C "$WORK/build" net_fuzzer

cp "$WORK/build/net_fuzzer" "$OUT/"
cp "$SRC_DIR/net_fuzzer.dict" "$OUT/"

# Seed corpus, without the README next to the seeds.
if [ -d "$SRC_DIR/corpus/seeds" ]; then
  find "$SRC_DIR/corpus/seeds" -type f ! -name 'README*' -print0 |
    xargs -0 zip -j -q "$OUT/net_fuzzer_seed_corpus.zip"
fi
