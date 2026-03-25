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

cd $SRC/sockfuzzer

mkdir -p build && cd build

SANITIZER=${SANITIZER:-address}
export SANITIZER

cmake .. -GNinja \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX

ninja net_fuzzer

cp net_fuzzer $OUT/
cp ../net_fuzzer.dict $OUT/

# Copy seed corpus if available
if [ -d ../corpus/seeds ]; then
  zip -j $OUT/net_fuzzer_seed_corpus.zip ../corpus/seeds/* 2>/dev/null || true
fi
