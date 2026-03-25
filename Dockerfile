# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Multi-stage build for SockFuzzer on Linux.
#
# Build:
#   docker build --pull -t sockfuzzer .
#
# Run fuzzer:
#   docker run --rm -v $PWD/corpus:/work/corpus -v $PWD/crashes:/work/crashes \
#     sockfuzzer ./net_fuzzer corpus/ -artifact_prefix=crashes/ -max_total_time=3600
#
# Interactive shell:
#   docker run -it --rm sockfuzzer /bin/bash

# --- Stage 1: Builder ---
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang-18 \
    cmake \
    git \
    lld-18 \
    llvm-18 \
    ninja-build \
    libprotobuf-dev \
    protobuf-compiler \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
  && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 \
  && update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/ld.lld-18 100 \
  && update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-18 100 \
  && update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-18 100

WORKDIR /build/source
COPY . .

RUN mkdir -p /build/out && cd /build/out \
  && CC=clang CXX=clang++ cmake -GNinja /build/source \
  && ninja

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libprotobuf32 \
    libstdc++6 \
    llvm-18 \
  && rm -rf /var/lib/apt/lists/* \
  && update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-18 100 \
  && update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-18 100

WORKDIR /work

COPY --from=builder /build/out/net_fuzzer /work/
COPY --from=builder /build/source/net_fuzzer.dict /work/
COPY --from=builder /build/source/scripts/ /work/scripts/

RUN mkdir -p corpus crashes && chmod +x scripts/*.sh

ENV ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=1

ENTRYPOINT ["/work/net_fuzzer"]
CMD ["corpus/", "-artifact_prefix=crashes/", "-dict=net_fuzzer.dict"]
