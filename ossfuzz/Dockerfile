# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# OSS-Fuzz compatible Dockerfile.
# See: https://google.github.io/oss-fuzz/getting-started/new-project-guide/

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    libprotobuf-dev \
    protobuf-compiler

COPY . $SRC/sockfuzzer
WORKDIR $SRC/sockfuzzer
COPY ossfuzz/build.sh $SRC/
