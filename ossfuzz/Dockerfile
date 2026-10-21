# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# OSS-Fuzz compatible Dockerfile.
# See: https://google.github.io/oss-fuzz/getting-started/new-project-guide/

# Ubuntu 24.04 base (base_os_version in project.yaml). The default 20.04
# image only has protobuf 3.6, too old for the vendored libprotobuf-mutator,
# which needs FieldDescriptor::has_presence (protobuf 3.12+). 24.04 ships
# 3.21, the same version the Linux CI job builds against.
FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    zip \
    libprotobuf-dev \
    protobuf-compiler

COPY . $SRC/sockfuzzer
WORKDIR $SRC/sockfuzzer
COPY ossfuzz/build.sh $SRC/
