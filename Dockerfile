# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build environment for SockFuzzer on Linux.
#
# Usage:
#   docker build --pull -t sockfuzzer-builder .
#   docker run -t -i -v $PWD:/source sockfuzzer-builder /bin/bash
#   # Inside the container:
#   cd /source && mkdir -p build && cd build
#   CC=clang CXX=clang++ cmake -GNinja .. && ninja

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    autoconf \
    cmake \
    git \
    g++-multilib \
    libtool \
    ninja-build \
    python3 \
    libprotobuf-dev \
    protobuf-compiler

WORKDIR $SRC
