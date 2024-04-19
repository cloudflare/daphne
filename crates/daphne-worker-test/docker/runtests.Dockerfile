# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

FROM rust:1.76-bookworm

WORKDIR /tmp/dap_test

RUN apt-get update && \
    apt-get install -y \
        libssl-dev \
        pkg-config \
        capnproto

COPY Cargo.toml Cargo.lock ./
COPY crates/daphne-worker-test ./crates/daphne-worker-test
COPY crates/daphne-worker ./crates/daphne-worker
COPY crates/daphne-service-utils ./crates/daphne-service-utils
COPY crates/daphne ./crates/daphne

ENV PATH="${PATH}:/root/.cargo/bin"
ENV RUST_BACKTRACE=1
CMD ["cargo", "test", \
    "--features=test_e2e", \
    "--", \
    "--nocapture", \
    "--test-threads=1", \
    "e2e"]
