# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

FROM rust:1.76-bookworm

WORKDIR /tmp/dap_test

RUN apt-get update && \
    apt-get install -y \
        libssl-dev \
        pkg-config \
        capnproto

RUN rustup component add clippy-preview

COPY Cargo.toml Cargo.lock ./
COPY crates/daphne_worker_test ./crates/daphne_worker_test
COPY crates/daphne_worker ./crates/daphne_worker
COPY crates/daphne_service_utils ./crates/daphne_service_utils
COPY crates/daphne ./crates/daphne

ENV PATH="${PATH}:/root/.cargo/bin"
ENV RUST_BACKTRACE=1
CMD ["cargo", "test", \
    "--features=test_e2e", \
    "--", \
    "--nocapture", \
    "--test-threads=1", \
    "e2e"]
