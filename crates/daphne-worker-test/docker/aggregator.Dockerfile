# Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

FROM rust:1.80-bookworm AS builder
RUN apt update && apt install -y capnproto clang cmake

# Pre-install worker-build and Rust's wasm32 target to speed up our custom build command
RUN rustup target add wasm32-unknown-unknown
RUN cargo install worker-build@0.1.1 --locked

# Build the worker.
WORKDIR /tmp/dap_test
COPY Cargo.toml Cargo.lock ./
COPY crates/daphne-worker-test ./crates/daphne-worker-test
COPY crates/daphne-worker ./crates/daphne-worker
COPY crates/daphne-service-utils ./crates/daphne-service-utils
COPY crates/daphne ./crates/daphne
WORKDIR /tmp/dap_test/crates/daphne-worker-test
RUN worker-build --dev

FROM node:bookworm AS leader
RUN npm install -g wrangler@3.60.1 && npm cache clean --force
COPY --from=builder /tmp/dap_test/crates/daphne-worker-test/build/ /build
COPY crates/daphne-worker-test/wrangler.aggregator.toml /
# this container doesn't need worker-build but the wrangler.toml requires it, so we just fake it
RUN ln -s /usr/bin/true /usr/bin/worker-build

ENTRYPOINT ["wrangler", "dev", "--config", "wrangler.aggregator.toml", "-e", "leader", "--port", "8787"]

FROM node:bookworm AS helper
RUN npm install -g wrangler@3.60.1 && npm cache clean --force
COPY --from=builder /tmp/dap_test/crates/daphne-worker-test/build/ /build
COPY crates/daphne-worker-test/wrangler.aggregator.toml /
# this container doesn't need worker-build but the wrangler.toml requires it, so we just fake it
RUN ln -s /usr/bin/true /usr/bin/worker-build

ENTRYPOINT ["wrangler", "dev", "--config", "wrangler.aggregator.toml", "-e", "helper", "--port", "8788", "--var", "COMPUTE_OFFLOAD_HOST:compute-offload:5000"]
