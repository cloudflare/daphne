# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

FROM rust:1.76-bookworm AS builder
RUN apt update && apt install -y capnproto clang

# Pre-install worker-build and Rust's wasm32 target to speed up our custom build command
RUN rustup target add wasm32-unknown-unknown
RUN cargo install --git https://github.com/cloudflare/workers-rs

# Build the storage proxy.
WORKDIR /tmp/dap_test
COPY Cargo.toml Cargo.lock ./
COPY crates/daphne-worker-test ./crates/daphne-worker-test
COPY crates/daphne-worker ./crates/daphne-worker
COPY crates/daphne-service-utils ./crates/daphne-service-utils
COPY crates/daphne ./crates/daphne
WORKDIR /tmp/dap_test/crates/daphne-worker-test
RUN worker-build --dev

FROM node:bookworm AS final
RUN npm install -g wrangler@3.50.0 && npm cache clean --force
COPY --from=builder /tmp/dap_test/crates/daphne-worker-test/build/ /build
COPY crates/daphne-worker-test/wrangler.storage-proxy.toml /

ENTRYPOINT ["wrangler", "dev", "--config", "wrangler.storage-proxy.toml"]
