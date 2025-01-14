# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

FROM rust:1.80-bookworm AS builder

RUN apt update && \
    apt install -y \
        capnproto

WORKDIR /dap

COPY Cargo.toml Cargo.lock .
COPY crates/daphne crates/daphne
COPY crates/daphne-service-utils crates/daphne-service-utils
COPY crates/daphne-server crates/daphne-server

RUN cargo build -p daphne-server --example service --features test-utils

FROM debian:bookworm AS helper

COPY ./crates/daphne-server/examples/configuration-helper.toml configuration.toml
RUN sed -i 's/localhost/helper_storage/g' configuration.toml
COPY --from=builder /dap/target/debug/examples/service .

ENTRYPOINT ["./service"]

FROM debian:bookworm AS leader

COPY ./crates/daphne-server/examples/configuration-leader.toml configuration.toml
RUN sed -i 's/localhost/leader_storage/g' configuration.toml
COPY --from=builder /dap/target/debug/examples/service .

ENTRYPOINT ["./service"]
