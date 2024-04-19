# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

FROM rust:1.76-bookworm AS builder

RUN apt update && \
    apt install -y \
        capnproto

WORKDIR /dap

COPY Cargo.toml Cargo.lock .
COPY crates/daphne crates/daphne
COPY crates/daphne_service_utils crates/daphne_service_utils
COPY crates/daphne_server crates/daphne_server

RUN cargo build -p daphne_server --example service --features test-utils

FROM debian:bookworm AS helper

COPY ./crates/daphne_server/examples/configuration-helper.toml configuration.toml
RUN sed -i 's/localhost/helper_storage/g' configuration.toml
COPY --from=builder /dap/target/debug/examples/service .

ENTRYPOINT ["./service"]

FROM debian:bookworm AS leader

COPY ./crates/daphne_server/examples/configuration-leader.toml configuration.toml
RUN sed -i 's/localhost/leader_storage/g' configuration.toml
COPY --from=builder /dap/target/debug/examples/service .

ENTRYPOINT ["./service"]
