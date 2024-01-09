FROM rust:1.75-bookworm AS builder

RUN apt update && \
    apt install -y \
        capnproto

WORKDIR /dap

COPY Cargo.toml Cargo.lock .
COPY daphne daphne
COPY daphne_service_utils daphne_service_utils
COPY daphne_server daphne_server
RUN cargo new --lib daphne_worker
RUN cargo new --lib daphne_worker_test

RUN cargo build -p daphne_server --example service --features test-utils

FROM debian:bookworm AS helper

COPY ./daphne_server/examples/configuration-helper.toml configuration.toml
RUN sed -i 's/localhost/helper_storage/g' configuration.toml
COPY --from=builder /dap/target/debug/examples/service .

ENTRYPOINT ["./service"]

FROM debian:bookworm AS leader

COPY ./daphne_server/examples/configuration-leader.toml configuration.toml
RUN sed -i 's/localhost/leader_storage/g' configuration.toml
COPY --from=builder /dap/target/debug/examples/service .

ENTRYPOINT ["./service"]
