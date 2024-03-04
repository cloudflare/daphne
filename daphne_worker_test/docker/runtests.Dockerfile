FROM rust:1.76-bookworm

WORKDIR /tmp/dap_test

RUN apt-get update && \
    apt-get install -y \
        libssl-dev \
        pkg-config \
        capnproto

RUN rustup component add clippy-preview

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker_test ./daphne_worker_test
COPY daphne_worker ./daphne_worker
COPY daphne_service_utils ./daphne_service_utils
COPY daphne ./daphne
RUN cargo new --lib daphne_server

ENV PATH="${PATH}:/root/.cargo/bin"
ENV RUST_BACKTRACE=1
CMD ["cargo", "test", \
    "--features=test_e2e", \
    "--", \
    "--nocapture", \
    "--test-threads=1", \
    "e2e"]
