FROM rust:1.61-bullseye

WORKDIR /tmp/dap_test

RUN apt-get update && \
    apt-get install -y \
        libssl-dev \
        pkg-config

RUN rustup component add clippy-preview

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker_test ./daphne_worker_test
COPY daphne_worker ./daphne_worker
COPY daphne ./daphne
COPY daphne_worker_test/docker/test.sh /
RUN chmod +x /test.sh

RUN cargo build

ENV PATH="${PATH}:/root/.cargo/bin"
CMD ["/test.sh"]
