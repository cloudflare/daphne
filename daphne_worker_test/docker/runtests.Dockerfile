FROM rust:1.73-bookworm

WORKDIR /tmp/dap_test

RUN apt-get update && \
    apt-get install -y \
        libssl-dev \
        pkg-config \
        capnproto

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker_test ./daphne_worker_test
COPY daphne_worker ./daphne_worker
COPY daphne_service_utils ./daphne_service_utils
COPY daphne ./daphne
COPY daphne_worker_test/docker/test.sh /
RUN cargo new --lib daphne_server
RUN chmod +x /test.sh

ENV PATH="${PATH}:/root/.cargo/bin"
CMD ["/test.sh"]
