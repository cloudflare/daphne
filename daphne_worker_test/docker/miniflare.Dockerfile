FROM rust:1.61-bullseye

WORKDIR /tmp/dap_test

RUN apt-get update && \
    apt-get install -y nodejs npm

RUN npm install -g n && \
    n 18.4.0

RUN npm install -g \
        @cloudflare/wrangler \
        wasm-pack \
        miniflare@2.5.1

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker_test ./daphne_worker_test
COPY daphne_worker ./daphne_worker
COPY daphne ./daphne

ENV PATH="${PATH}:/root/.cargo/bin"

WORKDIR /tmp/dap_test/daphne_worker_test
RUN wrangler build

ENTRYPOINT ["miniflare"]
