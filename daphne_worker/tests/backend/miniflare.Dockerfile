FROM rust:1.61-bullseye

WORKDIR /tmp/ppm

RUN apt-get update && \
    apt-get install -y nodejs npm

RUN npm install -g n && \
    n 17.1.0

RUN npm install -g \
        @cloudflare/wrangler \
        wasm-pack \
        miniflare@2.5.0

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker ./daphne_worker
COPY daphne ./daphne

WORKDIR /tmp/ppm/daphne_worker

ENV PATH="${PATH}:/root/.cargo/bin"
RUN wrangler build

ENTRYPOINT ["miniflare"]
