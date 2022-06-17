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

# TODO Remove this layer after the next workers-rs release. In order to build
# the Worker, we need the version of worker-build to match the version of
# workers-rs we're using.
RUN git clone https://github.com/cloudflare/workers-rs /tmp/ppm/worker-rs && \
    cd /tmp/ppm/worker-rs && \
    git checkout eacdadd0c0b7d8e74963656e44b3e9c150a5a7d9 && \
    cargo install --path ./worker-build --force

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker ./daphne_worker
COPY daphne ./daphne

WORKDIR /tmp/ppm/daphne_worker

ENV PATH="${PATH}:/root/.cargo/bin"
RUN wrangler build

ENTRYPOINT ["miniflare"]
