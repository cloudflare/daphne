FROM rust:1.76-bookworm AS builder
WORKDIR /tmp/dap_test
RUN apt update && \
    apt install -y \
    clang \
    make \
    npm \
    capnproto

RUN npm install -g wrangler@2.19.0

# Pre-install worker-build and Rust's wasm32 target to speed up our custom build command
RUN cargo install --git https://github.com/cloudflare/workers-rs
RUN rustup target add wasm32-unknown-unknown

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker_test ./daphne_worker_test
COPY daphne_worker ./daphne_worker
COPY daphne_service_utils ./daphne_service_utils
COPY daphne ./daphne
RUN cargo new --lib daphne_server
WORKDIR /tmp/dap_test/daphne_worker_test
COPY daphne_worker_test/wrangler.storage_proxy.toml ./wrangler.toml
RUN wrangler publish --dry-run

FROM alpine:3.16 AS test
RUN apk add --update npm bash
RUN npm install -g miniflare@2.14.0
COPY --from=builder /tmp/dap_test/daphne_worker_test/wrangler.toml /wrangler.toml
COPY --from=builder /tmp/dap_test/daphne_worker_test/build/worker/* /build/worker/
# `-B ""` to skip build command.
ENTRYPOINT ["miniflare", "--modules", "--modules-rule=CompiledWasm=**/*.wasm", "/build/worker/shim.mjs", "-B", ""]
