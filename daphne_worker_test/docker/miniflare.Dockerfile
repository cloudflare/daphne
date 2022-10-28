FROM rust:1.63-alpine AS builder
WORKDIR /tmp/dap_test
RUN apk add --update npm bash g++ openssl-dev
RUN npm install -g n wasm-pack && \
    n 18.4.0
RUN npm install -g wrangler@2.1.13

# Pre-install worker-build and Rust's wasm32 target to speed up our custom build command
RUN cargo install --git https://github.com/cloudflare/workers-rs
RUN rustup target add wasm32-unknown-unknown

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker_test ./daphne_worker_test
COPY daphne_worker ./daphne_worker
COPY daphne ./daphne
WORKDIR /tmp/dap_test/daphne_worker_test
RUN wrangler publish --dry-run

FROM alpine:3.16
RUN apk add --update npm bash
RUN npm install -g n && \
    n 18.4.0
RUN npm install -g miniflare@2.11.0
COPY --from=builder /tmp/dap_test/daphne_worker_test/wrangler.toml /wrangler.toml
COPY --from=builder /tmp/dap_test/daphne_worker_test/build/worker/* /build/worker/
# `-B ""` to skip build command.
ENTRYPOINT ["miniflare", "--modules", "--modules-rule=CompiledWasm=**/*.wasm", "/build/worker/shim.mjs", "-B", ""]
