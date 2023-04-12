FROM rust:1.68-alpine AS builder
WORKDIR /tmp/dap_test
RUN apk add --update \
    bash \
    g++ \
    make \
    npm \
    openssl-dev \
    wasm-pack
RUN npm install -g wrangler@2.12.2

# Pre-install worker-build and Rust's wasm32 target to speed up our custom build command
RUN cargo install --git https://github.com/cloudflare/workers-rs
RUN rustup target add wasm32-unknown-unknown

COPY Cargo.toml Cargo.lock ./
COPY daphne_worker_test ./daphne_worker_test
COPY daphne_worker ./daphne_worker
COPY daphne ./daphne
WORKDIR /tmp/dap_test/daphne_worker_test
COPY docker/wrangler.toml ./daphne_worker_test/wrangler.toml
RUN wrangler publish --dry-run

FROM alpine:3.16 AS test
RUN apk add --update npm bash
RUN npm install -g miniflare@2.12.2
COPY --from=builder /tmp/dap_test/daphne_worker_test/wrangler.toml /wrangler.toml
COPY --from=builder /tmp/dap_test/daphne_worker_test/build/worker/* /build/worker/
EXPOSE 8080
# `-B ""` to skip build command.
ENTRYPOINT ["miniflare", "--modules", "--modules-rule=CompiledWasm=**/*.wasm", "/build/worker/shim.mjs", "-B", ""]

FROM test AS helper

ENTRYPOINT ["miniflare", "--modules", "--modules-rule=CompiledWasm=**/*.wasm", "/build/worker/shim.mjs", "-B", "", "-p", "8080", "--wrangler-env=helper"]

FROM test AS leader

ENTRYPOINT ["miniflare", "--modules", "--modules-rule=CompiledWasm=**/*.wasm", "/build/worker/shim.mjs", "-B", "", "-p", "8080", "--wrangler-env=leader"]
