#!/bin/bash

set -e

# Start storage proxy.
cd /build/daphne_worker_test
wrangler dev --config wrangler.storage_proxy.toml --port 4001 | ansi2txt &

# Wait for the storage proxy to come up.
curl --retry 10 --retry-delay 1 --retry-all-errors -s http://localhost:4001

# Start service.
env RUST_LOG=info /build/target/release/examples/service -c /build/daphne_server/examples/configuration-helper.toml | ansi2txt &

# Wait for the service to come up.
curl --retry 10 --retry-delay 1 --retry-all-errors -s -X POST http://localhost:8788/internal/test/ready

wait -n
exit $?
