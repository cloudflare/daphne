#!/bin/bash
# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

set -e

mkdir /logs

echo "Starting storage proxy"
# Start storage proxy.
nohup wrangler dev --config wrangler.storage-proxy.toml --port 4001 | ansi2txt \
    > /logs/storage_proxy.log 2>&1 &

# Wait for the storage proxy to come up.
curl --retry 10 --retry-delay 1 --retry-all-errors -s http://localhost:4001

printf "\nStarting service\n"

# Start service.
nohup env RUST_LOG=info ./service -c configuration-helper.toml | ansi2txt \
    > /logs/service.log 2>&1 &

# Wait for the service to come up.
curl --retry 10 --retry-delay 1 --retry-all-errors -s -X POST http://localhost:8788/internal/test/ready

echo "Ready to receive requests!"

wait -n
exit $?
