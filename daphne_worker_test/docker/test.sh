#!/bin/bash
#
# Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

set -e

echo "Running e2e tests."
env RUST_BACKTRACE=1 cargo test \
    --features=test_e2e \
    -- \
    --nocapture \
    --test-threads 1 \
    e2e

echo "Running clippy."
cargo clippy -- -Dwarnings
