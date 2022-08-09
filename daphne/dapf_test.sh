#/bin/bash
#
# Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

# Script for demonstrating how `dapf` is used. To run it, you need to have
# `dapf` in your $PATH, e.g., by running `cargo install --path .`.

set -e

# Task configuration
TASK_ID="8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8=" # URL-safe, base64
LEADER_BASE_URL="http://127.0.0.1:8787"
HELPER_BASE_URL="http://127.0.0.1:8788"
MIN_BATCH_DURATION=3600 # seconds
VDAF_CONFIG=$(cat << EOF
{
    "prio3": {
        "sum": {
            "bits": 10
        }
    }
}
EOF
)

# Collector's bearer token for authorizing collect requests. This needs to be
# kept secret and have high entropy.
COLLECTOR_BEARER_TOKEN="this is the bearer token of the Collector"

# Collector's HPKE config and secret key. This needs to be kept secret.
#
# TODO(cjpatton) Make the KEM, KDF, and AEAD alg identifiers snake case.
COLLECTOR_HPKE_RECEIVER_CONFIG=$(cat << EOF
{
    "config": {
        "id": 23,
        "kem_id": "X25519HkdfSha256",
        "kdf_id": "HkdfSha256",
        "aead_id": "Aes128Gcm",
        "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
    },
    "secret_key": "60890f1e438bf1f0e9ad2bd839acf1341137eee623bf7906972bf1cc80bb5d7b"
}
EOF
)

now=$(date +%s)
let "now = $now - ($now % $MIN_BATCH_DURATION)"
batch_interval=$(cat << EOF
{
    "interval": {
        "start": $now,
        "duration": $MIN_BATCH_DURATION
    }
}
EOF
)

echo "Resetting the Aggregators..."
curl -f -X POST "$LEADER_BASE_URL/internal/delete_all"
curl -f -X POST "$HELPER_BASE_URL/internal/delete_all"


# Upload "13" a number of times.
MEASUREMENT=13
for i in {1..10}; do
    echo "Uploading report $i..."
    echo "{\"u64\":$MEASUREMENT}" | \
        dapf \
            --task-id "$TASK_ID" \
            upload \
                --leader-url "$LEADER_BASE_URL/v01/" \
                --helper-url "$HELPER_BASE_URL/v01/" \
                --vdaf "$VDAF_CONFIG"
done

echo "Sending collect request..."
collect_uri=$(echo $batch_interval | \
    dapf \
        --task-id "$TASK_ID" \
        --bearer-token "$COLLECTOR_BEARER_TOKEN" \
        collect \
            --leader-url "$LEADER_BASE_URL/v01/"
:)

# TODO(cjpatton) Remove this once aggregation jobs are scheduled automatically
# by the Leader. (See issue #25.)
echo "Processing reports...."
curl -f -X POST $LEADER_BASE_URL/internal/process \
    -d '{"max_buckets":10,"max_reports":10}'
echo



echo "Collecting result..."
result=$(echo $batch_interval | \
    dapf \
        --task-id "$TASK_ID" \
        --hpke-receiver "$COLLECTOR_HPKE_RECEIVER_CONFIG" \
        collect-poll \
            --uri "$collect_uri" \
            --vdaf "$VDAF_CONFIG"
)

echo "Done! $result"
