#!/bin/bash
#
# Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

# Script for demonstrating how `dapf` is used. To run it, you need to have
# `dapf` in your $PATH, e.g., by running `cargo install --path .`.

set -eo pipefail
# trap read debug

dapf() (
    set +x
    if command -v dapf > /dev/null 2>&1 && ! declare -F dapf > /dev/null 2>&1; then
        command dapf "$@"
    else
        cargo run --bin dapf --quiet -- "$@"
    fi
)


# Task configuration
LEADER_BASE_URL="http://127.0.0.1:8787"
HELPER_BASE_URL="http://127.0.0.1:8788"
for url in "$LEADER_BASE_URL" "$HELPER_BASE_URL"; do
    until curl --fail -X POST "$url/internal/test/ready"; do
        sleep 10
    done
    echo "$url ready"
done

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

LEADER_AUTH_TOKEN="I-am-the-leader"
COLLECTOR_AUTH_TOKEN="I-am-the-collector"
BASE64_ENCODED_HPKE_CONFIG=$(mktemp)
COLLECTOR_HPKE_RECEIVER_CONFIG=$(dapf hpke generate 2>"$BASE64_ENCODED_HPKE_CONFIG")
LEADER_TASK_CONFIG=$(dapf test-routes create-add-task-json \
    --leader-url "$LEADER_BASE_URL/v09/" \
    --helper-url "$HELPER_BASE_URL/v09/" \
    --query "time-interval" \
    --role leader \
    --vdaf "$VDAF_CONFIG" \
    --leader-auth-token "$LEADER_AUTH_TOKEN" \
    --collector-auth-token "$COLLECTOR_AUTH_TOKEN" \
    --collector-hpke-config "$(tail -n 1 "$BASE64_ENCODED_HPKE_CONFIG")" \
    </dev/null
)
HELPER_TASK_CONFIG=$(echo "$LEADER_TASK_CONFIG" | jq '.role = "helper"' | jq 'del(.collector_authentication_token)')

TASK_ID="$(jq -r .task_id <<<"$LEADER_TASK_CONFIG")" # URL-safe, base64

now=$(date +%s)
let "now = $now - ($now % $MIN_BATCH_DURATION)"
batch_interval=$(cat << EOF
{
    "time_interval": {
        "batch_interval": {
            "start": $now,
            "duration": $MIN_BATCH_DURATION
        }
    }
}
EOF
)

echo "Resetting the Aggregators..."
dapf test-routes clear-storage "${HELPER_BASE_URL}/v09/" --set-hpke-key x25519_hkdf_sha256
dapf test-routes clear-storage "${LEADER_BASE_URL}/v09/" --set-hpke-key x25519_hkdf_sha256

trap echo EXIT # curl doesn't insert a newline after the body so in case it fails we want to not screw up the terminal
curl --fail-with-body -X POST "${LEADER_BASE_URL}/v09/internal/test/add_task" -H content-type:application/json -d "$LEADER_TASK_CONFIG"
echo
curl --fail-with-body -X POST "${HELPER_BASE_URL}/v09/internal/test/add_task" -H content-type:application/json -d "$HELPER_TASK_CONFIG"
echo
trap - EXIT

# Upload "13" a number of times.
MEASUREMENT=13
for i in {1..10}; do
    echo "Uploading report $i..."
        dapf leader upload \
            --task-id "$TASK_ID" \
            --leader-url "$LEADER_BASE_URL/v09/" \
            --helper-url "$HELPER_BASE_URL/v09/" \
            --vdaf "$VDAF_CONFIG" \
            "{\"u64\":$MEASUREMENT}"
done

echo "Sending collect request..."
collect_job_id=$(
    dapf leader collect \
        --task-id "$TASK_ID" \
        --collector-auth-token "$COLLECTOR_AUTH_TOKEN" \
        --leader-url "$LEADER_BASE_URL/v09/" \
        "$batch_interval"
)

# TODO(cjpatton) Remove this once aggregation jobs are scheduled automatically
# by the Leader. (See issue #25.)
echo "Processing reports...."
curl -f -X POST $LEADER_BASE_URL/internal/process \
    -d '{"max_buckets":10,"max_reports":10}'
echo



echo "Collecting result..."
i=0
outcome='Done!'
until outcome=$(dapf leader collect-poll \
        --task-id "$TASK_ID" \
        --hpke-config-path <(echo "$COLLECTOR_HPKE_RECEIVER_CONFIG") \
        --leader-url "$LEADER_BASE_URL/v09/" \
        --collect-job-id "$collect_job_id" \
        --vdaf "$VDAF_CONFIG" \
        --batch-selector "$batch_interval" \
        --collector-auth-token "$COLLECTOR_AUTH_TOKEN"); do
    echo "Processing reports...."
    curl -f -X POST $LEADER_BASE_URL/internal/process \
        -d '{"max_buckets":10,"max_reports":10}'
    echo
    if [[ $(( i++ )) -eq 5 ]]; then
        outcome="failed to collect"
        break
    fi
done

echo -e "\noutcome: $outcome"
echo "expected outcome: 130"
