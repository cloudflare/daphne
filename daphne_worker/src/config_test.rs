// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::config::DaphneWorkerConfig;
use daphne::messages::{Id, Interval, Nonce};

pub const GLOBAL_CONFIG: &str = r#"{
    "max_batch_duration": 100,
    "min_batch_interval_start": 432000,
    "max_batch_interval_end": 18000
}"#;

const DAP_TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "leader_url": "https://leader.biz/leadver/v1/",
        "helper_url": "http://helper.com:8788",
        "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "min_batch_duration": 3600,
        "min_batch_size": 100,
        "vdaf": {
            "prio3": {
                "sum": {
                    "bits": 10
                }
            }
        },
        "vdaf_verify_key": "1fd8d30dc0e0b7ac81f0050fcab0782d"
    },
    "aaaabe3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "leader_url": "http://leader:8787",
        "helper_url": "http://helper:8788",
        "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "min_batch_duration": 3600,
        "min_batch_size": 10,
        "vdaf": {
            "prio2": {
                "dimension": 100
            }
        },
        "vdaf_verify_key": "1fd8d30dc0e0b7ac81f0050fcab0782d1fd8d30dc0e0b7ac81f0050fcab0782d"
    }
}"#;

const DAP_HPKE_RECEIVER_CONFIG_LIST: &str = r#"[
    {
        "config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key": "5dc71373c6aa7b0af67944a370ab96d8b8216832579c19159ca35d10f25a2765"
        },
        "secret_key": "888e94344585f44530d03e250268be6c6a5caca5314513dcec488cc431486c69"
    },
    {
        "config": {
            "id": 14,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key": "b07126295bcfcdeaec61b310fd7ffbf8c6ca7f6c17e3e0a80a5405a242e5084b"
        },
        "secret_key": "b809a4df399548f56c3a15ebaa4925dd292637f0b7e2f6bc3ba60376b69aa05e"
    }
]"#;

const DAP_BUCKET_KEY: &str = "773a0e77ffcfa580c11ad031c35cad02";

#[test]
fn daphne_param() {
    let now = 1637364244;
    let bucket_count = 5;
    let config: DaphneWorkerConfig<String> = DaphneWorkerConfig::from_test_config(
        GLOBAL_CONFIG,
        DAP_TASK_LIST,
        DAP_HPKE_RECEIVER_CONFIG_LIST,
        DAP_BUCKET_KEY,
        bucket_count,
    )
    .unwrap();

    let task_id_hex = "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f";
    let task_id = Id(hex::decode(task_id_hex).unwrap().try_into().unwrap());
    let task_config = config.tasks.get(&task_id).unwrap();

    // Try computing a batch name.
    let nonce = Nonce {
        time: now,
        rand: [1; 16],
    };
    assert_eq!(
        config.durable_report_store_name(&task_config, &task_id, &nonce),
        "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637362800/bucket/1"
    );

    // Try enumerating a sequence of batch names.
    let interval = Interval {
        start: now - (now % 3600),
        duration: 2 * 3600,
    };
    let batch_names: Vec<String> = config
        .iter_report_store_names(&task_id, &interval)
        .unwrap()
        .collect();
    assert_eq!(
        batch_names,
        vec![
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637362800/bucket/0",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637366400/bucket/0",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637362800/bucket/1",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637366400/bucket/1",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637362800/bucket/2",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637366400/bucket/2",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637362800/bucket/3",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637366400/bucket/3",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637362800/bucket/4",
            "task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/window/1637366400/bucket/4",
        ]
    );
}
