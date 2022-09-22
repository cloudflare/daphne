// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::config::DaphneWorkerConfig;
use daphne::messages::{Id, Nonce, ReportMetadata};

pub const GLOBAL_CONFIG: &str = r#"{
    "report_storage_epoch_duration": 604800,
    "max_batch_duration": 360000,
    "min_batch_interval_start": 259200,
    "max_batch_interval_end": 259200,
    "supported_hpke_kems": ["X25519HkdfSha256"]
}"#;

const DAP_TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "version": "v01",
        "leader_url": "https://leader.biz/v01/",
        "helper_url": "http://helper.com:8788/v01/",
        "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "time_precision": 3600,
        "query": {
            "time_interval": {
                "min_batch_size": 100
            }
        },
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
        "version": "v01",
        "leader_url": "http://leader:8787/v01/",
        "helper_url": "http://helper:8788/v01/",
        "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "time_precision": 3600,
        "query": {
            "fixed_size": {
                "min_batch_size": 100,
                "max_batch_size": 110
            }
        },
        "vdaf": {
            "prio2": {
                "dimension": 100
            }
        },
        "vdaf_verify_key": "1fd8d30dc0e0b7ac81f0050fcab0782d1fd8d30dc0e0b7ac81f0050fcab0782d"
    }
}"#;

const DAP_BUCKET_KEY: &str = "773a0e77ffcfa580c11ad031c35cad02";

#[test]
fn parse_static_config() {
    let now = 1637364244;
    let bucket_count = 5;
    let config: DaphneWorkerConfig<String> = DaphneWorkerConfig::from_test_config(
        GLOBAL_CONFIG,
        DAP_TASK_LIST,
        DAP_BUCKET_KEY,
        bucket_count,
    )
    .unwrap();

    let task_id_hex = "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f";
    let task_id = Id(hex::decode(task_id_hex).unwrap().try_into().unwrap());
    let task_config = config.tasks.get(&task_id).unwrap();

    // Try computing a batch name.
    let metadata = ReportMetadata {
        time: now,
        nonce: Nonce([1; 16]),
        extensions: Vec::new(),
    };
    let durable_name = config.durable_name_report_store(&task_config, &task_id.to_hex(), &metadata);
    assert_eq!(
        durable_name,
        "v01/task/f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f/epoch/00000000001637193600/shard/1"
    );
}
