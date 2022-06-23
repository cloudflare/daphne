// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::config::DaphneWorkerConfig;
use daphne::{
    hpke::HpkeDecrypter,
    messages::{Interval, Nonce},
};

const DAP_TASK_LIST: &str = r#"{
  "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
    "leader_url": "https://leader.biz/leadver/v1/",
    "helper_url": "http://helper.com:8788",
    "collector_hpke_config": "f40020000100010020a761d90c8c76d3d76349a3794a439a1572ab1fb8f13531d69744c92ea7757d7f",
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
  }
}"#;

const DAP_HPKE_CONFIG_LIST: &str = r#"[
    "1700200001000100205dc71373c6aa7b0af67944a370ab96d8b8216832579c19159ca35d10f25a2765"
]"#;

// TODO Encode the secret key as a hex string. Unfortunately it's not as simple as adding
// #[serde(with = "hex")] to the struct definition.
const DAP_HPKE_SECRET_KEY_LIST: &str = r#"[
    {
        "id": 23,
        "sk": "888e94344585f44530d03e250268be6c6a5caca5314513dcec488cc431486c69"
    }
]"#;

const DAP_BUCKET_KEY: &str = "773a0e77ffcfa580c11ad031c35cad02";

#[test]
fn daphne_param() {
    let now = 1637364244;
    let bucket_count = 5;
    let config: DaphneWorkerConfig<String> = DaphneWorkerConfig::from_test_config(
        DAP_TASK_LIST,
        DAP_HPKE_CONFIG_LIST,
        DAP_HPKE_SECRET_KEY_LIST,
        DAP_BUCKET_KEY,
        bucket_count,
    )
    .unwrap();

    let (task_id, task_config) = config.tasks.iter().next().unwrap().clone();

    // Try computing a batch name.
    let nonce = Nonce {
        time: now,
        rand: 10496152761178246059,
    };
    assert_eq!(
        config.durable_report_store_name(&task_config, &task_id, &nonce),
        "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637362800/bucket/3"
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
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637362800/bucket/0",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637366400/bucket/0",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637362800/bucket/1",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637366400/bucket/1",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637362800/bucket/2",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637366400/bucket/2",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637362800/bucket/3",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637366400/bucket/3",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637362800/bucket/4",
            "/task/8oW-PK-Uj8_Da30yGBwU25XFXwT1Wi2y7kOcWHkmTh8/window/1637366400/bucket/4",
        ]
    );

    // Try fetching the first HPKE config.
    config.get_hpke_config_for(&task_id).unwrap();
    // TODO Test that hpke_config() checks that the output can be parsed.
}
