// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use prio::codec::ParameterizedEncode;

use crate::{
    auth::BearerToken,
    hpke::{HpkeKemId, HpkeReceiverConfig},
    messages::taskprov::VdafType,
    messages::{encode_base64url, taskprov::*, Extension, ReportId, ReportMetadata, TaskId},
    taskprov::{
        compute_task_id, compute_vdaf_verify_key, resolve_advertised_task_config, TaskprovVersion,
    },
    vdaf::VdafVerifyKey,
    DapRequest,
};

#[test]
fn check_vdaf_key_computation() {
    let task_id = TaskId([
        0xb4, 0x76, 0x9b, 0xb0, 0x63, 0xa8, 0xb3, 0x31, 0x2a, 0xf7, 0x42, 0x97, 0xf3, 0x0f, 0xdb,
        0xf8, 0xe0, 0xb7, 0x1c, 0x2e, 0xb2, 0x48, 0x1f, 0x59, 0x1d, 0x1d, 0x7d, 0xe6, 0x6a, 0x4c,
        0xe3, 0x4f,
    ]);
    let verify_key_init: [u8; 32] = [
        0x1a, 0x2a, 0x3f, 0x1b, 0xeb, 0xb4, 0xbb, 0xe4, 0x55, 0xea, 0xac, 0xee, 0x29, 0x1a, 0x0f,
        0x32, 0xd7, 0xe1, 0xbc, 0x6c, 0x75, 0x10, 0x05, 0x60, 0x7b, 0x81, 0xda, 0xc3, 0xa7, 0xda,
        0x76, 0x1d,
    ];
    let vk = compute_vdaf_verify_key(
        TaskprovVersion::Draft02,
        &verify_key_init,
        &task_id,
        VdafType::Prio3Aes128Count,
    );
    let expected: [u8; 16] = [
        0xfb, 0xd1, 0x7d, 0xb5, 0x39, 0x0f, 0x94, 0x9e, 0xe3, 0x2d, 0x26, 0x34, 0xdc, 0x49, 0x9f,
        0x5b,
    ];
    match &vk {
        VdafVerifyKey::Prio3(bytes) => assert_eq!(*bytes, expected),
        _ => unreachable!(),
    }
}

// Ensure that the task config is computed the same way whether it was advertised in the request
// header or the report metadata.
#[test]
fn test_resolve_advertised_task_config() {
    let taskprov_version = TaskprovVersion::Draft02;
    let taskprov_task_config = TaskConfig {
        task_info: "Hi".as_bytes().to_vec(),
        aggregator_endpoints: vec![
            UrlBytes {
                bytes: "https://leader.com".as_bytes().to_vec(),
            },
            UrlBytes {
                bytes: "https://helper.com".as_bytes().to_vec(),
            },
        ],
        query_config: QueryConfig {
            time_precision: 0x01,
            max_batch_query_count: 128,
            min_batch_size: 1024,
            var: QueryConfigVar::FixedSize {
                max_batch_size: 2048,
            },
        },
        task_expiration: 0x6352f9a5,
        vdaf_config: VdafConfig {
            dp_config: DpConfig::None,
            var: VdafTypeVar::Prio3Aes128Histogram {
                buckets: vec![1, 2, 3],
            },
        },
    };

    let taskprov_task_config_data = taskprov_task_config.get_encoded_with_param(&taskprov_version);
    let taskprov_task_config_base64url = encode_base64url(&taskprov_task_config_data);
    let task_id = compute_task_id(taskprov_version, &taskprov_task_config_data).unwrap();
    let collector_hpke_config = HpkeReceiverConfig::gen(1, HpkeKemId::X25519HkdfSha256)
        .unwrap()
        .config;

    let from_request_header = resolve_advertised_task_config(
        &DapRequest::<BearerToken> {
            task_id: Some(task_id.clone()),
            taskprov: Some(taskprov_task_config_base64url),
            ..Default::default()
        },
        taskprov_version,
        &[0; 32],
        &collector_hpke_config,
        &task_id,
        None,
    )
    .unwrap()
    .unwrap();

    let from_report_metadata = resolve_advertised_task_config(
        &DapRequest::<BearerToken> {
            task_id: Some(task_id.clone()),
            ..Default::default()
        },
        taskprov_version,
        &[0; 32],
        &collector_hpke_config,
        &task_id,
        Some(&ReportMetadata {
            id: ReportId([0; 16]),
            time: 0,
            extensions: vec![Extension::Taskprov {
                payload: taskprov_task_config_data,
            }],
        }),
    )
    .unwrap()
    .unwrap();

    assert_eq!(from_request_header.version, from_report_metadata.version);
    assert_eq!(
        from_request_header.leader_url,
        from_report_metadata.leader_url
    );
    assert_eq!(
        from_request_header.helper_url,
        from_report_metadata.helper_url
    );
    assert_eq!(
        from_request_header.time_precision,
        from_report_metadata.time_precision
    );
    assert_eq!(
        from_request_header.expiration,
        from_report_metadata.expiration
    );
    assert_eq!(
        from_request_header.min_batch_size,
        from_report_metadata.min_batch_size
    );
    assert_eq!(from_request_header.query, from_report_metadata.query);
    assert_eq!(from_request_header.vdaf, from_report_metadata.vdaf);
    assert_eq!(
        from_request_header.vdaf_verify_key.as_ref(),
        from_report_metadata.vdaf_verify_key.as_ref()
    );
    assert_eq!(
        from_request_header.collector_hpke_config,
        from_report_metadata.collector_hpke_config
    );
}
