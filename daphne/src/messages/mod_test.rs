// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::messages::{
    decode_base64url, decode_base64url_vec, encode_base64url, AggregateShareReq,
    AggregationJobContinueReq, AggregationJobId, AggregationJobInitReq, AggregationJobResp,
    BatchId, BatchSelector, CollectionJobId, DapVersion, Draft02AggregationJobId, Extension,
    HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeKdfId, HpkeKemId, PartialBatchSelector, Report,
    ReportId, ReportMetadata, ReportShare, TaskId, Transition, TransitionVar,
};
use crate::{test_version, test_versions};
use hpke_rs::HpkePublicKey;
use paste::paste;
use prio::codec::{Decode, Encode, ParameterizedDecode, ParameterizedEncode};
use rand::prelude::*;

fn task_id_for_version(version: DapVersion) -> Option<TaskId> {
    if version == DapVersion::Draft02 {
        Some(TaskId([1; 32]))
    } else {
        None
    }
}

fn read_report(version: DapVersion) {
    let report = Report {
        draft02_task_id: task_id_for_version(version),
        report_metadata: ReportMetadata {
            id: ReportId([23; 16]),
            time: 1637364244,
            extensions: vec![],
        },
        public_share: b"public share".to_vec(),
        encrypted_input_shares: vec![
            HpkeCiphertext {
                config_id: 23,
                enc: b"leader encapsulated key".to_vec(),
                payload: b"leader ciphertext".to_vec(),
            },
            HpkeCiphertext {
                config_id: 119,
                enc: b"helper encapsulated key".to_vec(),
                payload: b"helper ciphertext".to_vec(),
            },
        ],
    };
    assert_eq!(
        Report::get_decoded_with_param(&version, &report.get_encoded_with_param(&version)).unwrap(),
        report
    );
}

test_versions! {read_report}

#[test]
fn read_report_with_unknown_extensions_draft02() {
    let report = Report {
        draft02_task_id: task_id_for_version(DapVersion::Draft02),
        report_metadata: ReportMetadata {
            id: ReportId([23; 16]),
            time: 1637364244,
            extensions: vec![Extension::Unhandled {
                typ: 0xfff,
                payload: b"some extension".to_vec(),
            }],
        },
        public_share: b"public share".to_vec(),
        encrypted_input_shares: vec![
            HpkeCiphertext {
                config_id: 23,
                enc: b"leader encapsulated key".to_vec(),
                payload: b"leader ciphertext".to_vec(),
            },
            HpkeCiphertext {
                config_id: 119,
                enc: b"helper encapsulated key".to_vec(),
                payload: b"helper ciphertext".to_vec(),
            },
        ],
    };
    let version = DapVersion::Draft02;
    assert!(
        Report::get_decoded_with_param(&version, &report.get_encoded_with_param(&version)).is_err()
    );
}

#[test]
fn read_agg_job_init_req() {
    let want = AggregationJobInitReq {
        draft02_task_id: Some(TaskId([23; 32])),
        draft02_agg_job_id: Some(Draft02AggregationJobId([1; 32])),
        agg_param: b"this is an aggregation parameter".to_vec(),
        part_batch_sel: PartialBatchSelector::FixedSizeByBatchId {
            batch_id: BatchId([0; 32]),
        },
        report_shares: vec![
            ReportShare {
                report_metadata: ReportMetadata {
                    id: ReportId([99; 16]),
                    time: 1637361337,
                    extensions: Vec::default(),
                },
                public_share: b"public share".to_vec(),
                encrypted_input_share: HpkeCiphertext {
                    config_id: 23,
                    enc: b"encapsulated key".to_vec(),
                    payload: b"ciphertext".to_vec(),
                },
            },
            ReportShare {
                report_metadata: ReportMetadata {
                    id: ReportId([17; 16]),
                    time: 163736423,
                    extensions: Vec::default(),
                },
                public_share: b"public share".to_vec(),
                encrypted_input_share: HpkeCiphertext {
                    config_id: 0,
                    enc: vec![],
                    payload: b"ciphertext".to_vec(),
                },
            },
        ],
    };

    let got = AggregationJobInitReq::get_decoded_with_param(
        &crate::DapVersion::Draft02,
        &want.get_encoded_with_param(&crate::DapVersion::Draft02),
    )
    .unwrap();
    assert_eq!(got, want);

    let want = AggregationJobInitReq {
        draft02_task_id: None,
        draft02_agg_job_id: None,
        agg_param: b"this is an aggregation parameter".to_vec(),
        part_batch_sel: PartialBatchSelector::FixedSizeByBatchId {
            batch_id: BatchId([0; 32]),
        },
        report_shares: vec![
            ReportShare {
                report_metadata: ReportMetadata {
                    id: ReportId([99; 16]),
                    time: 1637361337,
                    extensions: Vec::default(),
                },
                public_share: b"public share".to_vec(),
                encrypted_input_share: HpkeCiphertext {
                    config_id: 23,
                    enc: b"encapsulated key".to_vec(),
                    payload: b"ciphertext".to_vec(),
                },
            },
            ReportShare {
                report_metadata: ReportMetadata {
                    id: ReportId([17; 16]),
                    time: 163736423,
                    extensions: Vec::default(),
                },
                public_share: b"public share".to_vec(),
                encrypted_input_share: HpkeCiphertext {
                    config_id: 0,
                    enc: vec![],
                    payload: b"ciphertext".to_vec(),
                },
            },
        ],
    };

    let got = AggregationJobInitReq::get_decoded_with_param(
        &DapVersion::Draft05,
        &want.get_encoded_with_param(&DapVersion::Draft05),
    )
    .unwrap();
    assert_eq!(got, want);
}

#[test]
fn read_agg_job_cont_req() {
    let want = AggregationJobContinueReq {
        draft02_task_id: Some(TaskId([23; 32])),
        draft02_agg_job_id: Some(Draft02AggregationJobId([1; 32])),
        round: None,
        transitions: vec![
            Transition {
                report_id: ReportId([0; 16]),
                var: TransitionVar::Continued(b"this is a VDAF-specific message".to_vec()),
            },
            Transition {
                report_id: ReportId([1; 16]),
                var: TransitionVar::Continued(
                    b"believe it or not this is *also* a VDAF-specific message".to_vec(),
                ),
            },
        ],
    };

    let got = AggregationJobContinueReq::get_decoded_with_param(
        &DapVersion::Draft02,
        &want.get_encoded_with_param(&DapVersion::Draft02),
    )
    .unwrap();
    assert_eq!(got, want);

    let want = AggregationJobContinueReq {
        draft02_task_id: None,
        draft02_agg_job_id: None,
        round: Some(1),
        transitions: vec![
            Transition {
                report_id: ReportId([0; 16]),
                var: TransitionVar::Continued(b"this is a VDAF-specific message".to_vec()),
            },
            Transition {
                report_id: ReportId([1; 16]),
                var: TransitionVar::Continued(
                    b"believe it or not this is *also* a VDAF-specific message".to_vec(),
                ),
            },
        ],
    };

    let got = AggregationJobContinueReq::get_decoded_with_param(
        &DapVersion::Draft05,
        &want.get_encoded_with_param(&DapVersion::Draft05),
    )
    .unwrap();
    assert_eq!(got, want);
}

#[test]
fn read_agg_share_req() {
    let want = AggregateShareReq {
        draft02_task_id: Some(TaskId([23; 32])),
        batch_sel: BatchSelector::FixedSizeByBatchId {
            batch_id: BatchId([23; 32]),
        },
        agg_param: b"this is an aggregation parameter".to_vec(),
        report_count: 100,
        checksum: [0; 32],
    };

    let got = AggregateShareReq::get_decoded_with_param(
        &DapVersion::Draft02,
        &want.get_encoded_with_param(&DapVersion::Draft02),
    )
    .unwrap();
    assert_eq!(got, want);

    let want = AggregateShareReq {
        draft02_task_id: None,
        batch_sel: BatchSelector::FixedSizeByBatchId {
            batch_id: BatchId([23; 32]),
        },
        agg_param: b"this is an aggregation parameter".to_vec(),
        report_count: 100,
        checksum: [0; 32],
    };
    let got = AggregateShareReq::get_decoded_with_param(
        &DapVersion::Draft05,
        &want.get_encoded_with_param(&DapVersion::Draft05),
    )
    .unwrap();
    assert_eq!(got, want);
}

#[test]
fn read_agg_job_resp() {
    let want = AggregationJobResp {
        transitions: vec![
            Transition {
                report_id: ReportId([22; 16]),
                var: TransitionVar::Continued(b"this is a VDAF-specific message".to_vec()),
            },
            Transition {
                report_id: ReportId([255; 16]),
                var: TransitionVar::Continued(
                    b"believe it or not this is *also* a VDAF-specific message".to_vec(),
                ),
            },
        ],
    };

    let got = AggregationJobResp::get_decoded(&want.get_encoded()).unwrap();
    assert_eq!(got, want);
}

#[test]
fn read_hpke_config() {
    let data = [
        23, 0, 32, 0, 1, 0, 1, 0, 20, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 112, 117, 98,
        108, 105, 99, 32, 107, 101, 121,
    ];

    let hpke_config = HpkeConfig::get_decoded(&data).unwrap();
    assert_eq!(
        hpke_config,
        HpkeConfig {
            id: 23,
            kem_id: HpkeKemId::X25519HkdfSha256,
            kdf_id: HpkeKdfId::HkdfSha256,
            aead_id: HpkeAeadId::Aes128Gcm,
            public_key: HpkePublicKey::from(b"this is a public key".to_vec()),
        }
    );
}

#[test]
fn read_unsupported_hpke_config() {
    let data = [
        23, 0, 99, 0, 99, 0, 99, 0, 20, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 112, 117, 98,
        108, 105, 99, 32, 107, 101, 121,
    ];

    let hpke_config = HpkeConfig::get_decoded(&data).unwrap();
    assert_eq!(
        hpke_config,
        HpkeConfig {
            id: 23,
            kem_id: HpkeKemId::NotImplemented(99),
            kdf_id: HpkeKdfId::NotImplemented(99),
            aead_id: HpkeAeadId::NotImplemented(99),
            public_key: HpkePublicKey::from(b"this is a public key".to_vec()),
        }
    );
}

// NOTE: these test vectors are no longer valid, TaskProv doesn't match the VDAF-06
// Tracking the issue here: https://github.com/wangshan/draft-wang-ppm-dap-taskprov/issues/33.
// #[test]
// fn read_vdaf_config() {
//     let data = [
//         0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x18, 0x01, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02,
//         0x01, 0x02, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x02, 0x03, 0x02, 0x03, 0x04, 0x04, 0x03,
//         0x02, 0x03,
//     ];

//     // let buckets = vec![0x0102030404030201, 0x0202030404030202, 0x0302030404030203];
//     let len_length: u8 = 1;
//     let vdaf_config = VdafConfig::get_decoded(&data).unwrap();
//     assert_eq!(
//         vdaf_config,
//         VdafConfig {
//             dp_config: DpConfig::None,
//             // var: VdafTypeVar::Prio3Aes128Histogram { buckets },
//             var: VdafTypeVar::Prio3Aes128Histogram { len_length },
//         }
//     );
// }

// #[test]
// fn read_task_config_taskprov_draft02() {
//     let data = [
//         0x02, 0x48, 0x69, 0x00, 0x0e, 0x00, 0x0c, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
//         0x74, 0x65, 0x73, 0x74, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80,
//         0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x52, 0xf9,
//         0xa5, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x18, 0x01, 0x02, 0x03, 0x04, 0x04, 0x03,
//         0x02, 0x01, 0x02, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x02, 0x03, 0x02, 0x03, 0x04, 0x04,
//         0x03, 0x02, 0x03,
//     ];

//     // let buckets = vec![0x0102030404030201, 0x0202030404030202, 0x0302030404030203];
//     let len_length: u8 = 1;
//     let task_config = TaskConfig::get_decoded_with_param(&TaskprovVersion::Draft02, &data).unwrap();
//     assert_eq!(
//         task_config,
//         TaskConfig {
//             task_info: "Hi".as_bytes().to_vec(),
//             aggregator_endpoints: vec![UrlBytes {
//                 bytes: "https://test".as_bytes().to_vec()
//             }],
//             query_config: QueryConfig {
//                 time_precision: 0x01,
//                 max_batch_query_count: 128,
//                 min_batch_size: 1024,
//                 var: QueryConfigVar::FixedSize {
//                     max_batch_size: 2048
//                 },
//             },
//             task_expiration: 0x6352f9a5,
//             vdaf_config: VdafConfig {
//                 dp_config: DpConfig::None,
//                 var: VdafTypeVar::Prio3Aes128Histogram { len_length },
//             },
//         }
//     );

//     assert_eq!(
//         compute_task_id(
//             TaskprovVersion::Draft02,
//             &task_config.get_encoded_with_param(&TaskprovVersion::Draft02)
//         )
//         .unwrap()
//         .to_hex(),
//         "2b585fcbb48c21fb5f05221a241fdd8cb9ebe99bd183d66326fcecd85fe06fd5",
//     );

//     assert_eq!(
//         task_config.get_encoded_with_param(&TaskprovVersion::Draft02),
//         &data
//     );
// }

#[test]
fn test_base64url() {
    let mut rng = thread_rng();
    let id = rng.gen::<[u8; 32]>();
    assert_eq!(decode_base64url(encode_base64url(id)).unwrap(), id);
    assert_eq!(decode_base64url_vec(encode_base64url(id)).unwrap(), id);
}

#[test]
fn roundtrip_id_base64url() {
    let id = AggregationJobId([7; 16]);
    assert_eq!(
        AggregationJobId::try_from_base64url(id.to_base64url()).unwrap(),
        id
    );

    let id = BatchId([7; 32]);
    assert_eq!(BatchId::try_from_base64url(id.to_base64url()).unwrap(), id);

    let id = CollectionJobId([7; 16]);
    assert_eq!(
        CollectionJobId::try_from_base64url(id.to_base64url()).unwrap(),
        id
    );

    let id = Draft02AggregationJobId([13; 32]);
    assert_eq!(
        Draft02AggregationJobId::try_from_base64url(id.to_base64url()).unwrap(),
        id
    );

    let id = ReportId([7; 16]);
    assert_eq!(ReportId::try_from_base64url(id.to_base64url()).unwrap(), id);

    let id = TaskId([7; 32]);
    assert_eq!(TaskId::try_from_base64url(id.to_base64url()).unwrap(), id);
}
