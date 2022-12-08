// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::messages::taskprov::{
    DpConfig, QueryConfig, QueryConfigVar, TaskConfig, UrlBytes, VdafConfig, VdafTypeVar,
};
use crate::messages::{
    AggregateContinueReq, AggregateInitializeReq, AggregateResp, AggregateShareReq, BatchSelector,
    DapVersion, Extension, HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeKdfId, HpkeKemId, Id,
    PartialBatchSelector, Report, ReportId, ReportMetadata, ReportShare, Transition, TransitionVar,
};
use crate::taskprov::{compute_task_id, TaskprovVersion};
use crate::{test_version, test_versions};
use hpke_rs::HpkePublicKey;
use paste::paste;
use prio::codec::{Decode, Encode, ParameterizedDecode, ParameterizedEncode};

fn read_report(version: DapVersion) {
    let report = Report {
        task_id: Id([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16,
        ]),
        metadata: ReportMetadata {
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
        task_id: Id([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16,
        ]),
        metadata: ReportMetadata {
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
fn read_agg_init_req() {
    let want = AggregateInitializeReq {
        task_id: Id([23; 32]),
        agg_job_id: Id([1; 32]),
        agg_param: b"this is an aggregation parameter".to_vec(),
        part_batch_sel: PartialBatchSelector::FixedSizeByBatchId {
            batch_id: Id([0; 32]),
        },
        report_shares: vec![
            ReportShare {
                metadata: ReportMetadata {
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
                metadata: ReportMetadata {
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

    let got = AggregateInitializeReq::get_decoded_with_param(
        &crate::DapVersion::Draft02,
        &want.get_encoded_with_param(&crate::DapVersion::Draft02),
    )
    .unwrap();
    assert_eq!(got, want);
    let got = AggregateInitializeReq::get_decoded_with_param(
        &crate::DapVersion::Draft03,
        &want.get_encoded_with_param(&crate::DapVersion::Draft03),
    )
    .unwrap();
    assert_eq!(got, want);
}

#[test]
fn read_agg_cont_req() {
    let want = AggregateContinueReq {
        task_id: Id([23; 32]),
        agg_job_id: Id([1; 32]),
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

    let got = AggregateContinueReq::get_decoded(&want.get_encoded()).unwrap();
    assert_eq!(got, want);
}

#[test]
fn read_agg_share_req() {
    let want = AggregateShareReq {
        task_id: Id([23; 32]),
        batch_sel: BatchSelector::FixedSizeByBatchId {
            batch_id: Id([23; 32]),
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
    let got = AggregateShareReq::get_decoded_with_param(
        &DapVersion::Draft03,
        &want.get_encoded_with_param(&DapVersion::Draft03),
    )
    .unwrap();
    assert_eq!(got, want);
}

#[test]
fn read_agg_resp() {
    let want = AggregateResp {
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

    let got = AggregateResp::get_decoded(&want.get_encoded()).unwrap();
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

#[test]
fn read_vdaf_config() {
    let data = [
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x18, 0x01, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02,
        0x01, 0x02, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x02, 0x03, 0x02, 0x03, 0x04, 0x04, 0x03,
        0x02, 0x03,
    ];

    let buckets = vec![0x0102030404030201, 0x0202030404030202, 0x0302030404030203];
    let vdaf_config = VdafConfig::get_decoded(&data).unwrap();
    assert_eq!(
        vdaf_config,
        VdafConfig {
            dp_config: DpConfig::None,
            var: VdafTypeVar::Prio3Aes128Histogram { buckets: buckets },
        }
    );
}

#[test]
fn read_task_config_taskprov_draft02() {
    let data = [
        0x02, 0x48, 0x69, 0x00, 0x0e, 0x00, 0x0c, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
        0x74, 0x65, 0x73, 0x74, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80,
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x52, 0xf9,
        0xa5, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x18, 0x01, 0x02, 0x03, 0x04, 0x04, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x02, 0x03, 0x02, 0x03, 0x04, 0x04,
        0x03, 0x02, 0x03,
    ];

    let buckets = vec![0x0102030404030201, 0x0202030404030202, 0x0302030404030203];
    let task_config = TaskConfig::get_decoded_with_param(&TaskprovVersion::Draft02, &data).unwrap();
    assert_eq!(
        task_config,
        TaskConfig {
            task_info: "Hi".as_bytes().to_vec(),
            aggregator_endpoints: vec![UrlBytes {
                bytes: "https://test".as_bytes().to_vec()
            }],
            query_config: QueryConfig {
                time_precision: 0x01,
                max_batch_query_count: 128,
                min_batch_size: 1024,
                var: QueryConfigVar::FixedSize {
                    max_batch_size: 2048
                },
            },
            task_expiration: 0x6352f9a5,
            vdaf_config: VdafConfig {
                dp_config: DpConfig::None,
                var: VdafTypeVar::Prio3Aes128Histogram { buckets: buckets },
            },
        }
    );

    assert_eq!(
        compute_task_id(
            TaskprovVersion::Draft02,
            &task_config.get_encoded_with_param(&TaskprovVersion::Draft02)
        )
        .unwrap()
        .to_hex(),
        "2b585fcbb48c21fb5f05221a241fdd8cb9ebe99bd183d66326fcecd85fe06fd5",
    );

    assert_eq!(
        task_config.get_encoded_with_param(&TaskprovVersion::Draft02),
        &data
    );
}
