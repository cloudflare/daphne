// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::messages::{
    AggregateContinueReq, AggregateInitializeReq, AggregateResp, Extension, HpkeAeadId,
    HpkeCiphertext, HpkeConfig, HpkeKdfId, HpkeKemId, Id, Nonce, Report, ReportMetadata,
    ReportShare, Transition, TransitionVar,
};
use prio::codec::{Decode, Encode};

#[test]
fn read_report() {
    let report = Report {
        task_id: Id([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16,
        ]),
        metadata: ReportMetadata {
            time: 1637364244,
            nonce: Nonce([23; 16]),
            extensions: vec![Extension::Unhandled {
                typ: 0xfff,
                payload: b"some extension".to_vec(),
            }],
        },
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

    assert_eq!(Report::get_decoded(&report.get_encoded()).unwrap(), report);
}

#[test]
fn read_agg_init_req() {
    let want = AggregateInitializeReq {
        task_id: Id([23; 32]),
        agg_job_id: Id([1; 32]),
        agg_param: b"this is an aggregation parameter".to_vec(),
        report_shares: vec![
            ReportShare {
                metadata: ReportMetadata {
                    time: 1637361337,
                    nonce: Nonce([99; 16]),
                    extensions: Vec::default(),
                },
                encrypted_input_share: HpkeCiphertext {
                    config_id: 23,
                    enc: b"encapsulated key".to_vec(),
                    payload: b"ciphertext".to_vec(),
                },
            },
            ReportShare {
                metadata: ReportMetadata {
                    time: 163736423,
                    nonce: Nonce([17; 16]),
                    extensions: Vec::default(),
                },
                encrypted_input_share: HpkeCiphertext {
                    config_id: 0,
                    enc: vec![],
                    payload: b"ciphertext".to_vec(),
                },
            },
        ],
    };

    let got = AggregateInitializeReq::get_decoded(&want.get_encoded()).unwrap();
    assert_eq!(got, want);
}

#[test]
fn read_agg_cont_req() {
    let want = AggregateContinueReq {
        task_id: Id([23; 32]),
        agg_job_id: Id([1; 32]),
        transitions: vec![
            Transition {
                nonce: Nonce([0; 16]),
                var: TransitionVar::Continued(b"this is a VDAF-specific message".to_vec()),
            },
            Transition {
                nonce: Nonce([1; 16]),
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
fn read_agg_resp() {
    let want = AggregateResp {
        transitions: vec![
            Transition {
                nonce: Nonce([22; 16]),
                var: TransitionVar::Continued(b"this is a VDAF-specific message".to_vec()),
            },
            Transition {
                nonce: Nonce([255; 16]),
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
            public_key: b"this is a public key".to_vec(),
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
            public_key: b"this is a public key".to_vec(),
        }
    );
}
