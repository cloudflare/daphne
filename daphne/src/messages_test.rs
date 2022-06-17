// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::messages::{
    AggregateReq, AggregateReqVar, AggregateResp, HpkeAeadId, HpkeCiphertext, HpkeConfig,
    HpkeKdfId, HpkeKemId, Id, Nonce, Report, ReportShare, Transition, TransitionVar,
};
use assert_matches::assert_matches;
use prio::codec::{CodecError, Decode, Encode, ParameterizedDecode, ParameterizedEncode};

const TEST_HMAC_KEY_DATA: [u8; 32] = [
    104, 190, 224, 223, 112, 67, 73, 201, 254, 196, 12, 73, 163, 88, 229, 55, 36, 23, 112, 166, 8,
    30, 25, 172, 38, 159, 75, 82, 123, 70, 176, 162,
];

#[test]
fn read_nonce() {
    let data = [
        0, 0, 0, 0, 97, 152, 50, 20, 145, 169, 211, 83, 70, 67, 203, 171,
    ];

    let nonce = Nonce::get_decoded(&data).unwrap();
    assert_eq!(nonce.time, 1637364244);
    assert_eq!(nonce.rand, 10496152761178246059);
}

#[test]
fn read_report() {
    let report = Report {
        task_id: Id([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16,
        ]),
        nonce: Nonce {
            time: 1637364244,
            rand: 10496152761178246059,
        },
        ignored_extensions: b"some extension".to_vec(),
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
    let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &TEST_HMAC_KEY_DATA);

    let mut want = AggregateReq {
        task_id: Id([23; 32]),
        agg_job_id: Id([1; 32]),
        var: AggregateReqVar::Init {
            agg_param: b"this is an aggregation parameter".to_vec(),
            seq: vec![
                ReportShare {
                    nonce: Nonce {
                        time: 1637361337,
                        rand: 10496152761178246059,
                    },
                    ignored_extensions: b"these are extensions".to_vec(),
                    encrypted_input_share: HpkeCiphertext {
                        config_id: 23,
                        enc: b"encapsulated key".to_vec(),
                        payload: b"ciphertext".to_vec(),
                    },
                },
                ReportShare {
                    nonce: Nonce {
                        time: 163736423,
                        rand: 123897432897439,
                    },
                    ignored_extensions: vec![],
                    encrypted_input_share: HpkeCiphertext {
                        config_id: 0,
                        enc: vec![],
                        payload: b"ciphertext".to_vec(),
                    },
                },
            ],
        },
        tag: None,
    };

    let got =
        AggregateReq::get_decoded_with_param(&hmac_key, &want.get_encoded_with_param(&hmac_key))
            .unwrap();
    want.tag = got.tag;
    assert_eq!(got, want);
}

#[test]
fn read_agg_req() {
    let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &TEST_HMAC_KEY_DATA);

    let mut want = AggregateReq {
        task_id: Id([23; 32]),
        agg_job_id: Id([1; 32]),
        var: AggregateReqVar::Continue {
            seq: vec![
                Transition {
                    nonce: Nonce {
                        time: 1637361337,
                        rand: 10496152761178246059,
                    },
                    var: TransitionVar::Continued(b"this is a VDAF-specific message".to_vec()),
                },
                Transition {
                    nonce: Nonce {
                        time: 163736423,
                        rand: 123897432897439,
                    },
                    var: TransitionVar::Continued(
                        b"believe it or not this is *also* a VDAF-specific message".to_vec(),
                    ),
                },
            ],
        },
        tag: None,
    };

    let got =
        AggregateReq::get_decoded_with_param(&hmac_key, &want.get_encoded_with_param(&hmac_key))
            .unwrap();
    want.tag = got.tag;
    assert_eq!(got, want);
}

#[test]
fn read_agg_resp() {
    let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &TEST_HMAC_KEY_DATA);

    let mut want = AggregateResp {
        seq: vec![
            Transition {
                nonce: Nonce {
                    time: 1637361337,
                    rand: 10496152761178246059,
                },
                var: TransitionVar::Continued(b"this is a VDAF-specific message".to_vec()),
            },
            Transition {
                nonce: Nonce {
                    time: 163736423,
                    rand: 123897432897439,
                },
                var: TransitionVar::Continued(
                    b"believe it or not this is *also* a VDAF-specific message".to_vec(),
                ),
            },
        ],
        tag: None,
    };

    let got =
        AggregateResp::get_decoded_with_param(&hmac_key, &want.get_encoded_with_param(&hmac_key))
            .unwrap();
    want.tag = got.tag;
    assert_eq!(got, want);

    // Test various error conditions.
    let data = want.get_encoded_with_param(&hmac_key);
    let mut inauthentic = data.clone();
    inauthentic[data.len() - 1] ^= 255;
    assert_matches!(
        AggregateResp::get_decoded_with_param(&hmac_key, &inauthentic)
            .err()
            .unwrap(),
        CodecError::Other(e) => {
            assert_eq!(&e.to_string(), "hmac");
        }
    );
    assert_matches!(
        AggregateResp::get_decoded_with_param(&hmac_key, &data[..data.len() - 1])
            .err()
            .unwrap(),
        CodecError::Io(..)
    );
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
