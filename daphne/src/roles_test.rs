// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    auth::BearerToken,
    constants::{MEDIA_TYPE_AGG_INIT_REQ, MEDIA_TYPE_AGG_SHARE_REQ, MEDIA_TYPE_COLLECT_REQ},
    hpke::{HpkeDecrypter, HpkeReceiverConfig},
    messages::{
        AggregateInitializeReq, AggregateResp, AggregateShareReq, CollectReq, HpkeCiphertext, Id,
        Interval, Nonce, Report, ReportShare, TransitionFailure, TransitionVar,
    },
    roles::{DapAggregator, DapHelper, DapLeader},
    testing::{MockAggregator, HPKE_RECEIVER_CONFIG_LIST, LEADER_BEARER_TOKEN},
    DapAbort, DapError, DapMeasurement, DapRequest, Prio3Config, VdafConfig,
};
use assert_matches::assert_matches;
use prio::codec::{Decode, Encode};
use rand::prelude::*;
use std::vec;

#[tokio::test]
async fn http_post_aggregate_unauthorized_request() {
    let mut rng = thread_rng();
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();
    let task_config = helper.get_task_config_for(task_id).unwrap();

    let mut req = DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_INIT_REQ),
        payload: AggregateInitializeReq {
            task_id: task_id.clone(),
            agg_job_id: Id(rng.gen()),
            agg_param: Vec::default(),
            report_shares: Vec::default(),
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate").unwrap(),
        sender_auth: None,
    };

    // Expect failure due to missing bearer token.
    assert_matches!(
        helper.http_post_aggregate(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        helper.http_post_aggregate(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_post_aggregate_share_unauthorized_request() {
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();
    let task_config = helper.get_task_config_for(task_id).unwrap();

    let mut req = DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_SHARE_REQ),
        payload: AggregateShareReq {
            task_id: task_id.clone(),
            batch_interval: Interval::default(),
            agg_param: Vec::default(),
            report_count: 0,
            checksum: [0; 32],
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate_share").unwrap(),
        sender_auth: None,
    };

    // Expect failure due to missing bearer token.
    assert_matches!(
        helper.http_post_aggregate_share(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        helper.http_post_aggregate_share(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_post_collect_unauthorized_request() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();

    let mut req = DapRequest {
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: CollectReq {
            task_id: task_id.clone(),
            batch_interval: Interval::default(),
            agg_param: Vec::default(),
        }
        .get_encoded(),
        url: task_config.leader_url.join("/collect").unwrap(),
        sender_auth: None,
    };

    // Expect failure due to missing bearer token.
    assert_matches!(
        leader.http_post_collect(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        leader.http_post_collect(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_post_aggregate_invalid_ciphertext() {
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();
    let task_config = helper.get_task_config_for(task_id).unwrap();

    let req = DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_INIT_REQ),
        payload: AggregateInitializeReq {
            task_id: task_id.clone(),
            agg_job_id: Id([1; 32]),
            agg_param: b"this is an aggregation parameter".to_vec(),
            report_shares: vec![ReportShare {
                nonce: Nonce {
                    time: 1637361337,
                    rand: 10496152761178246059,
                },
                ignored_extensions: b"these are extensions".to_vec(),
                encrypted_input_share: HpkeCiphertext {
                    config_id: 23,
                    enc: b"invalid encapsulated key".to_vec(),
                    payload: b"invalid ciphertext".to_vec(),
                },
            }],
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate").unwrap(),
        sender_auth: Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string())),
    };

    // Get AggregateResp and then extract the transition data from inside.
    let agg_resp =
        AggregateResp::get_decoded(&helper.http_post_aggregate(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_resp.transitions[0];

    // Expect failure due to invalid ciphertext.
    assert_matches!(
        transition.var,
        TransitionVar::Failed(TransitionFailure::HpkeDecryptError)
    );
}

#[tokio::test]
async fn http_post_aggregate_valid_ciphertext() {
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();
    let task_config = helper.get_task_config_for(task_id).unwrap();

    // Construct HPKE receiver config List.
    let hpke_receiver_config_list: Vec<HpkeReceiverConfig> =
        serde_json::from_str(HPKE_RECEIVER_CONFIG_LIST)
            .expect("failed to parse hpke_receiver_config_list");

    // Construct HPKE config list.
    let mut hpke_config_list = Vec::with_capacity(hpke_receiver_config_list.len());
    for receiver_config in hpke_receiver_config_list {
        hpke_config_list.push(receiver_config.config);
    }

    // Construct report.
    let vdaf_config: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Count);
    let report = vdaf_config
        .produce_report(
            &hpke_config_list,
            1637361337,
            task_id,
            DapMeasurement::U64(1),
        )
        .unwrap();

    // Construct DapRequest.
    let req = DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_INIT_REQ),
        payload: AggregateInitializeReq {
            task_id: task_id.clone(),
            agg_job_id: Id([1; 32]),
            agg_param: b"this is an aggregation parameter".to_vec(),
            report_shares: vec![ReportShare {
                nonce: report.nonce,
                ignored_extensions: report.ignored_extensions,
                // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
                encrypted_input_share: report.encrypted_input_shares[1].clone(),
            }],
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate").unwrap(),
        sender_auth: Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string())),
    };

    // Get AggregateResp and then extract the transition data from inside.
    let agg_resp =
        AggregateResp::get_decoded(&helper.http_post_aggregate(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_resp.transitions[0];

    // Expect success due to valid ciphertext.
    assert_matches!(transition.var, TransitionVar::Continued(_));
}

#[test]
fn hpke_decrypter() {
    // Construct mock aggregator.
    let aggregator = MockAggregator::new();
    let task_id = aggregator.nominal_task_id();

    // Initialize variables for mock report.
    let info = b"info string";
    let aad = b"associated data";
    let plaintext = b"plaintext";
    let hpke_receiver_config_list: Vec<HpkeReceiverConfig> =
        serde_json::from_str(HPKE_RECEIVER_CONFIG_LIST)
            .expect("failed to parse hpke_receiver_config_list");
    let config = &hpke_receiver_config_list[0].config;
    let (enc, ciphertext) = config.encrypt(info, aad, plaintext).unwrap();

    // Construct mock report.
    let report = Report {
        task_id: Id([23; 32]),
        nonce: Nonce {
            time: 1637364244,
            rand: 10496152761178246059,
        },
        ignored_extensions: b"some extension".to_vec(),
        encrypted_input_shares: vec![HpkeCiphertext {
            config_id: 23,
            enc: enc,
            payload: ciphertext,
        }],
    };

    // Expect false due to non-existing config ID.
    assert_eq!(aggregator.can_hpke_decrypt(&task_id, 0), false);

    // Expect true due to existing config ID.
    assert_eq!(
        aggregator.can_hpke_decrypt(&task_id, report.encrypted_input_shares[0].config_id),
        true
    );

    // Expect decryption to fail.
    assert_matches!(
        aggregator.hpke_decrypt(
            &report.task_id,
            info,
            aad,
            &HpkeCiphertext {
                config_id: 0,
                enc: vec![],
                payload: b"ciphertext".to_vec(),
            }
        ),
        Err(DapError::Transition(TransitionFailure::HpkeUnknownConfigId))
    );

    // Expect decryption to succeed.
    assert_eq!(
        aggregator
            .hpke_decrypt(
                &report.task_id,
                info,
                aad,
                &report.encrypted_input_shares[0]
            )
            .unwrap(),
        plaintext
    );
}
