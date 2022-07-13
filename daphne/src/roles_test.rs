// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    auth::BearerToken,
    constants::{MEDIA_TYPE_AGG_INIT_REQ, MEDIA_TYPE_AGG_SHARE_REQ, MEDIA_TYPE_COLLECT_REQ},
    hpke::HpkeReceiverConfig,
    messages::{
        AggregateInitializeReq, AggregateResp, AggregateShareReq, CollectReq, HpkeCiphertext, Id,
        Interval, Nonce, Report, ReportShare, TransitionFailure, TransitionVar,
    },
    roles::{DapAggregator, DapHelper, DapLeader},
    testing::{
        BucketInfo, MockAggregator, ReportStore, HPKE_RECEIVER_CONFIG_LIST, LEADER_BEARER_TOKEN,
    },
    DapAbort, DapMeasurement, DapRequest, Prio3Config, VdafConfig,
};
use assert_matches::assert_matches;
use prio::codec::{Decode, Encode};
use rand::{thread_rng, Rng};
use std::{ops::DerefMut, vec};

fn gen_test_agg_init_req(
    agg: &MockAggregator,
    report_shares: Vec<ReportShare>,
) -> DapRequest<BearerToken> {
    let mut rng = thread_rng();
    let task_id = agg.nominal_task_id();
    let task_config = agg.get_task_config_for(task_id).unwrap();

    DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_INIT_REQ),
        payload: AggregateInitializeReq {
            task_id: task_id.clone(),
            agg_job_id: Id(rng.gen()),
            agg_param: Vec::default(),
            report_shares,
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate").unwrap(),
        sender_auth: None,
    }
}

fn gen_test_agg_share_req(
    agg: &MockAggregator,
    report_count: u64,
    checksum: [u8; 32],
) -> DapRequest<BearerToken> {
    let task_id = agg.nominal_task_id();
    let task_config = agg.get_task_config_for(task_id).unwrap();

    DapRequest {
        media_type: Some(MEDIA_TYPE_AGG_SHARE_REQ),
        payload: AggregateShareReq {
            task_id: task_id.clone(),
            batch_interval: Interval::default(),
            agg_param: Vec::default(),
            report_count,
            checksum,
        }
        .get_encoded(),
        url: task_config.helper_url.join("/aggregate_share").unwrap(),
        sender_auth: None,
    }
}

fn gen_test_collect_req(agg: &MockAggregator) -> DapRequest<BearerToken> {
    let task_id = agg.nominal_task_id();
    let task_config = agg.get_task_config_for(task_id).unwrap();

    DapRequest {
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: CollectReq {
            task_id: task_id.clone(),
            batch_interval: Interval::default(),
            agg_param: Vec::default(),
        }
        .get_encoded(),
        url: task_config.leader_url.join("/collect").unwrap(),
        sender_auth: None,
    }
}

fn gen_test_report(task_id: &Id) -> Report {
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

    report
}

#[tokio::test]
async fn http_post_aggregate_unauthorized_request() {
    let helper = MockAggregator::new();
    let mut req = gen_test_agg_init_req(&helper, Vec::default());

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
    let mut req = gen_test_agg_share_req(&helper, 0, [0; 32]);

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
    let mut req = gen_test_collect_req(&leader);

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
async fn http_post_aggregate_failure_hpke_decrypt_error() {
    let helper = MockAggregator::new();
    let report_shares = vec![ReportShare {
        nonce: Nonce {
            time: 1637361337,
            rand: [1; 16],
        },
        extensions: Vec::default(),
        encrypted_input_share: HpkeCiphertext {
            config_id: 23,
            enc: b"invalid encapsulated key".to_vec(),
            payload: b"invalid ciphertext".to_vec(),
        },
    }];
    let sender_auth = Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string()));
    let mut req = gen_test_agg_init_req(&helper, report_shares);
    req.sender_auth = sender_auth;

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
async fn http_post_aggregate_transition_continue() {
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();

    let report = gen_test_report(task_id);
    let report_shares = vec![ReportShare {
        nonce: report.nonce,
        extensions: report.extensions,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let sender_auth = Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string()));

    let mut req = gen_test_agg_init_req(&helper, report_shares);
    req.sender_auth = sender_auth;

    // Get AggregateResp and then extract the transition data from inside.
    let agg_resp =
        AggregateResp::get_decoded(&helper.http_post_aggregate(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_resp.transitions[0];

    // Expect success due to valid ciphertext.
    assert_matches!(transition.var, TransitionVar::Continued(_));
}

#[tokio::test]
async fn http_post_aggregate_failure_batch_collected() {
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();
    let task_config = helper.get_task_config_for(task_id).unwrap();

    let report = gen_test_report(task_id);
    let report_shares = vec![ReportShare {
        nonce: report.nonce.clone(),
        extensions: report.extensions,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let sender_auth = Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string()));

    let mut req = gen_test_agg_init_req(&helper, report_shares);
    req.sender_auth = sender_auth;

    // This is to ensure that the lock is released before we call http_post_aggregate.
    {
        let mut report_store_mutex_guard = helper.report_store.lock().expect("lock() failed");
        let report_store = report_store_mutex_guard.deref_mut();

        // Create a new instance of report store associated to the bucket_info.
        let bucket_info = BucketInfo::new(task_config, task_id, &report.nonce);
        report_store.insert(bucket_info.clone(), ReportStore::new());

        // Intentionally mark report store as `collected`.
        report_store
            .get_mut(&bucket_info)
            .expect("report_store not found")
            .process_mark_collected();
    }

    // Get AggregateResp and then extract the transition data from inside.
    let agg_resp =
        AggregateResp::get_decoded(&helper.http_post_aggregate(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_resp.transitions[0];

    // Expect failure due to report store marked as collected.
    assert_matches!(
        transition.var,
        TransitionVar::Failed(TransitionFailure::BatchCollected)
    );
}

#[tokio::test]
async fn http_post_aggregate_abort_helper_state_overwritten() {
    let helper = MockAggregator::new();
    let task_id = helper.nominal_task_id();

    let report = gen_test_report(task_id);
    let report_shares = vec![ReportShare {
        nonce: report.nonce.clone(),
        extensions: report.extensions,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let sender_auth = Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string()));

    let mut req = gen_test_agg_init_req(&helper, report_shares);
    req.sender_auth = sender_auth;

    // Send aggregate request.
    let _ = helper.http_post_aggregate(&req).await;

    // Send another aggregate request.
    let res = helper.http_post_aggregate(&req).await;

    // Expect failure due to overwriting existing helper state.
    assert_matches!(res.unwrap_err(), DapAbort::BadRequest(e) =>
        assert_eq!(e, "unexpected message for aggregation job (already exists)")
    );
}
