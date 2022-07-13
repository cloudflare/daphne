// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! End-to-end tests for daphne.

mod test_runner;

use daphne::{
    constants,
    hpke::HpkeReceiverConfig,
    messages::{CollectReq, CollectResp, HpkeCiphertext, Id, Interval, Nonce, Report},
    DapAggregateResult, DapMeasurement,
};
use daphne_worker::InternalAggregateInfo;
use prio::codec::{Decode, Encode};
use rand::prelude::*;
use std::time::SystemTime;
use test_runner::{TestRunner, COLLECTOR_BEARER_TOKEN, COLLECTOR_HPKE_RECEIVER_CONFIG};

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_hpke_config() {
    let t = TestRunner::default().await;
    let client = t.http_client();
    t.leader_get_raw_hpke_config(&client).await;
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_helper_hpke_config() {
    let t = TestRunner::default().await;
    let client = t.http_client();
    t.helper_get_raw_hpke_config(&client).await;
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_upload() {
    let t = TestRunner::default().await;
    let mut rng = thread_rng();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    // Generate and upload a report.
    let report = t
        .vdaf
        .produce_report(
            &hpke_config_list,
            t.now,
            &t.task_id,
            DapMeasurement::U64(23),
        )
        .unwrap();
    t.leader_post_expect_ok(
        &client,
        "/upload",
        constants::MEDIA_TYPE_REPORT,
        report.get_encoded(),
    )
    .await;

    // Try uploading the same report a second time (expect failure due to repeated nonce).
    t.leader_post_expect_abort(
        &client,
        None, // dap_auth_token
        "/upload",
        constants::MEDIA_TYPE_REPORT,
        report.get_encoded(),
        400,
        "replayedReport",
    )
    .await;

    // Try uploading a report with the incorrect task ID.
    t.leader_post_expect_abort(
        &client,
        None, // dap_auth_token
        "/upload",
        constants::MEDIA_TYPE_REPORT,
        t.vdaf
            .produce_report(
                &hpke_config_list,
                t.now,
                &Id(rng.gen()),
                DapMeasurement::U64(999),
            )
            .unwrap()
            .get_encoded(),
        400,
        "unrecognizedTask",
    )
    .await;

    // Try uploading a report for which the leader's share is encrypted under the wrong public key.
    let mut report = t
        .vdaf
        .produce_report(
            &hpke_config_list,
            t.now,
            &t.task_id,
            DapMeasurement::U64(999),
        )
        .unwrap();
    report.encrypted_input_shares[0].config_id ^= 0xff;
    t.leader_post_expect_abort(
        &client,
        None, // dap_auth_token
        "/upload",
        constants::MEDIA_TYPE_REPORT,
        report.get_encoded(),
        400,
        "unrecognizedHpkeConfig",
    )
    .await;

    // Try uploading a malformed report.
    t.leader_post_expect_abort(
        &client,
        None, // dap_auth_token
        "/upload",
        constants::MEDIA_TYPE_REPORT,
        b"junk data".to_vec(),
        400,
        "unrecognizedMessage",
    )
    .await;

    // Upload a fixed report. This is a sanity check to make sure that the test resets the Leader's
    // state each time the test is run. If it didn't, this would result in an error due to the
    // nonce being repeated.
    let url = t.leader_url.join("/upload").unwrap();
    let resp = client
        .post(url.as_str())
        .body(
            Report {
                task_id: t.task_id.clone(),
                nonce: Nonce {
                    time: t.now,
                    rand: [1; 16],
                },
                extensions: Vec::default(),
                encrypted_input_shares: vec![
                    HpkeCiphertext {
                        config_id: 23,
                        enc: b"encapsulated key".to_vec(),
                        payload: b"ciphertext".to_vec(),
                    },
                    HpkeCiphertext {
                        config_id: 14,
                        enc: b"encapsulated key".to_vec(),
                        payload: b"ciphertext".to_vec(),
                    },
                ],
            }
            .get_encoded(),
        )
        .send()
        .await
        .expect("request failed");
    assert_eq!(
        200,
        resp.status(),
        "unexpected response status: {:?}",
        resp.text().await.unwrap()
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_internal_leader_process() {
    let t = TestRunner::default().await;

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    let agg_info = InternalAggregateInfo {
        batch_info: t.batch_info(),
        agg_rate: t.min_batch_size,
    };

    let batch_interval = agg_info.batch_info.as_ref().unwrap();

    // Upload a number of reports (a few more than the aggregation rate).
    let mut rng = thread_rng();
    for _ in 0..agg_info.agg_rate + 3 {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "/upload",
            constants::MEDIA_TYPE_REPORT,
            t.vdaf
                .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
                .unwrap()
                .get_encoded(),
        )
        .await;
    }

    // Run an iteration of the processing loop. Expect the number of aggregated reports to match
    // the aggregation rate.
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_aggregated, agg_info.agg_rate);

    // Run a second iteration of the processing loop. Expect the number of aggregated reports to
    // be less than the aggregation rate.
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_aggregated, 3);

    // Run a third iteration of the processing loop. By now the report store has been drained, so
    // no reports should have been aggregated.
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_aggregated, 0);
}

// Test leader processing loop for the current batch window.
//
// WARNING: flaky test: This test assumes the client and aggregators have synchronized clocks. It
// may fail if the current time is close to the end of the current batch window, which is
// determined by the minimum batch interval.
#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_internal_leader_process_current_batch_window() {
    let t = TestRunner::default().await;
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    let agg_info = InternalAggregateInfo {
        batch_info: None,
        agg_rate: 1,
    };

    // Upload a report using the current time.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    t.leader_post_expect_ok(
        &client,
        "/upload",
        constants::MEDIA_TYPE_REPORT,
        t.vdaf
            .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
            .unwrap()
            .get_encoded(),
    )
    .await;

    let agg_telem = t.internal_process(&client, &agg_info).await;
    t.internal_reset(&None).await;
    assert_eq!(agg_telem.reports_aggregated, 1);
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_ok() {
    let t = TestRunner::default().await;
    let batch_info = t.batch_info();
    let batch_interval = batch_info.as_ref().unwrap();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.min_batch_size {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "/upload",
            constants::MEDIA_TYPE_REPORT,
            t.vdaf
                .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
                .unwrap()
                .get_encoded(),
        )
        .await;
    }

    // Get the collect URI.
    let collect_req = CollectReq {
        task_id: t.task_id.clone(),
        batch_interval: batch_interval.clone(),
        agg_param: Vec::new(),
    };
    let collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded())
        .await;
    println!("collect_uri: {}", collect_uri);

    // Poll the collect URI before the ColleectResp is ready.
    let resp = client.get(collect_uri.as_str()).send().await.unwrap();
    assert_eq!(resp.status(), 202);

    // The reports are aggregated in the background.
    let agg_telem = t
        .internal_process(
            &client,
            &InternalAggregateInfo {
                batch_info: batch_info.clone(),
                agg_rate: 100,
            },
        )
        .await;
    assert_eq!(agg_telem.reports_processed, t.min_batch_size);
    assert_eq!(agg_telem.reports_aggregated, t.min_batch_size);
    assert_eq!(agg_telem.reports_collected, t.min_batch_size);

    // Poll the collect URI.
    let resp = client.get(collect_uri.as_str()).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let decrypter: HpkeReceiverConfig =
        serde_json::from_str(COLLECTOR_HPKE_RECEIVER_CONFIG).unwrap();
    let collect_resp = CollectResp::get_decoded(&resp.bytes().await.unwrap()).unwrap();
    let agg_res = t
        .vdaf
        .consume_encrypted_agg_shares(
            &decrypter,
            &t.task_id,
            &batch_interval,
            collect_resp.encrypted_agg_shares,
        )
        .unwrap();
    assert_eq!(agg_res, DapAggregateResult::U128(t.min_batch_size as u128));

    // Poll the collect URI once more. Expect failure because the request has already been
    // processed.
    let resp = client.get(collect_uri.as_str()).send().await.unwrap();
    assert_eq!(resp.status(), 400);

    // Check that leader properly rejects late arriving reports.
    let now = rng.gen_range(batch_interval.start..batch_interval.end());
    t.leader_post_expect_abort(
        &client,
        None, // dap_auth_token
        "/upload",
        constants::MEDIA_TYPE_REPORT,
        t.vdaf
            .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
            .unwrap()
            .get_encoded(),
        400,
        "staleReport",
    )
    .await;
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_not_ready_min_batch_size() {
    let t = TestRunner::default().await;
    let batch_info = t.batch_info();
    let batch_interval = batch_info.as_ref().unwrap();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    // A number of reports are uploaded, but not enough to meet the minimum batch requirement.
    let mut rng = thread_rng();
    for _ in 0..t.min_batch_size - 1 {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "/upload",
            constants::MEDIA_TYPE_REPORT,
            t.vdaf
                .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
                .unwrap()
                .get_encoded(),
        )
        .await;
    }

    // Get the collect URI.
    let collect_req = CollectReq {
        task_id: t.task_id.clone(),
        batch_interval: batch_interval.clone(),
        agg_param: Vec::new(),
    };
    let collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded())
        .await;
    println!("collect_uri: {}", collect_uri);

    // The reports are aggregated in the background.
    let agg_telem = t
        .internal_process(
            &client,
            &InternalAggregateInfo {
                batch_info,
                agg_rate: 100,
            },
        )
        .await;
    assert_eq!(agg_telem.reports_processed, t.min_batch_size - 1);
    assert_eq!(agg_telem.reports_aggregated, t.min_batch_size - 1);
    assert_eq!(agg_telem.reports_collected, 0);

    // Poll the collect URI before the ColleectResp is ready.
    let resp = client.get(collect_uri).send().await.unwrap();
    assert_eq!(resp.status(), 202);
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_abort_unknown_request() {
    let t = TestRunner::default().await;
    let client = t.http_client();

    // Poll collect URI for an unknown collect request.
    let fake_id = Id([0; 32]);
    let collect_uri = t
        .leader_url
        .join(&format!(
            "/collect/task/{}/req/{}",
            fake_id.to_base64url(),
            fake_id.to_base64url()
        ))
        .unwrap();
    let resp = client.get(collect_uri).send().await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_abort_invalid_batch_interval() {
    let t = TestRunner::default().await;
    let client = t.http_client();
    let batch_interval = t.batch_info().unwrap();

    // Start of batch interval does not align with min_batch_duration.
    let collect_req = CollectReq {
        task_id: t.task_id.clone(),
        batch_interval: Interval {
            start: batch_interval.start + 1,
            duration: batch_interval.duration,
        },
        agg_param: Vec::new(),
    };
    t.leader_post_expect_abort(
        &client,
        Some(COLLECTOR_BEARER_TOKEN),
        "/collect",
        constants::MEDIA_TYPE_COLLECT_REQ,
        collect_req.get_encoded(),
        400,
        "invalidBatchInterval",
    )
    .await;

    // Batch interval duration does not align wiht min_batch_duration.
    let collect_req = CollectReq {
        task_id: t.task_id.clone(),
        batch_interval: Interval {
            start: batch_interval.start,
            duration: batch_interval.duration - 1,
        },
        agg_param: Vec::new(),
    };
    t.leader_post_expect_abort(
        &client,
        Some(COLLECTOR_BEARER_TOKEN),
        "/collect",
        constants::MEDIA_TYPE_COLLECT_REQ,
        collect_req.get_encoded(),
        400,
        "invalidBatchInterval",
    )
    .await;
}
