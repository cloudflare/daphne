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
    let path = "upload";

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
        path,
        constants::MEDIA_TYPE_REPORT,
        report.get_encoded(),
    )
    .await;

    // Try uploading the same report a second time (expect failure due to repeated nonce).
    t.leader_post_expect_abort(
        &client,
        None, // dap_auth_token
        path,
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
        path,
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
        path,
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
        path,
        constants::MEDIA_TYPE_REPORT,
        b"junk data".to_vec(),
        400,
        "unrecognizedMessage",
    )
    .await;

    // Upload a fixed report. This is a sanity check to make sure that the test resets the Leader's
    // state each time the test is run. If it didn't, this would result in an error due to the
    // nonce being repeated.
    let url = t.leader_url.join(path).unwrap();
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
        max_buckets: 100, // Needs to be sufficiently large to touch each bucket.
        max_reports: t.min_batch_size,
    };

    let batch_interval = t.batch_interval();

    // Upload a number of reports (a few more than the aggregation rate).
    let mut rng = thread_rng();
    for _ in 0..agg_info.max_reports + 3 {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "upload",
            constants::MEDIA_TYPE_REPORT,
            t.vdaf
                .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
                .unwrap()
                .get_encoded(),
        )
        .await;
    }

    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(
        agg_telem.reports_processed,
        agg_info.max_reports + 3,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated,
        agg_info.max_reports + 3,
        "reports aggregated"
    );
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");

    // There should be nothing left to aggregate.
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_processed, 0, "reports processed");
    assert_eq!(agg_telem.reports_aggregated, 0, "reports aggregated");
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");
}

// Test that all reports eventually get drained at minimum aggregation rate.
#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_process_min_agg_rate() {
    let t = TestRunner::default().await;
    let client = t.http_client();
    let batch_interval = t.batch_interval();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..7 {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "upload",
            constants::MEDIA_TYPE_REPORT,
            t.vdaf
                .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
                .unwrap()
                .get_encoded(),
        )
        .await;
    }

    // One bucket and one report/bucket equal an aggregation rate of one report.
    let agg_info = InternalAggregateInfo {
        max_buckets: 1,
        max_reports: 1,
    };

    for i in 0..7 {
        // Each round should process exactly one report.
        let agg_telem = t.internal_process(&client, &agg_info).await;
        assert_eq!(agg_telem.reports_processed, 1, "round {} is empty", i);
    }

    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_processed, 0, "reports processed");
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_ok() {
    let t = TestRunner::default().await;
    let batch_interval = t.batch_interval();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.min_batch_size {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "upload",
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
    assert_eq!(resp.status(), 202, "response: {:?}", resp);

    // The reports are aggregated in the background.
    let agg_telem = t
        .internal_process(
            &client,
            &InternalAggregateInfo {
                max_buckets: 100, // Needs to be sufficiently large to touch each bucket.
                max_reports: 100,
            },
        )
        .await;
    assert_eq!(
        agg_telem.reports_processed, t.min_batch_size,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated, t.min_batch_size,
        "reports aggregated"
    );
    assert_eq!(
        agg_telem.reports_collected, t.min_batch_size,
        "reports collected"
    );

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
            collect_resp.encrypted_agg_shares.clone(),
        )
        .unwrap();
    assert_eq!(agg_res, DapAggregateResult::U128(t.min_batch_size as u128));

    // Poll the collect URI once more. Expect the response to be the same as the first, per HTTP
    // GET semantics.
    let resp = client.get(collect_uri.as_str()).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap(), collect_resp.get_encoded());

    // Check that leader properly rejects late arriving reports.
    let now = rng.gen_range(batch_interval.start..batch_interval.end());
    t.leader_post_expect_abort(
        &client,
        None, // dap_auth_token
        "upload",
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

// Test that collect jobs complete even if the request is issued after all reports for the task
// have been processed.
#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_ok_interleaved() {
    let t = TestRunner::default().await;
    let client = t.http_client();
    let batch_interval = t.batch_interval();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.min_batch_size {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "upload",
            constants::MEDIA_TYPE_REPORT,
            t.vdaf
                .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
                .unwrap()
                .get_encoded(),
        )
        .await;
    }

    let agg_info = InternalAggregateInfo {
        max_buckets: 100, // Needs to be sufficiently large to touch each bucket.
        max_reports: 100,
    };

    // All reports for the task get processed ...
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(
        agg_telem.reports_processed, t.min_batch_size,
        "reports processed"
    );

    // ... then the collect request is issued ...
    let collect_req = CollectReq {
        task_id: t.task_id.clone(),
        batch_interval: batch_interval.clone(),
        agg_param: Vec::new(),
    };
    let _collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded())
        .await;

    // ... then the collect job gets completed.
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(
        agg_telem.reports_collected, t.min_batch_size,
        "reports collected"
    );
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_not_ready_min_batch_size() {
    let t = TestRunner::default().await;
    let batch_interval = t.batch_interval();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    // A number of reports are uploaded, but not enough to meet the minimum batch requirement.
    let mut rng = thread_rng();
    for _ in 0..t.min_batch_size - 1 {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "upload",
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
                max_buckets: 100, // Needs to be sufficiently large to touch each bucket.
                max_reports: 100,
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
            "collect/task/{}/req/{}",
            fake_id.to_base64url(),
            fake_id.to_base64url()
        ))
        .unwrap();
    let resp = client.get(collect_uri).send().await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_accept_max_batch_duration() {
    let t = TestRunner::default().await;
    let client = t.http_client();
    let batch_interval = Interval {
        start: t.now - (t.now % t.min_batch_duration) - t.max_batch_duration / 2,
        duration: t.max_batch_duration,
    };

    // Maximum allowed batch duration.
    let collect_req = CollectReq {
        task_id: t.task_id.clone(),
        batch_interval,
        agg_param: Vec::new(),
    };
    let _collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded())
        .await;
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_abort_invalid_batch_interval() {
    let t = TestRunner::default().await;
    let client = t.http_client();
    let batch_interval = t.batch_interval();
    let path = "collect";

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
        path,
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
        path,
        constants::MEDIA_TYPE_COLLECT_REQ,
        collect_req.get_encoded(),
        400,
        "invalidBatchInterval",
    )
    .await;
}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn e2e_leader_collect_abort_overlapping_batch_interval() {
    let t = TestRunner::default().await;
    let batch_interval = t.batch_interval();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.min_batch_size {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "upload",
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
    let _collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded())
        .await;

    // The reports are aggregated in the background.
    let agg_telem = t
        .internal_process(
            &client,
            &InternalAggregateInfo {
                max_buckets: 100, // Needs to be sufficiently large to touch each bucket.
                max_reports: 100,
            },
        )
        .await;
    assert_eq!(
        agg_telem.reports_processed, t.min_batch_size,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated, t.min_batch_size,
        "reports aggregated"
    );
    assert_eq!(
        agg_telem.reports_collected, t.min_batch_size,
        "reports collected"
    );

    // Send a collect request that overlaps with the previous request.
    //
    // NOTE: Since DURABLE_LEADER_COL_JOB_QUEUE_PUT has a mechanism to reject CollectReq
    // with the EXACT SAME content as previous requests, we need to tweak the request
    // a little bit.
    let collect_req = CollectReq {
        task_id: t.task_id.clone(),
        batch_interval: Interval {
            start: batch_interval.start,
            duration: batch_interval.duration * 2,
        },
        agg_param: Vec::new(),
    };
    t.leader_post_expect_abort(
        &client,
        Some(COLLECTOR_BEARER_TOKEN),
        "collect",
        constants::MEDIA_TYPE_COLLECT_REQ,
        collect_req.get_encoded(),
        400,
        "batchOverlap",
    )
    .await;
}
