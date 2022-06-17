// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! End-to-end tests for daphne.

mod test_runner;

use daphne::{
    constants,
    hpke::HpkeSecretKey,
    messages::{CollectReq, CollectResp, Id, Interval},
    DapAggregateResult, DapMeasurement,
};
use daphne_worker::InternalAggregateInfo;
use prio::codec::{Decode, Encode};
use rand::prelude::*;
use std::time::SystemTime;
use test_runner::{TestRunner, COLLECTOR_HPKE_SECRET_KEY};

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
        .body(hex::decode(TEST_DATA_REPORT_OK).unwrap())
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

// TODO Add tests for the following constants:
//
//  - Leader (resp. Helper) can't decrypt its input share (report gets dropped)
//      - nonce/extension mismatch
//      - unknown HPKE config ID
//      - incorrect public key
//  - Leader skips on init request (no valid reports)
//  - Helper skips on init aggregate request
//  - Input is invalid (report gets dropped)
//  - Helper doesn't recognize the task ID
//  - Helper can't parse (initial) aggregate request
//  - Helper got repeated nonce
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
    let url = t.leader_url.join("/collect").unwrap();
    let resp = client
        .post(url.as_str())
        .body(collect_req.get_encoded())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);

    // Poll the collect URI before the ColleectResp is ready.
    let collect_uri = resp.headers().get("Location").unwrap().to_str().unwrap();
    println!("collect_uri: {}", collect_uri);
    let resp = client.get(collect_uri).send().await.unwrap();
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
    let resp = client.get(collect_uri).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let decrypter: HpkeSecretKey = serde_json::from_str(COLLECTOR_HPKE_SECRET_KEY).unwrap();
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
    let resp = client.get(collect_uri).send().await.unwrap();
    assert_eq!(resp.status(), 400);

    // Check that leader properly rejects late arriving reports.
    let now = rng.gen_range(batch_interval.start..batch_interval.end());
    t.leader_post_expect_abort(
        &client,
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
    let url = t.leader_url.join("/collect").unwrap();
    let resp = client
        .post(url.as_str())
        .body(collect_req.get_encoded())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);

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
    let collect_uri = resp.headers().get("Location").unwrap().to_str().unwrap();
    println!("collect_uri: {}", collect_uri);
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
        "/collect",
        constants::MEDIA_TYPE_COLLECT_REQ,
        collect_req.get_encoded(),
        400,
        "invalidBatchInterval",
    )
    .await;
}

const TEST_DATA_REPORT_OK: &str = "\
f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f0000000061981e6\
0001b75158ac9febd00000326170020d4f619a75d39dcc87d40af0a7eab96a01d19e377c0d54b5a\
eda4b5331a1a1806024cdb4d1495ab8eeeb6c2499840758feec6de23032a199080a597f91a31355\
2cd835a592acbd28b428b2116c7fd80cce65d9e575aacde183fcb12046acf9bb515da9dc78ad326\
71e563b680cac5284b2e75e24af487ac504a271cd4e2ea18c6255ea281dcf6031fdb27f84a4e283\
2b210320919a97114c14c227d970fff6f36c3d9dc181a1ff36eacddb40f710c9c0f8502ebc64baf\
6adc57cbeb14a94f85fc4248dfcd95896cbae9ab6db070225b53e88842d1907b85bcaf4af7060cb\
4e13bf4debdf1fcfd9760e93e6b6edad650e64cf7ae42601e03aa9893ca5b0931b7f3fc70f8abc0\
172e4c94ed55993b85eade6ccb6f24dd9721e662e0bec03c5f7af1d51ad59a56140eba86958a1b0\
e57dcadc82a5680e22a9e8dc4fe5f3aac134dcdfe02d9dc4b35058497242bf3edf3226b50b71e26\
f01895e0502e953edc32efce29fef41db9d84442f6df56ea37ef8978e48c8ec0b872c9498c99742\
f48fbfada4302768851dcda982e9eb7a816b0ca58d2e58425c53f2a90cfb9c8bdecd12f090fcdc2\
d76b9d4406839f0c65f4ce444445025ea064a5c233c18781f7e34b74d1c2e146f5f65c11d315a65\
efc16f294196f13e4cd51e3a25e00f94ab944479ac4c04c17eaac1e516ea36b0962073257f9566b\
9e2643cceeaff2bb6f7166d9513004ccacf278cdade65e5b8a6e7a929b8d614703b56e0928b950a\
f129a9d515d9dd7437cf6d5d668fbfbd7b883fbd24dc7d366aa3ae765a239de56c24d9414486719\
2ceb7a4b3f207c54ad6fb23972b5a31d6b6d10a3664238c3733f4396a00fdfc9038f0b4bb16dbaa\
cfef07673d00e0020e677feeec22f2fb66fd3d32143e3b6e37fe0374ad5ec511d06fee65e42b478\
2000909f7e0d4ff40b85c324531b7773646c0669ac05ee34da63a4ee843872b3da9a3ea241ef46d\
0049439cc78bebde3c981066d81dcb853292daf37a665d09761679a89c83477889e6ffd919ca374\
74ed43e66ac35354a51832027ea2c165c8f86c002fe9d02220cb89ffa35251eaca6fb26287a8e09\
03501a3e7400787de9525161af8abe2eeb1eb59b1d1446c4c98102e89";
