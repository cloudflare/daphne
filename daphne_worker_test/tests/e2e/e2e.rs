// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! End-to-end tests for daphne.
use super::test_runner::TestRunner;
use daphne::{
    async_test_versions,
    constants::DapMediaType,
    messages::{
        decode_base64url_vec, Base64Encode, BatchSelector, Collection, CollectionReq, Extension,
        HpkeCiphertext, Interval, Query, Report, ReportId, ReportMetadata, TaskId,
    },
    DapAggregateResult, DapAggregationParam, DapMeasurement, DapQueryConfig, DapTaskParameters,
    DapVersion,
};
use daphne_service_utils::http_headers;
use prio::codec::{Encode, ParameterizedDecode, ParameterizedEncode};
use rand::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::{
    cmp::{max, min},
    io::Cursor,
};
use webpki::{EndEntityCert, ECDSA_P256_SHA256};
use x509_parser::pem::Pem;

#[derive(Deserialize)]
struct InternalTestEndpointForTaskResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
}

async fn leader_endpoint_for_task(version: DapVersion, want_prefix: bool) {
    let prefix = if want_prefix {
        format!("/{}", version.as_ref())
    } else {
        String::new()
    };
    let t = TestRunner::default_with_version(version).await;
    let res: InternalTestEndpointForTaskResult = t
        .leader_post_internal(
            format!("{prefix}/internal/test/endpoint_for_task").as_ref(),
            &json!({
                "task_id": "blah blah ignored",
                "role": "leader",
            }),
        )
        .await;
    assert_eq!(
        res.status, "success",
        "response status: {}, error: {:?}",
        res.status, res.error
    );
    let expected = if want_prefix {
        format!("/{}/", version.as_ref())
    } else {
        String::from("/v09/") // Must match DAP_DEFAULT_VERSION
    };
    assert_eq!(res.endpoint.unwrap(), expected);
}

async fn leader_endpoint_for_task_unprefixed(version: DapVersion) {
    leader_endpoint_for_task(version, false).await;
}

async_test_versions! { leader_endpoint_for_task_unprefixed }

async fn leader_endpoint_for_task_prefixed(version: DapVersion) {
    leader_endpoint_for_task(version, true).await;
}

async_test_versions! { leader_endpoint_for_task_prefixed }

async fn helper_endpoint_for_task(version: DapVersion, want_prefix: bool) {
    let prefix = if want_prefix {
        format!("/{}", version.as_ref())
    } else {
        String::new()
    };
    let t = TestRunner::default_with_version(version).await;
    let res: InternalTestEndpointForTaskResult = t
        .helper_post_internal(
            format!("{prefix}/internal/test/endpoint_for_task").as_ref(),
            &json!({
                "task_id": "blah blah ignored",
                "role": "helper",
            }),
        )
        .await;
    assert_eq!(
        res.status, "success",
        "response status: {}, error: {:?}",
        res.status, res.error
    );
    let expected = if want_prefix {
        format!("/{}/", version.as_ref())
    } else {
        String::from("/v09/") // Must match DAP_DEFAULT_VERSION
    };
    assert_eq!(res.endpoint.unwrap(), expected);
}

async fn helper_endpoint_for_task_unprefixed(version: DapVersion) {
    helper_endpoint_for_task(version, false).await;
}

async_test_versions! { helper_endpoint_for_task_unprefixed }

async fn helper_endpoint_for_task_prefixed(version: DapVersion) {
    helper_endpoint_for_task(version, true).await;
}

async_test_versions! { helper_endpoint_for_task_prefixed }

async fn leader_hpke_config(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    t.leader_get_raw_hpke_config(client).await;
}

async_test_versions! { leader_hpke_config }

async fn helper_hpke_config(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    t.helper_get_raw_hpke_config(client).await;
}

async_test_versions! { helper_hpke_config }

async fn hpke_configs_are_cached(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    // Get a set of HPKE configs from leader and helper.
    let hpke_config_list_0 = t.get_hpke_configs(version, client).await;
    // Get another set of HPKE configs from leader and helper.
    let hpke_config_list_1 = t.get_hpke_configs(version, client).await;
    // The leader HPKE configs in the two sets must be the same because we store
    // the HPKE receiver config in KV.
    assert_eq!(hpke_config_list_0[0], hpke_config_list_1[0]);
    // The same holds for the helper HPKE config.
    assert_eq!(hpke_config_list_0[1], hpke_config_list_1[1]);
}

async_test_versions! { hpke_configs_are_cached }

// TODO draft02 cleanup: In draft09, the client is meant to PUT its report, not POST it.
async fn leader_upload(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let mut rng = thread_rng();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await;
    let path = t.upload_path();

    // Generate and upload a report.
    let report = t
        .task_config
        .vdaf
        .produce_report(
            &hpke_config_list,
            t.now,
            &t.task_id,
            DapMeasurement::U64(23),
            version,
        )
        .unwrap();
    t.leader_put_expect_ok(
        client,
        &path,
        DapMediaType::Report,
        None,
        report.get_encoded_with_param(&version).unwrap(),
    )
    .await;

    // Try uploading a report with the incorrect task ID.
    let bad_id = TaskId(rng.gen());
    let bad_path = TestRunner::upload_path_for_task(&bad_id);
    t.leader_put_expect_abort(
        client,
        None, // dap_auth_token
        &bad_path,
        DapMediaType::Report,
        t.task_config
            .vdaf
            .produce_report(
                &hpke_config_list,
                t.now,
                &bad_id,
                DapMeasurement::U64(999),
                version,
            )
            .unwrap()
            .get_encoded_with_param(&version)
            .unwrap(),
        400,
        "unrecognizedTask",
    )
    .await;

    // Try uploading a report for which the leader's share is encrypted under the wrong public key.
    let mut report = t
        .task_config
        .vdaf
        .produce_report(
            &hpke_config_list,
            t.now,
            &t.task_id,
            DapMeasurement::U64(999),
            version,
        )
        .unwrap();
    report.encrypted_input_shares[0].config_id ^= 0xff;
    t.leader_put_expect_abort(
        client,
        None, // dap_auth_token
        &path,
        DapMediaType::Report,
        report.get_encoded_with_param(&version).unwrap(),
        400,
        "reportRejected",
    )
    .await;

    // Try uploading a malformed report.
    t.leader_put_expect_abort(
        client,
        None, // dap_auth_token
        &path,
        DapMediaType::Report,
        b"junk data".to_vec(),
        400,
        "invalidMessage",
    )
    .await;

    // Try uploading a report past the task's expiration date.
    let report = t
        .task_config
        .vdaf
        .produce_report(
            &hpke_config_list,
            t.task_config.expiration, // past the expiration date
            &t.task_id,
            DapMeasurement::U64(23),
            version,
        )
        .unwrap();
    t.leader_put_expect_abort(
        client,
        None, // dap_auth_token
        &path,
        DapMediaType::Report,
        report.get_encoded_with_param(&version).unwrap(),
        400,
        "reportTooLate",
    )
    .await;

    // Upload a fixed report. This is a sanity check to make sure that the test resets the Leader's
    // state each time the test is run. If it didn't, this would result in an error due to the
    // report ID being repeated.
    let url = t.leader_url.join(&path).unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        DapMediaType::Report
            .as_str_for_version(version)
            .unwrap()
            .parse()
            .unwrap(),
    );
    let builder = client.put(url.as_str());
    let resp = builder
        .body(
            Report {
                report_metadata: ReportMetadata {
                    id: ReportId([1; 16]),
                    time: t.now,
                },
                public_share: b"public share".to_vec(),
                encrypted_input_shares: [
                    HpkeCiphertext {
                        config_id: hpke_config_list[0].id,
                        enc: b"encapsulated key".to_vec(),
                        payload: b"ciphertext".to_vec(),
                    },
                    HpkeCiphertext {
                        config_id: hpke_config_list[1].id,
                        enc: b"encapsulated key".to_vec(),
                        payload: b"ciphertext".to_vec(),
                    },
                ],
            }
            .get_encoded_with_param(&version)
            .unwrap(),
        )
        .headers(headers)
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

async_test_versions! { leader_upload }

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn leader_upload_taskprov() {
    let version = DapVersion::Draft09;
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await;

    let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
        version,
        min_batch_size: 10,
        query: DapQueryConfig::TimeInterval,
        leader_url: t.task_config.leader_url.clone(),
        helper_url: t.task_config.helper_url.clone(),
        ..Default::default()
    }
    .to_config_with_taskprov(
        b"cool task".to_vec(),
        t.now,
        &t.taskprov_vdaf_verify_key_init,
        &t.taskprov_collector_hpke_receiver.config,
    )
    .unwrap();

    let report = task_config
        .vdaf
        .produce_report_with_extensions(
            &hpke_config_list,
            t.now,
            &task_id,
            DapMeasurement::U32Vec(vec![1; 10]),
            vec![Extension::Taskprov],
            version,
        )
        .unwrap();
    t.leader_post_expect_ok(
        client,
        &format!("tasks/{}/reports", task_id.to_base64url()),
        DapMediaType::Report,
        Some(&taskprov_advertisement),
        report.get_encoded_with_param(&version).unwrap(),
    )
    .await;

    // Generate and upload a report with the wrong task ID.
    let report = task_config
        .vdaf
        .produce_report_with_extensions(
            &hpke_config_list,
            t.now,
            &task_id,
            DapMeasurement::U32Vec(vec![1; 10]),
            vec![Extension::Taskprov],
            version,
        )
        .unwrap();
    t.leader_post_expect_abort(
        client,
        None,
        // Generate a random ID.
        &format!(
            "tasks/{}/reports",
            TaskId(thread_rng().gen()).to_base64url()
        ),
        DapMediaType::Report,
        Some(&taskprov_advertisement),
        report.get_encoded_with_param(&version).unwrap(),
        400,
        "unrecognizedTask",
    )
    .await;
}

async fn internal_leader_process(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let path = t.upload_path();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await;
    let batch_interval = t.batch_interval();

    // Upload a number of reports (a few more than the aggregation rate).
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size + 3 {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_put_expect_ok(
            client,
            &path,
            DapMediaType::Report,
            None,
            t.task_config
                .vdaf
                .produce_report(
                    &hpke_config_list,
                    now,
                    &t.task_id,
                    DapMeasurement::U64(1),
                    version,
                )
                .unwrap()
                .get_encoded_with_param(&version)
                .unwrap(),
        )
        .await;
    }

    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: DapAggregationParam::Empty.get_encoded().unwrap(),
    };
    let _collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;

    let agg_telem = t.internal_process(client).await;
    assert_eq!(
        agg_telem.reports_processed,
        t.task_config.min_batch_size + 3,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated,
        t.task_config.min_batch_size + 3,
        "reports aggregated"
    );
    assert_eq!(
        agg_telem.reports_collected,
        t.task_config.min_batch_size + 3,
        "reports collected"
    );

    // There should be nothing left to aggregate.
    let agg_telem = t.internal_process(client).await;
    assert_eq!(agg_telem.reports_processed, 0, "reports processed");
    assert_eq!(agg_telem.reports_aggregated, 0, "reports aggregated");
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");
}

async_test_versions! { internal_leader_process }

async fn leader_collect_ok(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await;
    let path = t.upload_path();

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    let mut time_min = u64::MAX;
    let mut time_max = 0u64;
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        time_min = min(time_min, now);
        time_max = max(time_max, now);
        t.leader_put_expect_ok(
            client,
            &path,
            DapMediaType::Report,
            None,
            t.task_config
                .vdaf
                .produce_report(
                    &hpke_config_list,
                    now,
                    &t.task_id,
                    DapMeasurement::U64(1),
                    version,
                )
                .unwrap()
                .get_encoded_with_param(&version)
                .unwrap(),
        )
        .await;
    }

    // Get the collect URI.
    let agg_param = DapAggregationParam::Empty;
    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;
    println!("collect_uri: {collect_uri}");

    // Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 202, "response: {resp:?}");

    // The reports are aggregated in the background.
    let agg_telem = t.internal_process(client).await;
    assert_eq!(
        agg_telem.reports_processed, t.task_config.min_batch_size,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated, t.task_config.min_batch_size,
        "reports aggregated"
    );
    assert_eq!(
        agg_telem.reports_collected, t.task_config.min_batch_size,
        "reports collected"
    );

    // Poll the collect URI.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 200);

    let collection =
        Collection::get_decoded_with_param(&t.version, &resp.bytes().await.unwrap()).unwrap();
    let agg_res = t
        .task_config
        .vdaf
        .consume_encrypted_agg_shares(
            &t.collector_hpke_receiver,
            &t.task_id,
            &BatchSelector::TimeInterval {
                batch_interval: batch_interval.clone(),
            },
            collection.report_count,
            &agg_param,
            collection.encrypted_agg_shares.to_vec(),
            version,
        )
        .await
        .unwrap();
    assert_eq!(
        agg_res,
        DapAggregateResult::U128(u128::from(t.task_config.min_batch_size))
    );

    // Check that the time interval for the reports is correct.
    let interval = &collection.interval;
    let low = t.task_config.quantized_time_lower_bound(time_min);
    let high = t.task_config.quantized_time_upper_bound(time_max);
    assert!(low < high);
    assert_eq!(interval.start, low);
    assert_eq!(interval.duration, high - low);

    // Poll the collect URI once more. Expect the response to be the same as the first, per HTTP
    // GET semantics.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap(),
        collection.get_encoded_with_param(&version).unwrap()
    );

    // NOTE Our Leader doesn't check if a report is stale until it is ready to process it. As such,
    // It won't tell the Client at this point that its report is stale. Delaying this check allows
    // to avoid sharding ReportsProcessed by batch bucket, which is not feasilbe for fixed-size
    // tasks.
    //
    //  let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
    //  t.leader_post_expect_abort(
    //      &client,
    //      None, // dap_auth_token
    //      "upload",
    //      DapMediaType::Report,
    //      t.task_config.vdaf
    //          .produce_report(&hpke_config_list, now, &t.task_id, DapMeasurement::U64(1))
    //          .unwrap()
    //          .get_encoded(),
    //      400,
    //      "staleReport",
    //  )
    //  .await;
}

async_test_versions! { leader_collect_ok }

// Test that collect jobs complete even if the request is issued after all reports for the task
// have been processed.
async fn leader_collect_ok_interleaved(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let batch_interval = t.batch_interval();
    let hpke_config_list = t.get_hpke_configs(version, client).await;
    let path = t.upload_path();

    // The reports are uploaded ...
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_put_expect_ok(
            client,
            &path,
            DapMediaType::Report,
            None,
            t.task_config
                .vdaf
                .produce_report(
                    &hpke_config_list,
                    now,
                    &t.task_id,
                    DapMeasurement::U64(1),
                    version,
                )
                .unwrap()
                .get_encoded_with_param(&version)
                .unwrap(),
        )
        .await;
    }

    // ... the result is requested ...
    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: Vec::new(),
    };
    let _collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;

    // ... then reports are aggregated and the result produced.
    let agg_telem = t.internal_process(client).await;
    assert_eq!(
        agg_telem.reports_processed, t.task_config.min_batch_size,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_collected, t.task_config.min_batch_size,
        "reports collected"
    );
}

async_test_versions! { leader_collect_ok_interleaved }

async fn leader_collect_not_ready_min_batch_size(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await;
    let path = t.upload_path();

    // A number of reports are uploaded, but not enough to meet the minimum batch requirement.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size - 1 {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_put_expect_ok(
            client,
            &path,
            DapMediaType::Report,
            None,
            t.task_config
                .vdaf
                .produce_report(
                    &hpke_config_list,
                    now,
                    &t.task_id,
                    DapMeasurement::U64(1),
                    version,
                )
                .unwrap()
                .get_encoded_with_param(&version)
                .unwrap(),
        )
        .await;
    }

    // Get the collect URI.
    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: Vec::new(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;
    println!("collect_uri: {collect_uri}");

    // The reports are aggregated in the background.
    let agg_telem = t.internal_process(client).await;
    assert_eq!(
        agg_telem.reports_processed,
        t.task_config.min_batch_size - 1
    );
    assert_eq!(
        agg_telem.reports_aggregated,
        t.task_config.min_batch_size - 1
    );
    assert_eq!(agg_telem.reports_collected, 0);

    // Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 202);
}

async_test_versions! { leader_collect_not_ready_min_batch_size }

async fn leader_collect_abort_unknown_request(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();

    // Poll collect URI for an unknown collect request.
    let fake_task_id = TaskId([0; 32]);
    let fake_collection_job_id = TaskId([0; 32]);
    let url_suffix = format!("/tasks/{fake_task_id}/collection_jobs/{fake_collection_job_id}");
    let expected_status = 404;
    let collect_uri = t.leader_url.join(&url_suffix).unwrap();
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), expected_status);
}

async_test_versions! { leader_collect_abort_unknown_request }

async fn leader_collect_accept_global_config_max_batch_duration(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let batch_interval = Interval {
        start: t.task_config.quantized_time_lower_bound(t.now)
            - t.global_config.max_batch_duration / 2,
        duration: t.global_config.max_batch_duration,
    };

    // Maximum allowed batch duration.
    let collect_req = CollectionReq {
        query: Query::TimeInterval { batch_interval },
        agg_param: Vec::new(),
    };
    let _collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;
}

async_test_versions! { leader_collect_accept_global_config_max_batch_duration }

async fn leader_collect_abort_invalid_batch_interval(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let batch_interval = t.batch_interval();
    let path = &TestRunner::collect_path_for_task(&t.task_id);

    // Start of batch interval does not align with time_precision.
    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: Interval {
                start: batch_interval.start + 1,
                duration: batch_interval.duration,
            },
        },
        agg_param: Vec::new(),
    };
    t.leader_put_expect_abort(
        client,
        Some(&t.collector_bearer_token),
        path,
        DapMediaType::CollectReq,
        collect_req.get_encoded_with_param(&t.version).unwrap(),
        400,
        "batchInvalid",
    )
    .await;

    // Batch interval duration does not align wiht min_batch_duration.
    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: Interval {
                start: batch_interval.start,
                duration: batch_interval.duration - 1,
            },
        },
        agg_param: Vec::new(),
    };
    t.leader_put_expect_abort(
        client,
        Some(&t.collector_bearer_token),
        path,
        DapMediaType::CollectReq,
        collect_req.get_encoded_with_param(&t.version).unwrap(),
        400,
        "batchInvalid",
    )
    .await;
}

async_test_versions! { leader_collect_abort_invalid_batch_interval }

async fn leader_collect_abort_overlapping_batch_interval(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await;
    let path = t.upload_path();

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_put_expect_ok(
            client,
            &path,
            DapMediaType::Report,
            None,
            t.task_config
                .vdaf
                .produce_report(
                    &hpke_config_list,
                    now,
                    &t.task_id,
                    DapMeasurement::U64(1),
                    version,
                )
                .unwrap()
                .get_encoded_with_param(&version)
                .unwrap(),
        )
        .await;
    }

    // Get the collect URI.
    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: Vec::new(),
    };
    let _collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;

    // The reports are aggregated in the background.
    let agg_telem = t.internal_process(client).await;
    assert_eq!(
        agg_telem.reports_processed, t.task_config.min_batch_size,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated, t.task_config.min_batch_size,
        "reports aggregated"
    );
    assert_eq!(
        agg_telem.reports_collected, t.task_config.min_batch_size,
        "reports collected"
    );

    // Send a collect request that overlaps with the previous request.
    //
    // NOTE: Since DURABLE_LEADER_COL_JOB_QUEUE_PUT has a mechanism to reject CollectReq
    // with the EXACT SAME content as previous requests, we need to tweak the request
    // a little bit.
    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: Interval {
                start: batch_interval.start,
                duration: batch_interval.duration * 2,
            },
        },
        agg_param: Vec::new(),
    };
    let path = &TestRunner::collect_path_for_task(&t.task_id);
    t.leader_put_expect_abort(
        client,
        Some(&t.collector_bearer_token),
        path,
        DapMediaType::CollectReq,
        collect_req.get_encoded_with_param(&t.version).unwrap(),
        400,
        "batchOverlap",
    )
    .await;
}

async_test_versions! { leader_collect_abort_overlapping_batch_interval }

#[tokio::test]
async fn fixed_size() {
    let version = DapVersion::Draft09;
    let t = TestRunner::fixed_size(version).await;
    let path = t.upload_path();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await;

    // Clients: Upload reports.
    for _ in 0..t.task_config.min_batch_size {
        t.leader_put_expect_ok(
            client,
            &path,
            DapMediaType::Report,
            None,
            t.task_config
                .vdaf
                .produce_report(
                    &hpke_config_list,
                    t.now,
                    &t.task_id,
                    DapMeasurement::U64(1),
                    version,
                )
                .unwrap()
                .get_encoded_with_param(&version)
                .unwrap(),
        )
        .await;
    }

    // Get the oldest, not-yet-collected batch ID.
    let batch_id = t.internal_current_batch(&t.task_id).await;

    // Collector: Get the collect URI.
    let agg_param = DapAggregationParam::Empty;
    let collect_req = CollectionReq {
        query: Query::FixedSizeCurrentBatch,
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;
    println!("collect_uri: {collect_uri}");

    // Collector: Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 202, "response: {resp:?}");

    // Aggregators run processing loop.
    let agg_telem = t.internal_process(client).await;
    assert_eq!(
        agg_telem.reports_processed, t.task_config.min_batch_size,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated, t.task_config.min_batch_size,
        "reports aggregated"
    );
    assert_eq!(
        agg_telem.reports_collected, t.task_config.min_batch_size,
        "reports collected"
    );

    // Collector: Poll the collect URI.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 200);

    let collection =
        Collection::get_decoded_with_param(&t.version, &resp.bytes().await.unwrap()).unwrap();
    let agg_res = t
        .task_config
        .vdaf
        .consume_encrypted_agg_shares(
            &t.collector_hpke_receiver,
            &t.task_id,
            &BatchSelector::FixedSizeByBatchId { batch_id },
            collection.report_count,
            &agg_param,
            collection.encrypted_agg_shares.to_vec(),
            version,
        )
        .await
        .unwrap();
    assert_eq!(
        agg_res,
        DapAggregateResult::U128(u128::from(t.task_config.min_batch_size))
    );

    // Collector: Poll the collect URI once more. Expect the response to be the same as the first,
    // per HTTP GET semantics.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap(),
        collection.get_encoded_with_param(&t.version).unwrap()
    );

    // Clients: Upload reports.
    for _ in 0..2 {
        t.leader_put_expect_ok(
            client,
            &path,
            DapMediaType::Report,
            None,
            t.task_config
                .vdaf
                .produce_report(
                    &hpke_config_list,
                    t.now,
                    &t.task_id,
                    DapMeasurement::U64(1),
                    version,
                )
                .unwrap()
                .get_encoded_with_param(&version)
                .unwrap(),
        )
        .await;
    }

    // Get the oldest, not-yet-collected batch ID. This should be different than the one we got
    // before, since that batch was collected.
    let prev_batch_id = batch_id;
    let batch_id = t.internal_current_batch(&t.task_id).await;
    assert_ne!(batch_id, prev_batch_id);

    // Collector: Get the collect URI.
    let agg_param = DapAggregationParam::Empty;
    let collect_req = CollectionReq {
        query: Query::FixedSizeCurrentBatch,
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;
    println!("collect_uri: {collect_uri}");

    // Aggregators run processing loop.
    let agg_telem = t.internal_process(client).await;
    assert_eq!(agg_telem.reports_processed, 2, "reports processed");
    assert_eq!(agg_telem.reports_aggregated, 2, "reports aggregated");
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");

    // Collector: Try CollectReq with out-dated batch ID.
    t.leader_put_expect_abort(
        client,
        Some(&t.collector_bearer_token),
        &TestRunner::collect_path_for_task(&t.task_id),
        DapMediaType::CollectReq,
        CollectionReq {
            query: Query::FixedSizeByBatchId {
                batch_id: prev_batch_id,
            },
            agg_param: Vec::new(),
        }
        .get_encoded_with_param(&t.version)
        .unwrap(),
        400,
        "batchOverlap",
    )
    .await;
}

async fn leader_collect_taskprov_ok(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await;

    let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
        version,
        min_batch_size: 10,
        query: DapQueryConfig::TimeInterval,
        leader_url: t.task_config.leader_url.clone(),
        helper_url: t.task_config.helper_url.clone(),
        ..Default::default()
    }
    .to_config_with_taskprov(
        b"cool task".to_vec(),
        t.now,
        &t.taskprov_vdaf_verify_key_init,
        &t.taskprov_collector_hpke_receiver.config,
    )
    .unwrap();

    let path = TestRunner::upload_path_for_task(&task_id);

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let extensions = vec![Extension::Taskprov];
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_put_expect_ok(
            client,
            &path,
            DapMediaType::Report,
            Some(&taskprov_advertisement),
            task_config
                .vdaf
                .produce_report_with_extensions(
                    &hpke_config_list,
                    now,
                    &task_id,
                    DapMeasurement::U32Vec(vec![1; 10]),
                    extensions,
                    version,
                )
                .unwrap()
                .get_encoded_with_param(&version)
                .unwrap(),
        )
        .await;
    }

    let agg_param = DapAggregationParam::Empty;

    // Get the collect URI.
    let collect_req = CollectionReq {
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect_using_token(
            client,
            "I-am-the-collector", // DAP_TASKPROV_COLLECTOR_AUTH
            Some(&taskprov_advertisement),
            Some(&task_id),
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;
    println!("collect_uri: {collect_uri}");

    // Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 202, "response: {resp:?}");

    // The reports are aggregated in the background.
    let agg_telem = t.internal_process(client).await;
    assert_eq!(
        agg_telem.reports_processed, task_config.min_batch_size,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated, task_config.min_batch_size,
        "reports aggregated"
    );
    assert_eq!(
        agg_telem.reports_collected, task_config.min_batch_size,
        "reports collected"
    );

    // Poll the collect URI.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 200);

    let collection =
        Collection::get_decoded_with_param(&t.version, &resp.bytes().await.unwrap()).unwrap();
    let agg_res = task_config
        .vdaf
        .consume_encrypted_agg_shares(
            &t.taskprov_collector_hpke_receiver,
            &task_id,
            &BatchSelector::TimeInterval {
                batch_interval: batch_interval.clone(),
            },
            collection.report_count,
            &agg_param,
            collection.encrypted_agg_shares.to_vec(),
            version,
        )
        .await
        .unwrap();
    assert_eq!(
        agg_res,
        DapAggregateResult::U32Vec(vec![10, 10, 10, 10, 10, 10, 10, 10, 10, 10]),
    );

    // Poll the collect URI once more. Expect the response to be the same as the first, per HTTP
    // GET semantics.
    let resp = t.poll_collection_url(client, &collect_uri).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap(),
        collection.get_encoded_with_param(&t.version).unwrap()
    );
}

async_test_versions! { leader_collect_taskprov_ok }

async fn helper_hpke_config_signature(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let url = t.helper_url.join("hpke_config").unwrap();
    let req = t.http_client().get(url.as_str());
    let resp = req.send().await.unwrap();
    let signature = resp
        .headers()
        .get(http_headers::HPKE_SIGNATURE)
        .expect("signature header not present")
        .clone();
    let hpke_config_bytes = resp.bytes().await.unwrap();

    let test_certificate = std::env::var("E2E_TEST_HPKE_SIGNING_CERTIFICATE").unwrap();

    let signature_bytes = decode_base64url_vec(signature.as_bytes()).unwrap();
    let (cert_pem, _bytes_read) = Pem::read(Cursor::new(test_certificate.as_bytes())).unwrap();
    let cert = EndEntityCert::try_from(cert_pem.contents.as_ref()).unwrap();
    cert.verify_signature(
        &ECDSA_P256_SHA256,
        &hpke_config_bytes,
        signature_bytes.as_ref(),
    )
    .unwrap();
}

async_test_versions! { helper_hpke_config_signature }
