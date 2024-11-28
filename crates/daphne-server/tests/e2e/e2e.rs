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
    DapAggregateResult, DapAggregationParam, DapBatchMode, DapMeasurement, DapTaskParameters,
    DapVersion,
};
use daphne_service_utils::http_headers;
use http::Method;
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
        .await
        .unwrap();
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
        .await
        .unwrap();
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
    t.leader_get_raw_hpke_config(client).await.unwrap();
}

async_test_versions! { leader_hpke_config }

async fn helper_hpke_config(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    t.helper_get_raw_hpke_config(client).await.unwrap();
}

async_test_versions! { helper_hpke_config }

async fn hpke_configs_are_cached(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    // Get a set of HPKE configs from leader and helper.
    let hpke_config_list_0 = t.get_hpke_configs(version, client).await.unwrap();
    // Get another set of HPKE configs from leader and helper.
    let hpke_config_list_1 = t.get_hpke_configs(version, client).await.unwrap();
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
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let path = t.upload_path();
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };

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
    t.leader_request_expect_ok(
        client,
        &path,
        method,
        DapMediaType::Report,
        None,
        report.get_encoded_with_param(&version).unwrap(),
    )
    .await
    .unwrap();

    // Try uploading a report with the incorrect task ID.
    let bad_id = TaskId(rng.gen());
    let bad_path = TestRunner::upload_path_for_task(&bad_id);
    t.leader_request_expect_abort(
        client,
        None, // dap_auth_token
        &bad_path,
        method,
        DapMediaType::Report,
        None,
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
    .await
    .unwrap();

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
    t.leader_request_expect_abort(
        client,
        None, // dap_auth_token
        &path,
        method,
        DapMediaType::Report,
        None,
        report.get_encoded_with_param(&version).unwrap(),
        400,
        "reportRejected",
    )
    .await
    .unwrap();

    // Try uploading a malformed report.
    t.leader_request_expect_abort(
        client,
        None, // dap_auth_token
        &path,
        method,
        DapMediaType::Report,
        None,
        b"junk data".to_vec(),
        400,
        "invalidMessage",
    )
    .await
    .unwrap();

    // Try uploading a report past the task's expiration date.
    let report = t
        .task_config
        .vdaf
        .produce_report(
            &hpke_config_list,
            t.task_config.not_after, // past the expiration date
            &t.task_id,
            DapMeasurement::U64(23),
            version,
        )
        .unwrap();
    t.leader_request_expect_abort(
        client,
        None, // dap_auth_token
        &path,
        method,
        DapMediaType::Report,
        None,
        report.get_encoded_with_param(&version).unwrap(),
        400,
        "reportTooLate",
    )
    .await
    .unwrap();

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
    let builder = client.request(method.clone(), url.as_str());
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

async fn leader_back_compat_upload(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let path = t.upload_path();
    let method = match version {
        DapVersion::Draft09 => &Method::POST,
        DapVersion::Latest => &Method::PUT,
    };

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
    let builder = client.request(method.clone(), url.as_str());
    let resp = builder
        .body(report.get_encoded_with_param(&version).unwrap())
        .headers(headers)
        .send()
        .await
        .unwrap_or_else(|_| panic!("route not implemented for version {version}"));
    assert_eq!(
        405,
        resp.status(),
        "unexpected response status: {:?}",
        resp.text().await.unwrap()
    );
}

async_test_versions! {leader_back_compat_upload}

#[tokio::test]
#[cfg_attr(not(feature = "test_e2e"), ignore)]
async fn leader_upload_taskprov() {
    let version = DapVersion::Draft09;
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();

    let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
        version,
        min_batch_size: 10,
        query: DapBatchMode::TimeInterval,
        leader_url: t.task_config.leader_url.clone(),
        helper_url: t.task_config.helper_url.clone(),
        ..Default::default()
    }
    .to_config_with_taskprov(
        b"cool task".to_vec(),
        t.now,
        daphne::roles::aggregator::TaskprovConfig {
            hpke_collector_config: &t.taskprov_collector_hpke_receiver.config,
            vdaf_verify_key_init: &t.taskprov_vdaf_verify_key_init,
        },
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
    t.leader_request_expect_ok(
        client,
        &format!("tasks/{}/reports", task_id.to_base64url()),
        &http::Method::PUT,
        DapMediaType::Report,
        Some(
            &taskprov_advertisement
                .serialize_to_header_value(version)
                .unwrap(),
        ),
        report.get_encoded_with_param(&version).unwrap(),
    )
    .await
    .unwrap();

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
    t.leader_request_expect_abort(
        client,
        None,
        // Generate a random ID.
        &format!(
            "tasks/{}/reports",
            TaskId(thread_rng().gen()).to_base64url()
        ),
        &http::Method::PUT,
        DapMediaType::Report,
        Some(
            &taskprov_advertisement
                .serialize_to_header_value(version)
                .unwrap(),
        ),
        report.get_encoded_with_param(&version).unwrap(),
        400,
        "unrecognizedTask",
    )
    .await
    .unwrap();
}

async fn leader_upload_taskprov_wrong_version(version: DapVersion) {
    let wrong_version = match version {
        DapVersion::Draft09 => DapVersion::Latest,
        DapVersion::Latest => DapVersion::Draft09,
    };
    let method = match version {
        DapVersion::Draft09 => &http::Method::PUT,
        DapVersion::Latest => &http::Method::POST,
    };
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();

    let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
        version,
        min_batch_size: 10,
        query: DapBatchMode::TimeInterval,
        leader_url: t.task_config.leader_url.clone(),
        helper_url: t.task_config.helper_url.clone(),
        ..Default::default()
    }
    .to_config_with_taskprov(
        b"cool task".to_vec(),
        t.now,
        daphne::roles::aggregator::TaskprovConfig {
            hpke_collector_config: &t.taskprov_collector_hpke_receiver.config,
            vdaf_verify_key_init: &t.taskprov_vdaf_verify_key_init,
        },
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
    t.leader_request_expect_abort(
        client,
        None,
        &format!("tasks/{}/reports", task_id.to_base64url()),
        method,
        DapMediaType::Report,
        Some(
            &taskprov_advertisement
                .serialize_to_header_value(wrong_version)
                .unwrap(),
        ),
        report.get_encoded_with_param(&version).unwrap(),
        400,
        "unrecognizedTask",
    )
    .await
    .unwrap();
}

async_test_versions!(leader_upload_taskprov_wrong_version);

async fn internal_leader_process(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let path = t.upload_path();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let batch_interval = t.batch_interval();
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };

    // Upload a number of reports (a few more than the aggregation rate).
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size + 3 {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_request_expect_ok(
            client,
            &path,
            method,
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
        .await
        .unwrap();
    }

    let collect_req = CollectionReq {
        query: Query::TimeInterval { batch_interval },
        agg_param: DapAggregationParam::Empty.get_encoded().unwrap(),
    };
    let _collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await;

    let agg_telem = t.internal_process(client).await.unwrap();
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
    let agg_telem = t.internal_process(client).await.unwrap();
    assert_eq!(agg_telem.reports_processed, 0, "reports processed");
    assert_eq!(agg_telem.reports_aggregated, 0, "reports aggregated");
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");
}

async_test_versions! { internal_leader_process }

async fn leader_collect_ok(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let path = t.upload_path();
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    let mut time_min = u64::MAX;
    let mut time_max = 0u64;
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        time_min = min(time_min, now);
        time_max = max(time_max, now);
        t.leader_request_expect_ok(
            client,
            &path,
            method,
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
        .await
        .unwrap();
    }

    // Get the collect URI.
    let agg_param = DapAggregationParam::Empty;
    let collect_req = CollectionReq {
        query: Query::TimeInterval { batch_interval },
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await
        .unwrap();
    println!("collect_uri: {collect_uri}");

    // Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(client, &collect_uri).await.unwrap();
    assert_eq!(resp.status(), 202, "response: {resp:?}");

    // The reports are aggregated in the background.
    let agg_telem = t.internal_process(client).await.unwrap();
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
    let resp = t.poll_collection_url(client, &collect_uri).await.unwrap();
    assert_eq!(resp.status(), 200);

    let collection =
        Collection::get_decoded_with_param(&t.version, &resp.bytes().await.unwrap()).unwrap();
    let agg_res = t
        .task_config
        .vdaf
        .consume_encrypted_agg_shares(
            &t.collector_hpke_receiver,
            &t.task_id,
            &BatchSelector::TimeInterval { batch_interval },
            collection.report_count,
            &agg_param,
            collection.encrypted_agg_shares.to_vec(),
            version,
        )
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
    let resp = t.poll_collection_url(client, &collect_uri).await.unwrap();
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
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let path = t.upload_path();
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };

    // The reports are uploaded ...
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_request_expect_ok(
            client,
            &path,
            method,
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
        .await
        .unwrap();
    }

    // ... the result is requested ...
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

    // ... then reports are aggregated and the result produced.
    let agg_telem = t.internal_process(client).await.unwrap();
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
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let path = t.upload_path();
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };

    // A number of reports are uploaded, but not enough to meet the minimum batch requirement.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size - 1 {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_request_expect_ok(
            client,
            &path,
            method,
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
        .await
        .unwrap();
    }

    // Get the collect URI.
    let collect_req = CollectionReq {
        query: Query::TimeInterval { batch_interval },
        agg_param: Vec::new(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await
        .unwrap();
    println!("collect_uri: {collect_uri}");

    // The reports are aggregated in the background.
    let agg_telem = t.internal_process(client).await.unwrap();
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
    let resp = t.poll_collection_url(client, &collect_uri).await.unwrap();
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
    let resp = t.poll_collection_url(client, &collect_uri).await.unwrap();
    assert_eq!(resp.status(), expected_status);
}

async_test_versions! { leader_collect_abort_unknown_request }

async fn leader_collect_back_compat(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let path = t.upload_path();
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };
    let expected_status = 405;

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    let mut time_min = u64::MAX;
    let mut time_max = 0u64;
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        time_min = min(time_min, now);
        time_max = max(time_max, now);
        t.leader_request_expect_ok(
            client,
            &path,
            method,
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
        .await
        .unwrap();
    }

    // Get the collect URI.
    let agg_param = DapAggregationParam::Empty;
    let collect_req = CollectionReq {
        query: Query::TimeInterval { batch_interval },
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await
        .unwrap();
    println!("collect_uri: {collect_uri}");

    let builder = match version {
        DapVersion::Draft09 => client.get(collect_uri.as_str()),
        DapVersion::Latest => client.post(collect_uri.as_str()),
    };
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static(http_headers::DAP_AUTH_TOKEN),
        reqwest::header::HeaderValue::from_str(&t.collector_bearer_token)
            .expect("couldn't parse bearer token"),
    );
    let resp = builder
        .headers(headers)
        .send()
        .await
        .expect("failed to get a response");

    assert_eq!(resp.status(), expected_status);
}

async_test_versions! { leader_collect_back_compat }

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
    t.leader_request_expect_abort(
        client,
        Some(&t.collector_bearer_token),
        path,
        &http::Method::PUT,
        DapMediaType::CollectionReq,
        None,
        collect_req.get_encoded_with_param(&t.version).unwrap(),
        400,
        "batchInvalid",
    )
    .await
    .unwrap();

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
    t.leader_request_expect_abort(
        client,
        Some(&t.collector_bearer_token),
        path,
        &http::Method::PUT,
        DapMediaType::CollectionReq,
        None,
        collect_req.get_encoded_with_param(&t.version).unwrap(),
        400,
        "batchInvalid",
    )
    .await
    .unwrap();
}

async_test_versions! { leader_collect_abort_invalid_batch_interval }

async fn leader_collect_abort_overlapping_batch_interval(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let path = t.upload_path();
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_request_expect_ok(
            client,
            &path,
            method,
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
        .await
        .unwrap();
    }

    // Get the collect URI.
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

    // The reports are aggregated in the background.
    let agg_telem = t.internal_process(client).await.unwrap();
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
    t.leader_request_expect_abort(
        client,
        Some(&t.collector_bearer_token),
        path,
        &http::Method::PUT,
        DapMediaType::CollectionReq,
        None,
        collect_req.get_encoded_with_param(&t.version).unwrap(),
        400,
        "batchOverlap",
    )
    .await
    .unwrap();
}

async_test_versions! { leader_collect_abort_overlapping_batch_interval }

#[tokio::test]
async fn leader_selected() {
    let version = DapVersion::Draft09;
    let t = TestRunner::leader_selected(version).await;
    let path = t.upload_path();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };

    // Clients: Upload reports.
    for _ in 0..t.task_config.min_batch_size {
        t.leader_request_expect_ok(
            client,
            &path,
            method,
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
        .await
        .unwrap();
    }

    // Get the oldest, not-yet-collected batch ID.
    let batch_id = t.internal_current_batch(&t.task_id).await.unwrap();

    // Collector: Get the collect URI.
    let agg_param = DapAggregationParam::Empty;
    let collect_req = CollectionReq {
        query: Query::LeaderSelectedCurrentBatch,
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await
        .unwrap();
    println!("collect_uri: {collect_uri}");

    // Collector: Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(client, &collect_uri).await.unwrap();
    assert_eq!(resp.status(), 202, "response: {resp:?}");

    // Aggregators run processing loop.
    let agg_telem = t.internal_process(client).await.unwrap();
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
    let resp = t.poll_collection_url(client, &collect_uri).await.unwrap();
    assert_eq!(resp.status(), 200);

    let collection =
        Collection::get_decoded_with_param(&t.version, &resp.bytes().await.unwrap()).unwrap();
    let agg_res = t
        .task_config
        .vdaf
        .consume_encrypted_agg_shares(
            &t.collector_hpke_receiver,
            &t.task_id,
            &BatchSelector::LeaderSelectedByBatchId { batch_id },
            collection.report_count,
            &agg_param,
            collection.encrypted_agg_shares.to_vec(),
            version,
        )
        .unwrap();
    assert_eq!(
        agg_res,
        DapAggregateResult::U128(u128::from(t.task_config.min_batch_size))
    );

    // Collector: Poll the collect URI once more. Expect the response to be the same as the first,
    // per HTTP GET semantics.
    let resp = t.poll_collection_url(client, &collect_uri).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap(),
        collection.get_encoded_with_param(&t.version).unwrap()
    );

    // Clients: Upload reports.
    for _ in 0..2 {
        t.leader_request_expect_ok(
            client,
            &path,
            method,
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
        .await
        .unwrap();
    }

    // Get the oldest, not-yet-collected batch ID. This should be different than the one we got
    // before, since that batch was collected.
    let prev_batch_id = batch_id;
    let batch_id = t.internal_current_batch(&t.task_id).await.unwrap();
    assert_ne!(batch_id, prev_batch_id);

    // Collector: Get the collect URI.
    let agg_param = DapAggregationParam::Empty;
    let collect_req = CollectionReq {
        query: Query::LeaderSelectedCurrentBatch,
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect(
            client,
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await
        .unwrap();
    println!("collect_uri: {collect_uri}");

    // Aggregators run processing loop.
    let agg_telem = t.internal_process(client).await.unwrap();
    assert_eq!(agg_telem.reports_processed, 2, "reports processed");
    assert_eq!(agg_telem.reports_aggregated, 2, "reports aggregated");
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");

    // Collector: Try CollectReq with out-dated batch ID.
    t.leader_request_expect_abort(
        client,
        Some(&t.collector_bearer_token),
        &TestRunner::collect_path_for_task(&t.task_id),
        &http::Method::PUT,
        DapMediaType::CollectionReq,
        None,
        CollectionReq {
            query: Query::LeaderSelectedByBatchId {
                batch_id: prev_batch_id,
            },
            agg_param: Vec::new(),
        }
        .get_encoded_with_param(&t.version)
        .unwrap(),
        400,
        "batchOverlap",
    )
    .await
    .unwrap();
}

async fn leader_collect_taskprov_ok(version: DapVersion) {
    const DAP_TASKPROV_COLLECTOR_TOKEN: &str = "I-am-the-collector";
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, client).await.unwrap();

    let (task_config, task_id, taskprov_advertisement) = DapTaskParameters {
        version,
        min_batch_size: 10,
        query: DapBatchMode::TimeInterval,
        leader_url: t.task_config.leader_url.clone(),
        helper_url: t.task_config.helper_url.clone(),
        ..Default::default()
    }
    .to_config_with_taskprov(
        b"cool task".to_vec(),
        t.now,
        daphne::roles::aggregator::TaskprovConfig {
            hpke_collector_config: &t.taskprov_collector_hpke_receiver.config,
            vdaf_verify_key_init: &t.taskprov_vdaf_verify_key_init,
        },
    )
    .unwrap();

    let path = TestRunner::upload_path_for_task(&task_id);
    let method = match version {
        DapVersion::Draft09 => &Method::PUT,
        DapVersion::Latest => &Method::POST,
    };

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let extensions = vec![Extension::Taskprov];
        let now = rng.gen_range(TestRunner::report_interval(&batch_interval));
        t.leader_request_expect_ok(
            client,
            &path,
            method,
            DapMediaType::Report,
            Some(
                &taskprov_advertisement
                    .serialize_to_header_value(version)
                    .unwrap(),
            ),
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
        .await
        .unwrap();
    }

    let agg_param = DapAggregationParam::Empty;

    // Get the collect URI.
    let collect_req = CollectionReq {
        query: Query::TimeInterval { batch_interval },
        agg_param: agg_param.get_encoded().unwrap(),
    };
    let collect_uri = t
        .leader_post_collect_using_token(
            client,
            DAP_TASKPROV_COLLECTOR_TOKEN,
            Some(&taskprov_advertisement),
            Some(&task_id),
            collect_req.get_encoded_with_param(&t.version).unwrap(),
        )
        .await
        .unwrap();
    println!("collect_uri: {collect_uri}");

    // Poll the collect URI before the CollectResp is ready.
    let resp = t
        .poll_collection_url_using_token(client, &collect_uri, DAP_TASKPROV_COLLECTOR_TOKEN)
        .await
        .unwrap();
    #[expect(clippy::format_in_format_args)]
    {
        assert_eq!(
            resp.status(),
            202,
            "response: {} {}",
            format!("{resp:?}"),
            resp.text().await.unwrap()
        );
    }

    // The reports are aggregated in the background.
    let agg_telem = t.internal_process(client).await.unwrap();
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
    let resp = t
        .poll_collection_url_using_token(client, &collect_uri, DAP_TASKPROV_COLLECTOR_TOKEN)
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let collection =
        Collection::get_decoded_with_param(&t.version, &resp.bytes().await.unwrap()).unwrap();
    let agg_res = task_config
        .vdaf
        .consume_encrypted_agg_shares(
            &t.taskprov_collector_hpke_receiver,
            &task_id,
            &BatchSelector::TimeInterval { batch_interval },
            collection.report_count,
            &agg_param,
            collection.encrypted_agg_shares.to_vec(),
            version,
        )
        .unwrap();
    assert_eq!(
        agg_res,
        DapAggregateResult::U32Vec(vec![10, 10, 10, 10, 10, 10, 10, 10, 10, 10]),
    );

    // Poll the collect URI once more. Expect the response to be the same as the first, per HTTP
    // GET semantics.
    let resp = t
        .poll_collection_url_using_token(client, &collect_uri, DAP_TASKPROV_COLLECTOR_TOKEN)
        .await
        .unwrap();
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
