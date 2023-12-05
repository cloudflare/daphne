// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! End-to-end tests for daphne.
use super::test_runner::TestRunner;
use daphne::{
    async_test_versions,
    constants::DapMediaType,
    messages::{
        taskprov::{
            DpConfig, QueryConfig, QueryConfigVar, TaskConfig, UrlBytes, VdafConfig, VdafTypeVar,
        },
        BatchSelector, Collection, CollectionReq, Extension, HpkeCiphertext, Interval, Query,
        Report, ReportId, ReportMetadata, TaskId,
    },
    taskprov::compute_task_id,
    DapAggregateResult, DapMeasurement, DapQueryConfig, DapTaskConfig, DapTaskParameters,
    DapVersion,
};
use daphne_worker::DaphneWorkerReportSelector;
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use rand::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::cmp::{max, min};

#[derive(Deserialize)]
struct InternalTestEndpointForTaskResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
}

async fn helper_ready(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    t.helper_post_internal::<_, ()>("/internal/test/ready", &())
        .await;
}

async_test_versions! { helper_ready }

async fn leader_ready(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    t.leader_post_internal::<_, ()>("/internal/test/ready", &())
        .await;
}

async_test_versions! { leader_ready }

async fn leader_endpoint_for_task(version: DapVersion, want_prefix: bool) {
    let prefix = if want_prefix {
        format!("/{}", version.as_ref())
    } else {
        String::from("")
    };
    let t = TestRunner::default_with_version(version).await;
    let res: InternalTestEndpointForTaskResult = t
        .leader_post_internal(
            format!("{}/internal/test/endpoint_for_task", prefix).as_ref(),
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
    leader_endpoint_for_task(version, false).await
}

async_test_versions! { leader_endpoint_for_task_unprefixed }

async fn leader_endpoint_for_task_prefixed(version: DapVersion) {
    leader_endpoint_for_task(version, true).await
}

async_test_versions! { leader_endpoint_for_task_prefixed }

async fn helper_endpoint_for_task(version: DapVersion, want_prefix: bool) {
    let prefix = if want_prefix {
        format!("/{}", version.as_ref())
    } else {
        String::from("")
    };
    let t = TestRunner::default_with_version(version).await;
    let res: InternalTestEndpointForTaskResult = t
        .helper_post_internal(
            format!("{}/internal/test/endpoint_for_task", prefix).as_ref(),
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
    helper_endpoint_for_task(version, false).await
}

async_test_versions! { helper_endpoint_for_task_unprefixed }

async fn helper_endpoint_for_task_prefixed(version: DapVersion) {
    helper_endpoint_for_task(version, true).await
}

async_test_versions! { helper_endpoint_for_task_prefixed }

async fn leader_hpke_config(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    t.leader_get_raw_hpke_config(&client).await;
}

async_test_versions! { leader_hpke_config }

async fn helper_hpke_config(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    t.helper_get_raw_hpke_config(&client).await;
}

async_test_versions! { helper_hpke_config }

async fn hpke_configs_are_cached(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    // Get a set of HPKE configs from leader and helper.
    let hpke_config_list_0 = t.get_hpke_configs(version, &client).await;
    // Get another set of HPKE configs from leader and helper.
    let hpke_config_list_1 = t.get_hpke_configs(version, &client).await;
    // The leader HPKE configs in the two sets must be the same because we store
    // the HPKE receiver config in KV.
    assert_eq!(hpke_config_list_0[0], hpke_config_list_1[0]);
    // The same holds for the helper HPKE config.
    assert_eq!(hpke_config_list_0[1], hpke_config_list_1[1]);
}

async_test_versions! { hpke_configs_are_cached }

async fn leader_upload(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let mut rng = thread_rng();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, &client).await;
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
        &client,
        &path,
        DapMediaType::Report,
        None,
        report.get_encoded_with_param(&version),
    )
    .await;

    // Try uploading the same report a second time (expect failure due to repeated ID.
    t.leader_put_expect_abort(
        &client,
        None, // dap_auth_token
        &path,
        DapMediaType::Report,
        report.get_encoded_with_param(&version),
        400,
        "reportRejected",
    )
    .await;

    // Try uploading a report with the incorrect task ID.
    let bad_id = TaskId(rng.gen());
    let bad_path = t.upload_path_for_task(&bad_id);
    t.leader_put_expect_abort(
        &client,
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
            .get_encoded_with_param(&version),
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
        &client,
        None, // dap_auth_token
        &path,
        DapMediaType::Report,
        report.get_encoded_with_param(&version),
        400,
        "reportRejected",
    )
    .await;

    // Try uploading a malformed report.
    t.leader_put_expect_abort(
        &client,
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
        &client,
        None, // dap_auth_token
        &path,
        DapMediaType::Report,
        report.get_encoded_with_param(&version),
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
    let builder = match t.version {
        DapVersion::Draft02 => client.post(url.as_str()),
        DapVersion::DraftLatest => client.put(url.as_str()),
    };
    let resp = builder
        .body(
            Report {
                draft02_task_id: t.task_id.for_request_payload(&version),
                report_metadata: ReportMetadata {
                    id: ReportId([1; 16]),
                    time: t.now,
                    draft02_extensions: match version {
                        DapVersion::Draft02 => Some(Vec::default()),
                        DapVersion::DraftLatest => None,
                    },
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
            .get_encoded_with_param(&version),
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
    let version = DapVersion::Draft02;
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, &client).await;
    let path = "upload";

    let taskprov_vdaf_config = VdafConfig {
        dp_config: DpConfig::None,
        var: VdafTypeVar::Prio2 { dimension: 10 },
    };

    // Generate and upload a report with taskprov.
    //
    // We have to make this by hand as if we cut and paste a pre-serialized one it
    // will have an expiring task.
    let (task_config, task_id, taskprov_task_config) = {
        let taskprov_task_config = TaskConfig {
            task_info: "Hi".as_bytes().to_vec(),
            leader_url: UrlBytes {
                bytes: "https://test1".as_bytes().to_vec(),
            },
            helper_url: UrlBytes {
                bytes: "https://test2".as_bytes().to_vec(),
            },
            query_config: QueryConfig {
                time_precision: 0x01,
                max_batch_query_count: 1,
                min_batch_size: 1024,
                var: QueryConfigVar::FixedSize {
                    max_batch_size: 2048,
                },
            },
            task_expiration: t.now + 86400,
            vdaf_config: taskprov_vdaf_config.clone(),
        };
        let task_id = compute_task_id(
            version,
            &taskprov_task_config.get_encoded_with_param(&version),
        );
        let task_config = DapTaskConfig::try_from_taskprov(
            version,
            &task_id,
            taskprov_task_config.clone(),
            &t.taskprov_vdaf_verify_key_init,
            &t.taskprov_collector_hpke_receiver.config,
        )
        .unwrap();
        (task_config, task_id, taskprov_task_config)
    };

    let report = task_config
        .vdaf
        .produce_report_with_extensions(
            &hpke_config_list,
            t.now,
            &task_id,
            DapMeasurement::U32Vec(vec![1; 10]),
            vec![Extension::Taskprov {
                draft02_payload: Some(taskprov_task_config.get_encoded_with_param(&version)),
            }],
            version,
        )
        .unwrap();
    t.leader_post_expect_ok(
        &client,
        path,
        DapMediaType::Report,
        report.get_encoded_with_param(&version),
    )
    .await;

    // Generate and upload a report with taskprov but with the wrong id
    let payload = taskprov_task_config.get_encoded_with_param(&version);
    let mut bad_payload = payload.clone();
    bad_payload[0] = u8::wrapping_add(bad_payload[0], 1);
    let task_id = compute_task_id(DapVersion::Draft02, &bad_payload);
    let extensions = vec![Extension::Taskprov {
        draft02_payload: Some(payload),
    }];
    let report = task_config
        .vdaf
        .produce_report_with_extensions(
            &hpke_config_list,
            t.now,
            &task_id,
            DapMeasurement::U32Vec(vec![1; 10]),
            extensions,
            version,
        )
        .unwrap();
    t.leader_post_expect_abort(
        &client,
        None, // dap_auth_token
        path,
        DapMediaType::Report,
        report.get_encoded_with_param(&version),
        400,
        "unrecognizedTask",
    )
    .await;
}

async fn internal_leader_process(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let path = t.upload_path();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, &client).await;

    let report_sel = DaphneWorkerReportSelector {
        max_agg_jobs: 100, // Needs to be sufficiently large to touch each bucket.
        max_reports: t.task_config.min_batch_size,
    };

    let batch_interval = t.batch_interval();

    // Upload a number of reports (a few more than the aggregation rate).
    let mut rng = thread_rng();
    for _ in 0..report_sel.max_reports + 3 {
        let now = rng.gen_range(t.report_interval(&batch_interval));
        t.leader_put_expect_ok(
            &client,
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    let agg_telem = t.internal_process(&client, &report_sel).await;
    assert_eq!(
        agg_telem.reports_processed,
        report_sel.max_reports + 3,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated,
        report_sel.max_reports + 3,
        "reports aggregated"
    );
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");

    // There should be nothing left to aggregate.
    let agg_telem = t.internal_process(&client, &report_sel).await;
    assert_eq!(agg_telem.reports_processed, 0, "reports processed");
    assert_eq!(agg_telem.reports_aggregated, 0, "reports aggregated");
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");
}

async_test_versions! { internal_leader_process }

// Test that all reports eventually get drained at minimum aggregation rate.
async fn leader_process_min_agg_rate(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let batch_interval = t.batch_interval();
    let hpke_config_list = t.get_hpke_configs(version, &client).await;
    let path = t.upload_path();

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..7 {
        let now = rng.gen_range(t.report_interval(&batch_interval));
        t.leader_put_expect_ok(
            &client,
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    // One bucket and one report/bucket equal an aggregation rate of one report.
    let report_sel = DaphneWorkerReportSelector {
        max_agg_jobs: 1,
        max_reports: 1,
    };

    for i in 0..7 {
        // Each round should process exactly one report.
        let agg_telem = t.internal_process(&client, &report_sel).await;
        assert_eq!(agg_telem.reports_processed, 1, "round {} is empty", i);
    }

    let agg_telem = t.internal_process(&client, &report_sel).await;
    assert_eq!(agg_telem.reports_processed, 0, "reports processed");
}

async_test_versions! { leader_process_min_agg_rate }

async fn leader_collect_ok(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, &client).await;
    let path = t.upload_path();

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    let mut time_min = u64::MAX;
    let mut time_max = 0u64;
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(t.report_interval(&batch_interval));
        time_min = min(time_min, now);
        time_max = max(time_max, now);
        t.leader_put_expect_ok(
            &client,
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    // Get the collect URI.
    let collect_req = CollectionReq {
        draft02_task_id: t.collect_task_id_field(),
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: Vec::new(),
    };
    let collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded_with_param(&t.version))
        .await;
    println!("collect_uri: {}", collect_uri);

    // Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(&client, &collect_uri).await;
    assert_eq!(resp.status(), 202, "response: {:?}", resp);

    // The reports are aggregated in the background.
    let agg_telem = t
        .internal_process(
            &client,
            &DaphneWorkerReportSelector {
                max_agg_jobs: 100, // Needs to be sufficiently large to touch each bucket.
                max_reports: 100,
            },
        )
        .await;
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
    let resp = t.poll_collection_url(&client, &collect_uri).await;
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
            &collect_req.agg_param,
            collection.encrypted_agg_shares.to_vec(),
            version,
        )
        .await
        .unwrap();
    assert_eq!(
        agg_res,
        DapAggregateResult::U128(t.task_config.min_batch_size as u128)
    );

    if version != DapVersion::Draft02 {
        // Check that the time interval for the reports is correct.
        let interval = collection.draft_latest_interval.as_ref().unwrap();
        let low = t.task_config.quantized_time_lower_bound(time_min);
        let high = t.task_config.quantized_time_upper_bound(time_max);
        assert!(low < high);
        assert_eq!(interval.start, low);
        assert_eq!(interval.duration, high - low);
    }

    // Poll the collect URI once more. Expect the response to be the same as the first, per HTTP
    // GET semantics.
    let resp = t.poll_collection_url(&client, &collect_uri).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap(),
        collection.get_encoded_with_param(&version)
    );

    // NOTE Our Leader doesn't check if a report is stale until it is ready to process it. As such,
    // It won't tell the Client at this point that its report is stale. Delaying this check allows
    // to avoid sharding ReportsProcessed by batch bucket, which is not feasilbe for fixed-size
    // tasks.
    //
    //  let now = rng.gen_range(t.report_interval(&batch_interval));
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
    let hpke_config_list = t.get_hpke_configs(version, &client).await;
    let path = t.upload_path();

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(t.report_interval(&batch_interval));
        t.leader_put_expect_ok(
            &client,
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    let report_sel = DaphneWorkerReportSelector {
        max_agg_jobs: 100, // Needs to be sufficiently large to touch each bucket.
        max_reports: 100,
    };

    // All reports for the task get processed ...
    let agg_telem = t.internal_process(&client, &report_sel).await;
    assert_eq!(
        agg_telem.reports_processed, t.task_config.min_batch_size,
        "reports processed"
    );

    // ... then the collect request is issued ...
    let collect_req = CollectionReq {
        draft02_task_id: t.collect_task_id_field(),
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: Vec::new(),
    };
    let _collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded_with_param(&t.version))
        .await;

    // ... then the collect job gets completed.
    let agg_telem = t.internal_process(&client, &report_sel).await;
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
    let hpke_config_list = t.get_hpke_configs(version, &client).await;
    let path = t.upload_path();

    // A number of reports are uploaded, but not enough to meet the minimum batch requirement.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size - 1 {
        let now = rng.gen_range(t.report_interval(&batch_interval));
        t.leader_put_expect_ok(
            &client,
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    // Get the collect URI.
    let collect_req = CollectionReq {
        draft02_task_id: t.collect_task_id_field(),
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: Vec::new(),
    };
    let collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded_with_param(&t.version))
        .await;
    println!("collect_uri: {}", collect_uri);

    // The reports are aggregated in the background.
    let agg_telem = t
        .internal_process(
            &client,
            &DaphneWorkerReportSelector {
                max_agg_jobs: 100, // Needs to be sufficiently large to touch each bucket.
                max_reports: 100,
            },
        )
        .await;
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
    let resp = t.poll_collection_url(&client, &collect_uri).await;
    assert_eq!(resp.status(), 202);
}

async_test_versions! { leader_collect_not_ready_min_batch_size }

async fn leader_collect_abort_unknown_request(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();

    // Poll collect URI for an unknown collect request.
    let fake_task_id = TaskId([0; 32]);
    let fake_collection_job_id = TaskId([0; 32]);
    let url_suffix = if t.version == DapVersion::Draft02 {
        format!("collect/task/{fake_task_id}/req/{fake_collection_job_id}")
    } else {
        format!("/tasks/{fake_task_id}/collection_jobs/{fake_collection_job_id}")
    };
    let expected_status = if t.version == DapVersion::Draft02 {
        400
    } else {
        404
    };
    let collect_uri = t.leader_url.join(&url_suffix).unwrap();
    let resp = t.poll_collection_url(&client, &collect_uri).await;
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
        draft02_task_id: t.collect_task_id_field(),
        query: Query::TimeInterval { batch_interval },
        agg_param: Vec::new(),
    };
    let _collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded_with_param(&t.version))
        .await;
}

async_test_versions! { leader_collect_accept_global_config_max_batch_duration }

async fn leader_collect_abort_invalid_batch_interval(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let client = t.http_client();
    let batch_interval = t.batch_interval();
    let path = &t.collect_path_for_task(&t.task_id);

    // Start of batch interval does not align with time_precision.
    let collect_req = CollectionReq {
        draft02_task_id: t.collect_task_id_field(),
        query: Query::TimeInterval {
            batch_interval: Interval {
                start: batch_interval.start + 1,
                duration: batch_interval.duration,
            },
        },
        agg_param: Vec::new(),
    };
    if t.version == DapVersion::Draft02 {
        t.leader_post_expect_abort(
            &client,
            Some(&t.collector_bearer_token),
            path,
            DapMediaType::CollectReq,
            collect_req.get_encoded_with_param(&t.version),
            400,
            "batchInvalid",
        )
        .await;
    } else {
        t.leader_put_expect_abort(
            &client,
            Some(&t.collector_bearer_token),
            path,
            DapMediaType::CollectReq,
            collect_req.get_encoded_with_param(&t.version),
            400,
            "batchInvalid",
        )
        .await;
    }

    // Batch interval duration does not align wiht min_batch_duration.
    let collect_req = CollectionReq {
        draft02_task_id: t.collect_task_id_field(),
        query: Query::TimeInterval {
            batch_interval: Interval {
                start: batch_interval.start,
                duration: batch_interval.duration - 1,
            },
        },
        agg_param: Vec::new(),
    };
    if t.version == DapVersion::Draft02 {
        t.leader_post_expect_abort(
            &client,
            Some(&t.collector_bearer_token),
            path,
            DapMediaType::CollectReq,
            collect_req.get_encoded_with_param(&t.version),
            400,
            "batchInvalid",
        )
        .await;
    } else {
        t.leader_put_expect_abort(
            &client,
            Some(&t.collector_bearer_token),
            path,
            DapMediaType::CollectReq,
            collect_req.get_encoded_with_param(&t.version),
            400,
            "batchInvalid",
        )
        .await;
    }
}

async_test_versions! { leader_collect_abort_invalid_batch_interval }

async fn leader_collect_abort_overlapping_batch_interval(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, &client).await;
    let path = t.upload_path();

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let now = rng.gen_range(t.report_interval(&batch_interval));
        t.leader_put_expect_ok(
            &client,
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    // Get the collect URI.
    let collect_req = CollectionReq {
        draft02_task_id: t.collect_task_id_field(),
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: Vec::new(),
    };
    let _collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded_with_param(&t.version))
        .await;

    // The reports are aggregated in the background.
    let agg_telem = t
        .internal_process(
            &client,
            &DaphneWorkerReportSelector {
                max_agg_jobs: 100, // Needs to be sufficiently large to touch each bucket.
                max_reports: 100,
            },
        )
        .await;
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
        draft02_task_id: t.collect_task_id_field(),
        query: Query::TimeInterval {
            batch_interval: Interval {
                start: batch_interval.start,
                duration: batch_interval.duration * 2,
            },
        },
        agg_param: Vec::new(),
    };
    let path = &t.collect_path_for_task(&t.task_id);
    if t.version == DapVersion::Draft02 {
        t.leader_post_expect_abort(
            &client,
            Some(&t.collector_bearer_token),
            &path,
            DapMediaType::CollectReq,
            collect_req.get_encoded_with_param(&t.version),
            400,
            "batchOverlap",
        )
        .await;
    } else {
        t.leader_put_expect_abort(
            &client,
            Some(&t.collector_bearer_token),
            &path,
            DapMediaType::CollectReq,
            collect_req.get_encoded_with_param(&t.version),
            400,
            "batchOverlap",
        )
        .await;
    }
}

async_test_versions! { leader_collect_abort_overlapping_batch_interval }

async fn fixed_size(version: DapVersion, use_current: bool) {
    if version == DapVersion::Draft02 && use_current {
        // draft02 compatibility: The "current batch" isn't a feature in draft02, but is in the
        // latest version.
        return;
    }
    let t = TestRunner::fixed_size(version).await;
    let path = t.upload_path();
    let report_sel = DaphneWorkerReportSelector {
        max_agg_jobs: 100, // Needs to be sufficiently large to touch each bucket.
        max_reports: 100,
    };

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, &client).await;

    // Clients: Upload reports.
    for _ in 0..t.task_config.min_batch_size {
        t.leader_put_expect_ok(
            &client,
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    // ... Aggregators run processing loop.
    let agg_telem = t.internal_process(&client, &report_sel).await;
    assert_eq!(
        agg_telem.reports_processed, t.task_config.min_batch_size,
        "reports processed"
    );
    assert_eq!(
        agg_telem.reports_aggregated, t.task_config.min_batch_size,
        "reports aggregated"
    );
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");

    // Get the oldest, not-yet-collected batch ID.
    //
    // TODO spec: Decide whether to formalize this (cf.
    // https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/pull/313).
    let batch_id = t.internal_current_batch(&t.task_id).await;

    // Collector: Get the collect URI.
    let collect_req = CollectionReq {
        draft02_task_id: t.collect_task_id_field(),
        query: if use_current {
            Query::FixedSizeCurrentBatch
        } else {
            Query::FixedSizeByBatchId { batch_id }
        },
        agg_param: Vec::new(),
    };
    let collect_uri = t
        .leader_post_collect(&client, collect_req.get_encoded_with_param(&t.version))
        .await;
    println!("collect_uri: {}", collect_uri);

    // Collector: Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(&client, &collect_uri).await;
    assert_eq!(resp.status(), 202, "response: {:?}", resp);

    // ... Aggregators run processing loop.
    let agg_telem = t.internal_process(&client, &report_sel).await;
    assert_eq!(agg_telem.reports_processed, 0, "reports processed");
    assert_eq!(agg_telem.reports_aggregated, 0, "reports aggregated");
    assert_eq!(
        agg_telem.reports_collected, t.task_config.min_batch_size,
        "reports collected"
    );

    // Collector: Poll the collect URI.
    let resp = t.poll_collection_url(&client, &collect_uri).await;
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
            &collect_req.agg_param,
            collection.encrypted_agg_shares.to_vec(),
            version,
        )
        .await
        .unwrap();
    assert_eq!(
        agg_res,
        DapAggregateResult::U128(t.task_config.min_batch_size as u128)
    );

    // Collector: Poll the collect URI once more. Expect the response to be the same as the first,
    // per HTTP GET semantics.
    let resp = t.poll_collection_url(&client, &collect_uri).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap(),
        collection.get_encoded_with_param(&t.version)
    );

    // Clients: Upload reports.
    for _ in 0..2 {
        t.leader_put_expect_ok(
            &client,
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    // ... Aggregators run processing loop.
    let agg_telem = t.internal_process(&client, &report_sel).await;
    assert_eq!(agg_telem.reports_processed, 2, "reports processed");
    assert_eq!(agg_telem.reports_aggregated, 2, "reports aggregated");
    assert_eq!(agg_telem.reports_collected, 0, "reports collected");

    // Get the oldest, not-yet-collected batch ID. This should be different than the one we got
    // before, since that batch was collected.
    let prev_batch_id = batch_id;
    let batch_id = t.internal_current_batch(&t.task_id).await;
    assert_ne!(batch_id, prev_batch_id);

    // Collector: Try CollectReq with out-dated batch ID.
    if t.version == DapVersion::Draft02 {
        t.leader_post_expect_abort(
            &client,
            Some(&t.collector_bearer_token),
            &t.collect_path_for_task(&t.task_id),
            DapMediaType::CollectReq,
            CollectionReq {
                draft02_task_id: t.collect_task_id_field(),
                query: Query::FixedSizeByBatchId {
                    batch_id: prev_batch_id,
                },
                agg_param: Vec::new(),
            }
            .get_encoded_with_param(&t.version),
            400,
            "batchOverlap",
        )
        .await;
    } else {
        t.leader_put_expect_abort(
            &client,
            Some(&t.collector_bearer_token),
            &t.collect_path_for_task(&t.task_id),
            DapMediaType::CollectReq,
            CollectionReq {
                draft02_task_id: t.collect_task_id_field(),
                query: Query::FixedSizeByBatchId {
                    batch_id: prev_batch_id,
                },
                agg_param: Vec::new(),
            }
            .get_encoded_with_param(&t.version),
            400,
            "batchOverlap",
        )
        .await;
    }
}

async fn fixed_size_no_current(version: DapVersion) {
    fixed_size(version, true).await;
}

async_test_versions! { fixed_size_no_current }

async fn fixed_size_current(version: DapVersion) {
    fixed_size(version, true).await;
}

async_test_versions! { fixed_size_current }

async fn leader_collect_taskprov_ok(version: DapVersion) {
    let t = TestRunner::default_with_version(version).await;
    let batch_interval = t.batch_interval();

    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(version, &client).await;

    let (task_config, task_id, taskprov_advertisement, taskprov_report_extension_payload) =
        DapTaskParameters {
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

    let path = t.upload_path_for_task(&task_id);

    // The reports are uploaded in the background.
    let mut rng = thread_rng();
    for _ in 0..t.task_config.min_batch_size {
        let extensions = vec![Extension::Taskprov {
            draft02_payload: match version {
                DapVersion::DraftLatest => None,
                DapVersion::Draft02 => taskprov_report_extension_payload.clone(),
            },
        }];
        let now = rng.gen_range(t.report_interval(&batch_interval));
        t.leader_put_expect_ok(
            &client,
            &path,
            DapMediaType::Report,
            taskprov_advertisement.as_deref(),
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
                .get_encoded_with_param(&version),
        )
        .await;
    }

    // Get the collect URI.
    let collect_req = CollectionReq {
        draft02_task_id: Some(task_id),
        query: Query::TimeInterval {
            batch_interval: batch_interval.clone(),
        },
        agg_param: Vec::new(),
    };
    let collect_uri = t
        .leader_post_collect_using_token(
            &client,
            "I am the collector!", // DAP_TASKPROV_COLLECTOR_AUTH
            taskprov_advertisement.as_deref(),
            Some(&task_id),
            collect_req.get_encoded_with_param(&t.version),
        )
        .await;
    println!("collect_uri: {}", collect_uri);

    // Poll the collect URI before the CollectResp is ready.
    let resp = t.poll_collection_url(&client, &collect_uri).await;
    assert_eq!(resp.status(), 202, "response: {:?}", resp);

    // The reports are aggregated in the background.
    let agg_telem = t
        .internal_process(
            &client,
            &DaphneWorkerReportSelector {
                max_agg_jobs: 100, // Needs to be sufficiently large to touch each bucket.
                max_reports: 100,
            },
        )
        .await;
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
    let resp = t.poll_collection_url(&client, &collect_uri).await;
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
            &collect_req.agg_param,
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
    let resp = t.poll_collection_url(&client, &collect_uri).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap(),
        collection.get_encoded_with_param(&t.version)
    );
}

async_test_versions! { leader_collect_taskprov_ok }
