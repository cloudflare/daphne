// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    auth::BearerToken,
    constants::{
        MEDIA_TYPE_AGG_CONT_REQ, MEDIA_TYPE_AGG_INIT_REQ, MEDIA_TYPE_AGG_SHARE_REQ,
        MEDIA_TYPE_COLLECT_REQ, MEDIA_TYPE_REPORT,
    },
    hpke::HpkeReceiverConfig,
    messages::{
        AggregateContinueReq, AggregateInitializeReq, AggregateResp, AggregateShareReq,
        AggregateShareResp, CollectReq, CollectResp, HpkeCiphertext, Id, Interval, Nonce, Report,
        ReportShare, Transition, TransitionFailure, TransitionVar,
    },
    roles::{DapAggregator, DapHelper, DapLeader},
    testing::{
        BucketInfo, MockAggregateInfo, MockAggregator, ReportStore, COLLECTOR_BEARER_TOKEN,
        HPKE_RECEIVER_CONFIG_LIST, LEADER_BEARER_TOKEN,
    },
    DapAbort, DapCollectJob, DapError, DapLeaderTransition, DapMeasurement, DapRequest,
    DapTaskConfig, DapVersion, Prio3Config, VdafConfig,
};
use assert_matches::assert_matches;
use matchit::Router;
use prio::codec::{Decode, Encode};
use rand::{thread_rng, Rng};
use std::{ops::DerefMut, vec};

// MockAggregator's implementation of DapLeader::get_report() always returns reports for a single
// task. This macro is used to conveniently unwrap the task ID and reports for testing purposes.
macro_rules! get_reports {
    ($leader:expr, $selector:expr) => {{
        let reports_per_task = $leader.get_reports($selector).await.unwrap();
        assert_eq!(reports_per_task.len(), 1);
        reports_per_task.into_iter().next().unwrap()
    }};
}

impl MockAggregator {
    fn gen_test_upload_req(&self, report: Report) -> DapRequest<BearerToken> {
        let task_id = self.nominal_task_id();
        let task_config = self.get_task_config_for(task_id).unwrap();
        let version = task_config.version.clone();

        DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_REPORT),
            payload: report.get_encoded(),
            url: task_config.leader_url.join("upload").unwrap(),
            sender_auth: None,
        }
    }

    fn gen_test_agg_init_req(&self, report_shares: Vec<ReportShare>) -> DapRequest<BearerToken> {
        let mut rng = thread_rng();
        let task_id = self.nominal_task_id();
        let task_config = self.get_task_config_for(task_id).unwrap();
        let version = task_config.version.clone();

        DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_AGG_INIT_REQ),
            payload: AggregateInitializeReq {
                task_id: task_id.clone(),
                agg_job_id: Id(rng.gen()),
                agg_param: Vec::default(),
                report_shares,
            }
            .get_encoded(),
            url: task_config.helper_url.join("aggregate").unwrap(),
            sender_auth: None,
        }
    }

    fn gen_test_agg_cont_req(
        &self,
        agg_job_id: Id,
        transitions: Vec<Transition>,
    ) -> DapRequest<BearerToken> {
        let task_id = self.nominal_task_id();
        let task_config = self.get_task_config_for(task_id).unwrap();
        let version = task_config.version.clone();

        DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_AGG_CONT_REQ),
            payload: AggregateContinueReq {
                task_id: task_id.clone(),
                agg_job_id,
                transitions,
            }
            .get_encoded(),
            url: task_config.helper_url.join("aggregate").unwrap(),
            sender_auth: None,
        }
    }

    fn gen_test_agg_share_req(
        &self,
        report_count: u64,
        checksum: [u8; 32],
    ) -> DapRequest<BearerToken> {
        let task_id = self.nominal_task_id();
        let task_config = self.get_task_config_for(task_id).unwrap();
        let version = task_config.version.clone();

        DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_AGG_SHARE_REQ),
            payload: AggregateShareReq {
                task_id: task_id.clone(),
                batch_interval: Interval::default(),
                agg_param: Vec::default(),
                report_count,
                checksum,
            }
            .get_encoded(),
            url: task_config.helper_url.join("aggregate_share").unwrap(),
            sender_auth: None,
        }
    }

    fn gen_test_collect_req(&self) -> DapRequest<BearerToken> {
        let task_id = self.nominal_task_id();
        let task_config = self.get_task_config_for(task_id).unwrap();
        let version = task_config.version.clone();

        DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_COLLECT_REQ),
            payload: CollectReq {
                task_id: task_id.clone(),
                batch_interval: Interval::default(),
                agg_param: Vec::default(),
            }
            .get_encoded(),
            url: task_config.leader_url.join("collect").unwrap(),
            sender_auth: None,
        }
    }

    fn gen_test_report(&self, task_id: &Id) -> Report {
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
        let now = self.get_current_time();
        let report = vdaf_config
            .produce_report(&hpke_config_list, now, task_id, DapMeasurement::U64(1))
            .unwrap();

        report
    }

    async fn run_test_agg_job(
        &self,
        helper: &MockAggregator,
        now: u64,
        task_id: &Id,
        task_config: &DapTaskConfig,
    ) {
        // Leader: Store received report to ReportStore.
        let selector = &MockAggregateInfo {
            task_id: task_id.clone(),
            batch_info: Some(task_config.current_batch_window(now)),
            agg_rate: 1,
        };
        let (task_id, reports) = get_reports!(self, selector);

        // Leader: Consume report share.
        let mut rng = thread_rng();
        let agg_job_id = Id(rng.gen());
        let transition = task_config
            .vdaf
            .produce_agg_init_req(
                self,
                &task_config.vdaf_verify_key,
                &task_id,
                &agg_job_id,
                reports,
            )
            .unwrap();
        assert_matches!(transition, DapLeaderTransition::Continue(..));
        let (leader_state, agg_init_req) = transition.unwrap_continue();

        // Leader: Send aggregate initialization request to Helper and receive response.
        let version = task_config.version.clone();
        let req = DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_AGG_INIT_REQ),
            payload: agg_init_req.get_encoded(),
            url: task_config.helper_url.join("aggregate").unwrap(),
            sender_auth: Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string())),
        };
        let res = helper.http_post_aggregate(&req).await.unwrap();
        let agg_resp = AggregateResp::get_decoded(&res.payload).unwrap();

        // Leader: Produce Leader output share and prepare aggregate continue request for Helper.
        let transition = task_config
            .vdaf
            .handle_agg_resp(&task_id, &agg_job_id, leader_state, agg_resp)
            .unwrap();
        assert_matches!(transition, DapLeaderTransition::Uncommitted(..));
        let (leader_uncommitted, agg_cont_req) = transition.unwrap_uncommitted();

        // Leader: Send aggregate continue request to Helper and receive response.
        let version = task_config.version.clone();
        let req = DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_AGG_CONT_REQ),
            payload: agg_cont_req.get_encoded(),
            url: task_config.helper_url.join("aggregate").unwrap(),
            sender_auth: Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string())),
        };
        let res = helper.http_post_aggregate(&req).await.unwrap();
        let agg_resp = AggregateResp::get_decoded(&res.payload).unwrap();

        // Leader: Commit output shares of Leader and Helper.
        let out_shares = task_config
            .vdaf
            .handle_final_agg_resp(leader_uncommitted, agg_resp)
            .unwrap();
        self.put_out_shares(&task_id, out_shares).await.unwrap();
    }

    async fn run_test_col_job(
        &self,
        task_id: &Id,
        collect_id: &Id,
        collect_req: &CollectReq,
        task_config: &DapTaskConfig,
    ) {
        // Leader: Get Leader's encrypted aggregate share.
        let leader_agg_share = self
            .get_agg_share(&collect_req.task_id, &collect_req.batch_interval)
            .await
            .unwrap();

        let leader_enc_agg_share = task_config
            .vdaf
            .produce_leader_encrypted_agg_share(
                &task_config.collector_hpke_config,
                &collect_req.task_id,
                &collect_req.batch_interval,
                &leader_agg_share,
            )
            .unwrap();

        // Leader: Prepare AggregateShareReq.
        let agg_share_req = AggregateShareReq {
            task_id: collect_req.task_id.clone(),
            batch_interval: collect_req.batch_interval.clone(),
            agg_param: collect_req.agg_param.clone(),
            report_count: leader_agg_share.report_count,
            checksum: leader_agg_share.checksum,
        };

        // Leader: Send AggregateShareReq to Helper and receive AggregateShareResp.
        let version = task_config.version.clone();
        let req = DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_AGG_SHARE_REQ),
            payload: agg_share_req.get_encoded(),
            url: task_config.helper_url.join("aggregate_share").unwrap(),
            sender_auth: Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string())),
        };
        let res = self.http_post_aggregate_share(&req).await.unwrap();
        let agg_share_resp = AggregateShareResp::get_decoded(&res.payload).unwrap();
        let helper_enc_agg_share = agg_share_resp.encrypted_agg_share;

        // Leader: Complete the collect job by storing CollectResp in LeaderStore.processed.
        let collect_resp = CollectResp {
            encrypted_agg_shares: vec![leader_enc_agg_share, helper_enc_agg_share],
        };

        self.finish_collect_job(task_id, collect_id, &collect_resp)
            .await
            .unwrap();

        // Leader: Mark the reports as collected.
        self.mark_collected(task_id, &agg_share_req.batch_interval)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn http_post_aggregate_init_unauthorized_request() {
    let helper = MockAggregator::new();
    let mut req = helper.gen_test_agg_init_req(Vec::default());

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
async fn http_post_aggregate_cont_unauthorized_request() {
    let helper = MockAggregator::new();
    let mut rng = thread_rng();
    let mut req = helper.gen_test_agg_cont_req(Id(rng.gen()), Vec::default());

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
    let mut req = helper.gen_test_agg_share_req(0, [0; 32]);

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
    let mut req = leader.gen_test_collect_req();

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
    let now = helper.get_current_time();
    let report_shares = vec![ReportShare {
        nonce: Nonce {
            time: now,
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
    let mut req = helper.gen_test_agg_init_req(report_shares);
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

    let report = helper.gen_test_report(task_id);
    let report_shares = vec![ReportShare {
        nonce: report.nonce,
        extensions: report.extensions,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let sender_auth = Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string()));

    let mut req = helper.gen_test_agg_init_req(report_shares);
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

    let report = helper.gen_test_report(task_id);
    let report_shares = vec![ReportShare {
        nonce: report.nonce.clone(),
        extensions: report.extensions,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let sender_auth = Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string()));

    let mut req = helper.gen_test_agg_init_req(report_shares);
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

    let report = helper.gen_test_report(task_id);
    let report_shares = vec![ReportShare {
        nonce: report.nonce.clone(),
        extensions: report.extensions,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let sender_auth = Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string()));

    let mut req = helper.gen_test_agg_init_req(report_shares);
    req.sender_auth = sender_auth;

    // Send aggregate request.
    let _ = helper.http_post_aggregate(&req).await;

    // Send another aggregate request.
    let err = helper.http_post_aggregate(&req).await.unwrap_err();

    // Expect failure due to overwriting existing helper state.
    assert_matches!(err, DapAbort::BadRequest(e) =>
        assert_eq!(e, "unexpected message for aggregation job (already exists)")
    );
}

#[tokio::test]
async fn http_post_aggregate_fail_send_cont_req() {
    let mut rng = thread_rng();
    let helper = MockAggregator::new();
    let leader = MockAggregator::new();
    let sender_auth = Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string()));

    let mut req = leader.gen_test_agg_cont_req(Id(rng.gen()), Vec::default());
    req.sender_auth = sender_auth;

    // Send aggregate continue request to helper.
    let err = helper.http_post_aggregate(&req).await.unwrap_err();

    // Expect failure due to sending continue request before initialization request.
    assert_matches!(err, DapAbort::UnrecognizedAggregationJob);
}

#[tokio::test]
async fn http_post_upload_fail_send_invalid_report() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();

    // Construct a report payload with an invalid task ID.
    let mut report_empty_task_id = leader.gen_test_report(task_id);
    report_empty_task_id.task_id = Id([0; 32]);
    let req = leader.gen_test_upload_req(report_empty_task_id);

    // Expect failure due to invalid task ID in report.
    assert_matches!(
        leader.http_post_upload(&req).await,
        Err(DapAbort::UnrecognizedTask)
    );

    // Construct an invalid report payload that only has one input share.
    let mut report_one_input_share = leader.gen_test_report(task_id);
    report_one_input_share.encrypted_input_shares =
        vec![report_one_input_share.encrypted_input_shares[0].clone()];
    let req = leader.gen_test_upload_req(report_one_input_share);

    // Expect failure due to incorrect number of input shares
    assert_matches!(
        leader.http_post_upload(&req).await,
        Err(DapAbort::UnrecognizedMessage)
    );

    // Construct an invalid report payload that has an incorrect order of input shares.
    let mut report_incorrect_share_order = leader.gen_test_report(task_id);
    report_incorrect_share_order.encrypted_input_shares = vec![
        HpkeCiphertext {
            config_id: 1,
            enc: b"invalid encapsulated key".to_vec(),
            payload: b"invalid ciphertext".to_vec(),
        },
        HpkeCiphertext {
            config_id: 0,
            enc: b"another invalid encapsulated key".to_vec(),
            payload: b"another invalid ciphertext".to_vec(),
        },
    ];

    let req = leader.gen_test_upload_req(report_incorrect_share_order);

    // Expect failure due to incorrect number of input shares
    assert_matches!(
        leader.http_post_upload(&req).await,
        Err(DapAbort::UnrecognizedHpkeConfig)
    );
}

#[tokio::test]
async fn get_reports_fail_invalid_batch_interval() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();

    // Attempt to get reports using an empty interval.
    let empty_interval = Interval {
        start: 0,
        duration: 0,
    };
    let selector = &MockAggregateInfo {
        task_id: task_id.clone(),
        batch_info: Some(empty_interval),
        agg_rate: 1,
    };
    let err = leader.get_reports(selector).await.unwrap_err();

    // Fails because a 0 second duration interval is not permitted.
    assert_matches!(err, DapError::Fatal(e) =>
        assert_eq!(e, "invalid batch interval")
    );
}

#[tokio::test]
async fn get_reports_empty_response() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();

    let report = leader.gen_test_report(task_id);
    let req = leader.gen_test_upload_req(report.clone());

    // Upload report.
    leader
        .http_post_upload(&req)
        .await
        .expect("upload failed unexpectedly");

    // Get report.
    let now = report.nonce.time - task_config.min_batch_duration - 1;
    let selector = &MockAggregateInfo {
        task_id: task_id.clone(),
        batch_info: Some(task_config.current_batch_window(now)),
        agg_rate: 1,
    };
    let (task_id, reports) = get_reports!(leader, selector);

    // We get an empty response due to no reports existing within requested batch_window.
    assert_eq!(reports.len(), 0);

    // Attempt to get reports from the future.
    let now = report.nonce.time + task_config.min_batch_duration + 1;
    let selector = &MockAggregateInfo {
        task_id: task_id.clone(),
        batch_info: Some(task_config.current_batch_window(now)),
        agg_rate: 1,
    };
    let (_task_id, reports) = get_reports!(leader, selector);

    // We get an empty response due to no reports existing within requested batch_window.
    assert_eq!(reports.len(), 0);
}

#[tokio::test]
async fn poll_collect_job_test_results() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();
    let now = leader.get_current_time();

    // Collector: Create a CollectReq.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: task_config.current_batch_window(now),
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collector_collect_req.get_encoded(),
        url: task_config.helper_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    leader.http_post_collect(&req).await.unwrap();

    // Expect DapCollectJob::Unknown due to invalid collect ID.
    assert_eq!(
        leader
            .poll_collect_job(task_id, &Id::default())
            .await
            .unwrap(),
        DapCollectJob::Unknown
    );

    // Leader: Get pending collect job to obtain collect_id
    let resp = leader.get_pending_collect_jobs().await.unwrap();
    let (collect_id, _collect_req) = &resp[0];
    let collect_resp = CollectResp {
        encrypted_agg_shares: Vec::default(),
    };

    // Expect DapCollectJob::Pending due to pending collect job.
    assert_eq!(
        leader.poll_collect_job(task_id, &collect_id).await.unwrap(),
        DapCollectJob::Pending
    );

    // Leader: Complete the collect job by storing CollectResp in LeaderStore.processed.
    leader
        .finish_collect_job(&task_id, &collect_id, &collect_resp)
        .await
        .unwrap();

    // Expect DapCollectJob::Done due to processed collect job.
    assert_matches!(
        leader.poll_collect_job(task_id, &collect_id).await.unwrap(),
        DapCollectJob::Done(..)
    );
}

#[tokio::test]
async fn http_post_collect_fail_invalid_batch_interval() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();
    let now = leader.get_current_time();

    // Collector: Create a CollectReq with a very large batch interval.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: Interval {
            start: now - (now % task_config.min_batch_duration),
            duration: leader.global_config.max_batch_duration + task_config.min_batch_duration,
        },
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collector_collect_req.get_encoded(),
        url: task_config.helper_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    let err = leader.http_post_collect(&req).await.unwrap_err();

    // Fails because the requested batch interval is too large.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too large".to_string()));

    // Collector: Create a CollectReq with a batch interval in the past.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: Interval {
            start: now
                - (now % task_config.min_batch_duration)
                - leader.global_config.min_batch_interval_start
                - task_config.min_batch_duration,
            duration: task_config.min_batch_duration * 2,
        },
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collector_collect_req.get_encoded(),
        url: task_config.helper_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    let err = leader.http_post_collect(&req).await.unwrap_err();

    // Fails because the requested batch interval is too far into the past.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too far into past".to_string()));

    // Collector: Create a CollectReq with a batch interval in the future.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: Interval {
            start: now - (now % task_config.min_batch_duration)
                + leader.global_config.max_batch_interval_end
                - task_config.min_batch_duration,
            duration: task_config.min_batch_duration * 2,
        },
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collector_collect_req.get_encoded(),
        url: task_config.helper_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    let err = leader.http_post_collect(&req).await.unwrap_err();

    // Fails because the requested batch interval is too far into the future.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too far into future".to_string()));
}

#[tokio::test]
async fn http_post_collect_succeed_max_batch_interval() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();
    let now = leader.get_current_time();

    // Collector: Create a CollectReq with a very large batch interval.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: Interval {
            start: now
                - (now % task_config.min_batch_duration)
                - leader.global_config.max_batch_duration / 2,
            duration: leader.global_config.max_batch_duration,
        },
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collector_collect_req.get_encoded(),
        url: task_config.helper_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    let _collect_uri = leader.http_post_collect(&req).await.unwrap();
}

// Send a collect request with an overlapping batch interval.
#[tokio::test]
async fn http_post_collect_fail_overlapping_batch_interval() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();
    let helper = MockAggregator::new();
    let now = leader.get_current_time();

    // Create a report.
    let report = leader.gen_test_report(task_id);
    let req = leader.gen_test_upload_req(report.clone());

    // Client: Send upload request to Leader.
    leader.http_post_upload(&req).await.unwrap();

    // Leader: Run aggregation job.
    leader
        .run_test_agg_job(&helper, now, task_id, task_config)
        .await;

    // Collector: Create first CollectReq.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: task_config.current_batch_window(now),
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collector_collect_req.get_encoded(),
        url: task_config.helper_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    let _url = leader.http_post_collect(&req).await.unwrap();
    let resp = leader.get_pending_collect_jobs().await.unwrap();
    let (collect_id, collect_req) = &resp[0];

    // Leader: Run collect job.
    leader
        .run_test_col_job(task_id, collect_id, collect_req, task_config)
        .await;

    // Collector: Create second CollectReq.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: task_config.current_batch_window(now),
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collector_collect_req.get_encoded(),
        url: task_config.helper_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    // Fails due to batch interval overlapping.
    let err = leader.http_post_collect(&req).await.unwrap_err();
    assert_matches!(err, DapAbort::BatchOverlap);
}

// Test a successful collect request submission.
// This checks that the Leader reponds with the collect ID with the ID associated to the request.
#[tokio::test]
async fn http_post_collect_success() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();
    let now = leader.get_current_time();

    // Collector: Create a CollectReq.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: task_config.current_batch_window(now),
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collector_collect_req.get_encoded(),
        url: task_config.leader_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    let url = leader.http_post_collect(&req).await.unwrap();
    let resp = leader.get_pending_collect_jobs().await.unwrap();
    let (leader_collect_id, leader_collect_req) = &resp[0];

    // Check that the CollectReq sent by Collector is the same that is received by Leader.
    assert_eq!(&collector_collect_req, leader_collect_req);

    // Check that the collect_id included in the URI is the same with the one received
    // by Leader.
    let path = url.path().to_string();
    let mut router = Router::new();
    router
        .insert("/:version/collect/task/:task_id/req/:collect_id", true)
        .unwrap();
    let url_match = router.at(&path).unwrap();
    let collector_collect_id = url_match.params.get("collect_id").unwrap();
    assert_eq!(
        collector_collect_id.to_string(),
        leader_collect_id.to_base64url()
    );
}

// Test HTTP POST requests with a wrong DAP version.
#[tokio::test]
async fn http_post_fail_wrong_dap_version() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();

    // Send a request with the wrong DAP version.
    let report = leader.gen_test_report(task_id);
    let mut req = leader.gen_test_upload_req(report);
    req.version = DapVersion::Unknown;
    req.url = task_config.leader_url.join("upload").unwrap();

    let err = leader.http_post_upload(&req).await.unwrap_err();
    assert_matches!(err, DapAbort::InvalidProtocolVersion);
}

// Test the upload sub-protocol.
#[tokio::test]
async fn successful_http_post_upload() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();

    let report = leader.gen_test_report(task_id);
    let req = leader.gen_test_upload_req(report);

    leader
        .http_post_upload(&req)
        .await
        .expect("upload failed unexpectedly");
}

// Test the end-to-end protocol.
// TODO(nakatsuka-y) Implement the rest of the e2e functionality.
#[tokio::test]
async fn e2e() {
    let leader = MockAggregator::new();
    let task_id = leader.nominal_task_id();
    let task_config = leader.get_task_config_for(task_id).unwrap();
    let now = leader.get_current_time();

    let helper = MockAggregator::new();

    let report = leader.gen_test_report(task_id);
    let req = leader.gen_test_upload_req(report.clone());

    // Client: Send upload request to Leader.
    leader.http_post_upload(&req).await.unwrap();

    // Leader: Run aggregation job.
    leader
        .run_test_agg_job(&helper, now, task_id, task_config)
        .await;

    // Collector: Create a CollectReq.
    let collect_req = CollectReq {
        task_id: task_id.clone(),
        batch_interval: task_config.current_batch_window(now),
        agg_param: Vec::default(),
    };
    let version = task_config.version.clone();
    let req = DapRequest {
        version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: collect_req.get_encoded(),
        url: task_config.helper_url.join("collect").unwrap(),
        sender_auth: Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())),
    };

    // Leader: Handle the CollectReq received from Collector.
    leader.http_post_collect(&req).await.unwrap();
    let resp = leader.get_pending_collect_jobs().await.unwrap();
    let (collect_id, collect_req) = &resp[0];

    // Leader: Run collect job.
    leader
        .run_test_col_job(task_id, collect_id, collect_req, task_config)
        .await;

    // Leader: Respond to poll request from Collector.
    let collect_job = leader
        .poll_collect_job(&task_id, &collect_id)
        .await
        .unwrap();
    assert_matches!(collect_job, DapCollectJob::Done(..))
}
