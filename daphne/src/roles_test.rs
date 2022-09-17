// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    auth::BearerToken,
    constants::{
        MEDIA_TYPE_AGG_CONT_REQ, MEDIA_TYPE_AGG_INIT_REQ, MEDIA_TYPE_AGG_SHARE_REQ,
        MEDIA_TYPE_COLLECT_REQ, MEDIA_TYPE_HPKE_CONFIG, MEDIA_TYPE_REPORT,
    },
    hpke::{HpkeDecrypter, HpkeReceiverConfig},
    messages::{
        AggregateContinueReq, AggregateInitializeReq, AggregateResp, AggregateShareReq,
        AggregateShareResp, BatchParameter, BatchSelector, CollectReq, CollectResp, HpkeCiphertext,
        HpkeKemId, Id, Interval, Query, Report, ReportShare, Time, Transition, TransitionFailure,
        TransitionVar,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    testing::{AggStore, MockAggregateInfo, MockAggregator, ReportStore},
    vdaf::VdafVerifyKey,
    DapAbort, DapAggregateShare, DapCollectJob, DapGlobalConfig, DapLeaderTransition,
    DapMeasurement, DapQueryConfig, DapRequest, DapTaskConfig, DapVersion, Prio3Config, VdafConfig,
};
use assert_matches::assert_matches;
use matchit::Router;
use prio::codec::{Decode, Encode};
use rand::{thread_rng, Rng};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::SystemTime,
    vec,
};
use url::Url;

macro_rules! get_reports {
    ($leader:expr, $selector:expr) => {{
        let reports_per_task = $leader.get_reports($selector).await.unwrap();
        assert_eq!(reports_per_task.len(), 1);
        reports_per_task.into_iter().next().unwrap()
    }};
}

struct Test {
    now: Time,
    leader: MockAggregator,
    helper: MockAggregator,
    #[allow(dead_code)] // TODO(issue #100) Remove
    collector_hpke_receiver_config: HpkeReceiverConfig,
    #[allow(dead_code)] // TODO(issue #100) Remove
    collector_token: BearerToken,
    time_interval_task_id: Id,
    #[allow(dead_code)] // TODO(issue #100) Remove
    fixed_size_task_id: Id,
}

impl Test {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut rng = thread_rng();

        // Global config. In a real deployment, the Leader and Helper may make different choices
        // here.
        let global_config = DapGlobalConfig {
            max_batch_duration: 360000,
            min_batch_interval_start: 259200,
            max_batch_interval_end: 259200,
            supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
        };

        // Task Parameters that the Leader and Helper must agree on.
        let vdaf_config = VdafConfig::Prio3(Prio3Config::Count);
        let leader_url = Url::parse("https://leader.biz/v01/").unwrap();
        let helper_url = Url::parse("http://helper.com:8788/v01/").unwrap();
        let time_precision = 3600;
        let version = DapVersion::Draft01;
        let collector_hpke_receiver_config =
            HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256);

        // Create the task list.
        let time_interval_task_id = Id(rng.gen());
        let fixed_size_task_id = Id(rng.gen());
        let mut tasks = HashMap::new();
        tasks.insert(
            time_interval_task_id.clone(),
            DapTaskConfig {
                version,
                collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                leader_url: leader_url.clone(),
                helper_url: helper_url.clone(),
                time_precision,
                query: DapQueryConfig::TimeInterval { min_batch_size: 1 },
                vdaf: vdaf_config.clone(),
                vdaf_verify_key: VdafVerifyKey::Prio3(rng.gen()),
            },
        );
        tasks.insert(
            fixed_size_task_id.clone(),
            DapTaskConfig {
                version,
                collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                leader_url: leader_url.clone(),
                helper_url: helper_url.clone(),
                time_precision,
                query: DapQueryConfig::FixedSize {
                    min_batch_size: 1,
                    max_batch_size: 2,
                },
                vdaf: vdaf_config.clone(),
                vdaf_verify_key: VdafVerifyKey::Prio3(rng.gen()),
            },
        );

        // Authorization tokens, used for all tasks.
        let leader_token = BearerToken::from("this is a bearer token!");
        let collector_token = BearerToken::from("This is a DIFFERENT token.");

        let leader_hpke_receiver_config_list = global_config
            .gen_hpke_receiver_config_list(rng.gen())
            .into_iter()
            .collect();
        let leader = MockAggregator {
            now,
            global_config: global_config.clone(),
            tasks: tasks.clone(),
            hpke_receiver_config_list: leader_hpke_receiver_config_list,
            leader_token: leader_token.clone(),
            collector_token: Some(collector_token.clone()),
            report_store: Arc::new(Mutex::new(HashMap::new())),
            leader_state_store: Arc::new(Mutex::new(HashMap::new())),
            helper_state_store: Arc::new(Mutex::new(HashMap::new())),
            agg_store: Arc::new(Mutex::new(HashMap::new())),
        };

        let helper_hpke_receiver_config_list = global_config
            .gen_hpke_receiver_config_list(rng.gen())
            .into_iter()
            .collect();
        let helper = MockAggregator {
            now,
            global_config,
            tasks,
            leader_token,
            collector_token: None,
            hpke_receiver_config_list: helper_hpke_receiver_config_list,
            report_store: Arc::new(Mutex::new(HashMap::new())),
            leader_state_store: Arc::new(Mutex::new(HashMap::new())),
            helper_state_store: Arc::new(Mutex::new(HashMap::new())),
            agg_store: Arc::new(Mutex::new(HashMap::new())),
        };

        Self {
            now,
            leader,
            helper,
            collector_hpke_receiver_config,
            collector_token,
            time_interval_task_id,
            fixed_size_task_id,
        }
    }

    fn gen_test_upload_req(&self, report: Report) -> DapRequest<BearerToken> {
        let task_id = &self.time_interval_task_id;
        let task_config = self.leader.tasks.get(task_id).unwrap();
        let version = task_config.version.clone();

        DapRequest {
            version,
            media_type: Some(MEDIA_TYPE_REPORT),
            payload: report.get_encoded(),
            url: task_config.leader_url.join("upload").unwrap(),
            sender_auth: None,
        }
    }

    async fn gen_test_agg_init_req(
        &self,
        task_id: &Id,
        report_shares: Vec<ReportShare>,
    ) -> DapRequest<BearerToken> {
        let mut rng = thread_rng();
        let task_config = self.leader.tasks.get(task_id).unwrap();
        let batch_param = match task_config.query {
            DapQueryConfig::TimeInterval { .. } => BatchParameter::TimeInterval,
            _ => panic!("TODO(issue #100)"),
        };

        self.leader_authorized_req(
            task_id,
            task_config.version,
            MEDIA_TYPE_AGG_INIT_REQ,
            AggregateInitializeReq {
                task_id: task_id.clone(),
                agg_job_id: Id(rng.gen()),
                agg_param: Vec::default(),
                batch_param,
                report_shares,
            },
            task_config.helper_url.join("aggregate").unwrap(),
        )
        .await
    }

    async fn gen_test_agg_cont_req(
        &self,
        agg_job_id: Id,
        transitions: Vec<Transition>,
    ) -> DapRequest<BearerToken> {
        let task_id = &self.time_interval_task_id;
        let task_config = self.leader.tasks.get(task_id).unwrap();

        self.leader_authorized_req(
            task_id,
            task_config.version,
            MEDIA_TYPE_AGG_CONT_REQ,
            AggregateContinueReq {
                task_id: task_id.clone(),
                agg_job_id,
                transitions,
            },
            task_config.helper_url.join("aggregate").unwrap(),
        )
        .await
    }

    async fn gen_test_agg_share_req(
        &self,
        report_count: u64,
        checksum: [u8; 32],
    ) -> DapRequest<BearerToken> {
        let task_id = &self.time_interval_task_id;
        let task_config = self.leader.tasks.get(task_id).unwrap();

        self.leader_authorized_req(
            task_id,
            task_config.version,
            MEDIA_TYPE_AGG_SHARE_REQ,
            AggregateShareReq {
                task_id: task_id.clone(),
                batch_selector: BatchSelector::default(),
                agg_param: Vec::default(),
                report_count,
                checksum,
            },
            task_config.helper_url.join("aggregate_share").unwrap(),
        )
        .await
    }

    async fn gen_test_report(&self, task_id: &Id) -> Report {
        // Construct HPKE config list.
        let hpke_config_list = [
            self.leader
                .get_hpke_config_for(Some(task_id))
                .await
                .unwrap()
                .as_ref()
                .clone(),
            self.helper
                .get_hpke_config_for(Some(task_id))
                .await
                .unwrap()
                .as_ref()
                .clone(),
        ];

        // Construct report.
        let vdaf_config: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Count);
        let report = vdaf_config
            .produce_report(&hpke_config_list, self.now, task_id, DapMeasurement::U64(1))
            .unwrap();

        report
    }

    async fn run_agg_job(&self, task_id: &Id) -> Result<(), DapAbort> {
        let wrapped = self.leader.get_task_config_for(task_id).await.unwrap();
        let task_config = wrapped.as_ref().unwrap();

        // Leader: Store received report to ReportStore.
        let selector = &MockAggregateInfo {
            task_id: task_id.clone(),
            agg_rate: 1,
        };
        let (task_id, reports) = get_reports!(self.leader, selector);

        // Leader: Consume report share.
        let mut rng = thread_rng();
        let agg_job_id = Id(rng.gen());
        let transition = task_config
            .vdaf
            .produce_agg_init_req(
                &self.leader,
                &task_config.vdaf_verify_key,
                &task_id,
                &agg_job_id,
                reports,
            )
            .await?;
        assert_matches!(transition, DapLeaderTransition::Continue(..));
        let (leader_state, agg_init_req) = transition.unwrap_continue();

        // Leader: Send aggregate initialization request to Helper and receive response.
        let version = task_config.version.clone();
        let req = self
            .leader_authorized_req(
                &task_id,
                version,
                MEDIA_TYPE_AGG_INIT_REQ,
                agg_init_req,
                task_config.helper_url.join("aggregate").unwrap(),
            )
            .await;
        let res = self.helper.http_post_aggregate(&req).await?;
        let agg_resp = AggregateResp::get_decoded(&res.payload).unwrap();

        // Leader: Produce Leader output share and prepare aggregate continue request for Helper.
        let transition =
            task_config
                .vdaf
                .handle_agg_resp(&task_id, &agg_job_id, leader_state, agg_resp)?;
        assert_matches!(transition, DapLeaderTransition::Uncommitted(..));
        let (leader_uncommitted, agg_cont_req) = transition.unwrap_uncommitted();

        // Leader: Send aggregate continue request to Helper and receive response.
        let version = task_config.version.clone();
        let req = self
            .leader_authorized_req(
                &task_id,
                version,
                MEDIA_TYPE_AGG_CONT_REQ,
                agg_cont_req,
                task_config.helper_url.join("aggregate").unwrap(),
            )
            .await;
        let res = self.helper.http_post_aggregate(&req).await?;
        let agg_resp = AggregateResp::get_decoded(&res.payload)?;

        // Leader: Commit output shares of Leader and Helper.
        let out_shares = task_config
            .vdaf
            .handle_final_agg_resp(leader_uncommitted, agg_resp)?;
        self.leader.put_out_shares(&task_id, out_shares).await?;

        Ok(())
    }

    async fn run_col_job(&self, task_id: &Id, query: &Query) -> Result<(), DapAbort> {
        let wrapped = self.leader.get_task_config_for(task_id).await.unwrap();
        let task_config = wrapped.as_ref().unwrap();

        // Collector->Leader: HTTP POST /collect
        let req = self
            .collector_authorized_req(
                task_config.version,
                MEDIA_TYPE_COLLECT_REQ,
                CollectReq {
                    task_id: task_id.clone(),
                    query: query.clone(),
                    agg_param: Vec::default(),
                },
                task_config.helper_url.join("collect").unwrap(),
            )
            .await;

        // Handle request.
        self.leader.http_post_collect(&req).await?;
        let resp = self.leader.get_pending_collect_jobs().await?;
        let (collect_id, collect_req) = &resp[0];

        // Leader: Handle collect job. First, fetch the aggregate share.
        let leader_agg_share = self
            .leader
            .get_agg_share(&collect_req.task_id, &collect_req.query)
            .await?;
        let leader_enc_agg_share = task_config.vdaf.produce_leader_encrypted_agg_share(
            &task_config.collector_hpke_config,
            &collect_req.task_id,
            &collect_req.query,
            &leader_agg_share,
        )?;

        // Leader->Helper: HTTP POST /aggregate_share
        let agg_share_req = AggregateShareReq {
            task_id: collect_req.task_id.clone(),
            batch_selector: collect_req.query.clone(),
            agg_param: collect_req.agg_param.clone(),
            report_count: leader_agg_share.report_count,
            checksum: leader_agg_share.checksum,
        };
        let req = self
            .leader_authorized_req(
                &task_id,
                task_config.version,
                MEDIA_TYPE_AGG_SHARE_REQ,
                agg_share_req.clone(),
                task_config.helper_url.join("aggregate_share").unwrap(),
            )
            .await;

        // Helper: Handle request.
        let res = self.helper.http_post_aggregate_share(&req).await?;
        let agg_share_resp = AggregateShareResp::get_decoded(&res.payload).unwrap();

        // Leader: Complete the collect job.
        let collect_resp = CollectResp {
            report_count: leader_agg_share.report_count,
            encrypted_agg_shares: vec![leader_enc_agg_share, agg_share_resp.encrypted_agg_share],
        };
        self.leader
            .finish_collect_job(task_id, collect_id, &collect_resp)
            .await?;
        self.leader
            .mark_collected(task_id, &agg_share_req.batch_selector)
            .await?;

        // Collector: Poll the collect job.
        let collect_job = self.leader.poll_collect_job(&task_id, &collect_id).await?;
        assert_matches!(collect_job, DapCollectJob::Done(..));

        Ok(())
    }

    async fn leader_authorized_req<M: Encode>(
        &self,
        task_id: &Id,
        version: DapVersion,
        media_type: &'static str,
        msg: M,
        url: Url,
    ) -> DapRequest<BearerToken> {
        let payload = msg.get_encoded();
        let sender_auth = Some(
            self.leader
                .authorize(task_id, media_type, &payload)
                .await
                .unwrap(),
        );
        DapRequest {
            version,
            media_type: Some(media_type),
            payload,
            url,
            sender_auth,
        }
    }

    async fn collector_authorized_req<M: Encode>(
        &self,
        version: DapVersion,
        media_type: &'static str,
        msg: M,
        url: Url,
    ) -> DapRequest<BearerToken> {
        DapRequest {
            version,
            media_type: Some(media_type),
            payload: msg.get_encoded(),
            url,
            sender_auth: Some(self.collector_token.clone()),
        }
    }
}

// Test that the Helper properly handles the batch parameter in the AggregateInitializeReq.
#[tokio::test]
async fn http_post_aggregate_invalid_batch_selector() {
    let mut rng = thread_rng();
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Helper expects "time_interval" query, but Leader indicates "fixed_size".
    let req = t
        .leader_authorized_req(
            task_id,
            task_config.version,
            MEDIA_TYPE_AGG_INIT_REQ,
            AggregateInitializeReq {
                task_id: task_id.clone(),
                agg_job_id: Id(rng.gen()),
                agg_param: Vec::default(),
                batch_param: BatchParameter::FixedSize {
                    batch_id: Id(rng.gen()),
                },
                report_shares: Vec::default(),
            },
            task_config.helper_url.join("aggregate").unwrap(),
        )
        .await;
    assert_matches!(
        t.helper.http_post_aggregate(&req).await.unwrap_err(),
        DapAbort::QueryMismatch
    );
}

#[tokio::test]
async fn http_post_aggregate_init_unauthorized_request() {
    let t = Test::new();
    let mut req = t
        .gen_test_agg_init_req(&t.time_interval_task_id, Vec::default())
        .await;
    req.sender_auth = None;

    // Expect failure due to missing bearer token.
    assert_matches!(
        t.helper.http_post_aggregate(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        t.helper.http_post_aggregate(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_get_hpke_config_unrecognized_task() {
    let t = Test::new();
    let mut rng = thread_rng();
    let task_id = Id(rng.gen());
    let req = DapRequest {
        version: DapVersion::Draft01,
        media_type: Some(MEDIA_TYPE_HPKE_CONFIG),
        payload: Vec::new(),
        url: Url::parse(&format!(
            "http://aggregator.biz/v01/hpke_config?task_id={}",
            task_id.to_base64url()
        ))
        .unwrap(),
        sender_auth: None,
    };

    assert_matches!(
        t.leader.http_get_hpke_config(&req).await,
        Err(DapAbort::UnrecognizedTask)
    );
}

#[tokio::test]
async fn http_get_hpke_config_missing_task_id() {
    let t = Test::new();
    let req = DapRequest {
        version: DapVersion::Draft01,
        media_type: Some(MEDIA_TYPE_HPKE_CONFIG),
        payload: Vec::new(),
        url: Url::parse("http://aggregator.biz/v01/hpke_config").unwrap(),
        sender_auth: None,
    };

    // An Aggregator is permitted to abort an HPKE config request if the task ID is missing. Note
    // that Daphne-Workder does not implement this behavior. Instead it returns the HPKE config
    // used for all tasks.
    assert_matches!(
        t.leader.http_get_hpke_config(&req).await,
        Err(DapAbort::MissingTaskId)
    );
}

#[tokio::test]
async fn http_post_aggregate_cont_unauthorized_request() {
    let t = Test::new();
    let mut rng = thread_rng();
    let mut req = t.gen_test_agg_cont_req(Id(rng.gen()), Vec::default()).await;
    req.sender_auth = None;

    // Expect failure due to missing bearer token.
    assert_matches!(
        t.helper.http_post_aggregate(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        t.helper.http_post_aggregate(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_post_aggregate_share_unauthorized_request() {
    let t = Test::new();
    let mut req = t.gen_test_agg_share_req(0, [0; 32]).await;
    req.sender_auth = None;

    // Expect failure due to missing bearer token.
    assert_matches!(
        t.helper.http_post_aggregate_share(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        t.helper.http_post_aggregate_share(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

// Test that the Helper handles the batch selector sent from the Leader properly.
#[tokio::test]
async fn http_post_aggregate_share_invalid_batch_selector() {
    let mut rng = thread_rng();
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Helper expects "time_interval" query, but Leader sent "fixed_size".
    let req = t
        .leader_authorized_req(
            task_id,
            task_config.version,
            MEDIA_TYPE_AGG_SHARE_REQ,
            AggregateShareReq {
                task_id: task_id.clone(),
                batch_selector: BatchSelector::FixedSize {
                    batch_id: Id(rng.gen()),
                },
                agg_param: Vec::default(),
                report_count: 0,
                checksum: [0; 32],
            },
            task_config.helper_url.join("aggregate_share").unwrap(),
        )
        .await;
    assert_matches!(
        t.helper.http_post_aggregate_share(&req).await.unwrap_err(),
        DapAbort::QueryMismatch
    );
}

#[tokio::test]
async fn http_post_collect_unauthorized_request() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();
    let mut req = DapRequest {
        version: task_config.version,
        media_type: Some(MEDIA_TYPE_COLLECT_REQ),
        payload: CollectReq {
            task_id: task_id.clone(),
            query: Query::default(),
            agg_param: Vec::default(),
        }
        .get_encoded(),
        url: task_config.leader_url.join("collect").unwrap(),
        sender_auth: None, // Unauthorized request.
    };

    // Expect failure due to missing bearer token.
    assert_matches!(
        t.leader.http_post_collect(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        t.leader.http_post_collect(&req).await,
        Err(DapAbort::UnauthorizedRequest)
    );
}

#[tokio::test]
async fn http_post_aggregate_failure_hpke_decrypt_error() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let (metadata, public_share, mut encrypted_input_share) = (
        report.metadata,
        report.public_share,
        report.encrypted_input_shares[1].clone(),
    );
    encrypted_input_share.payload[0] ^= 0xff; // Cause decryption to fail
    let report_shares = vec![ReportShare {
        metadata,
        public_share,
        encrypted_input_share,
    }];
    let req = t.gen_test_agg_init_req(task_id, report_shares).await;

    // Get AggregateResp and then extract the transition data from inside.
    let agg_resp =
        AggregateResp::get_decoded(&t.helper.http_post_aggregate(&req).await.unwrap().payload)
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
    let t = Test::new();
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let report_shares = vec![ReportShare {
        metadata: report.metadata.clone(),
        public_share: report.public_share,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let req = t.gen_test_agg_init_req(task_id, report_shares).await;

    // Get AggregateResp and then extract the transition data from inside.
    let agg_resp =
        AggregateResp::get_decoded(&t.helper.http_post_aggregate(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_resp.transitions[0];

    // Expect success due to valid ciphertext.
    assert_matches!(transition.var, TransitionVar::Continued(_));
}

#[tokio::test]
async fn http_post_aggregate_failure_report_replayed() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let report_shares = vec![ReportShare {
        metadata: report.metadata.clone(),
        public_share: report.public_share,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let req = t.gen_test_agg_init_req(task_id, report_shares).await;

    // The following scope is to ensure that the report_store lock is released before http_post_aggregate is called.
    {
        let mut report_store_mutex_guard = t.helper.report_store.lock().expect("lock() failed");
        let report_store = report_store_mutex_guard.deref_mut();
        let mut processed = HashSet::new();
        processed.insert(report.metadata.nonce.clone());
        report_store.insert(
            task_id.clone(),
            ReportStore {
                pending: VecDeque::new(),
                processed,
            },
        );
    }

    // Get AggregateResp and then extract the transition data from inside.
    let agg_resp =
        AggregateResp::get_decoded(&t.helper.http_post_aggregate(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_resp.transitions[0];

    // Expect failure due to report store marked as collected.
    assert_matches!(
        transition.var,
        TransitionVar::Failed(TransitionFailure::ReportReplayed)
    );
}

#[tokio::test]
async fn http_post_aggregate_failure_batch_collected() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.helper.tasks.get(task_id).unwrap();

    let report = t.gen_test_report(task_id).await;
    let report_shares = vec![ReportShare {
        metadata: report.metadata.clone(),
        public_share: report.public_share,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let req = t.gen_test_agg_init_req(task_id, report_shares).await;

    // Add mock data to the aggreagte store backend. This is done in its own scope so that the lock
    // is released before running the test. Otherwise the test will deadlock.
    {
        let mut guard = t
            .helper
            .agg_store
            .lock()
            .expect("agg_store: failed to lock");
        let agg_store = guard.entry(task_id.clone()).or_default();

        agg_store.insert(
            BatchSelector::TimeInterval {
                batch_interval: Interval {
                    start: task_config.truncate_time(t.now),
                    duration: task_config.time_precision,
                },
            },
            AggStore {
                agg_share: DapAggregateShare::default(),
                collected: true,
            },
        );
    }

    // Get AggregateResp and then extract the transition data from inside.
    let agg_resp =
        AggregateResp::get_decoded(&t.helper.http_post_aggregate(&req).await.unwrap().payload)
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
    let t = Test::new();
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let report_shares = vec![ReportShare {
        metadata: report.metadata.clone(),
        public_share: report.public_share,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let req = t.gen_test_agg_init_req(task_id, report_shares).await;

    // Send aggregate request.
    let _ = t.helper.http_post_aggregate(&req).await;

    // Send another aggregate request.
    let err = t.helper.http_post_aggregate(&req).await.unwrap_err();

    // Expect failure due to overwriting existing helper state.
    assert_matches!(err, DapAbort::BadRequest(e) =>
        assert_eq!(e, "unexpected message for aggregation job (already exists)")
    );
}

#[tokio::test]
async fn http_post_aggregate_fail_send_cont_req() {
    let t = Test::new();
    let mut rng = thread_rng();
    let req = t.gen_test_agg_cont_req(Id(rng.gen()), Vec::default()).await;

    // Send aggregate continue request to helper.
    let err = t.helper.http_post_aggregate(&req).await.unwrap_err();

    // Expect failure due to sending continue request before initialization request.
    assert_matches!(err, DapAbort::UnrecognizedAggregationJob);
}

#[tokio::test]
async fn http_post_upload_fail_send_invalid_report() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;

    // Construct a report payload with an invalid task ID.
    let mut report_empty_task_id = t.gen_test_report(task_id).await;
    report_empty_task_id.task_id = Id([0; 32]);
    let req = t.gen_test_upload_req(report_empty_task_id);

    // Expect failure due to invalid task ID in report.
    assert_matches!(
        t.leader.http_post_upload(&req).await,
        Err(DapAbort::UnrecognizedTask)
    );

    // Construct an invalid report payload that only has one input share.
    let mut report_one_input_share = t.gen_test_report(task_id).await;
    report_one_input_share.encrypted_input_shares =
        vec![report_one_input_share.encrypted_input_shares[0].clone()];
    let req = t.gen_test_upload_req(report_one_input_share);

    // Expect failure due to incorrect number of input shares
    assert_matches!(
        t.leader.http_post_upload(&req).await,
        Err(DapAbort::UnrecognizedMessage)
    );

    // Construct an invalid report payload that has an incorrect order of input shares.
    let mut report_incorrect_share_order = t.gen_test_report(task_id).await;
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

    let req = t.gen_test_upload_req(report_incorrect_share_order);

    // Expect failure due to incorrect number of input shares
    assert_matches!(
        t.leader.http_post_upload(&req).await,
        Err(DapAbort::UnrecognizedHpkeConfig)
    );
}

#[tokio::test]
async fn get_reports_empty_response() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report.clone());

    // Upload report.
    t.leader
        .http_post_upload(&req)
        .await
        .expect("upload failed unexpectedly");

    // Get one report. This should return with the report that was uploaded earlier.
    // We also check that the task ID associated to the report is the same one we
    // requested.
    let selector = &MockAggregateInfo {
        task_id: task_id.clone(),
        agg_rate: 1,
    };
    let (returned_task_id, reports) = get_reports!(t.leader, selector);
    assert_eq!(reports.len(), 1);
    assert_eq!(&returned_task_id, task_id);

    // Try to get another report. This should not return an error, but simply
    // an empty vector, as we drained the ReportStore above. The task ID
    // associated to the report should be the same one we requested.
    let (returned_task_id, reports) = get_reports!(t.leader, selector);
    assert_eq!(reports.len(), 0);
    assert_eq!(&returned_task_id, task_id);
}

#[tokio::test]
async fn poll_collect_job_test_results() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Collector: Create a CollectReq.
    let version = task_config.version.clone();
    let req = t
        .collector_authorized_req(
            version,
            MEDIA_TYPE_COLLECT_REQ,
            CollectReq {
                task_id: task_id.clone(),
                query: task_config.query_for_current_batch_window(t.now),
                agg_param: Vec::default(),
            },
            task_config.helper_url.join("collect").unwrap(),
        )
        .await;

    // Leader: Handle the CollectReq received from Collector.
    t.leader.http_post_collect(&req).await.unwrap();

    // Expect DapCollectJob::Unknown due to invalid collect ID.
    assert_eq!(
        t.leader
            .poll_collect_job(task_id, &Id::default())
            .await
            .unwrap(),
        DapCollectJob::Unknown
    );

    // Leader: Get pending collect job to obtain collect_id
    let resp = t.leader.get_pending_collect_jobs().await.unwrap();
    let (collect_id, _collect_req) = &resp[0];
    let collect_resp = CollectResp {
        report_count: 0,
        encrypted_agg_shares: Vec::default(),
    };

    // Expect DapCollectJob::Pending due to pending collect job.
    assert_eq!(
        t.leader
            .poll_collect_job(task_id, &collect_id)
            .await
            .unwrap(),
        DapCollectJob::Pending
    );

    // Leader: Complete the collect job by storing CollectResp in LeaderStore.processed.
    t.leader
        .finish_collect_job(&task_id, &collect_id, &collect_resp)
        .await
        .unwrap();

    // Expect DapCollectJob::Done due to processed collect job.
    assert_matches!(
        t.leader
            .poll_collect_job(task_id, &collect_id)
            .await
            .unwrap(),
        DapCollectJob::Done(..)
    );
}

#[tokio::test]
async fn http_post_collect_fail_invalid_batch_interval() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Collector: Create a CollectReq with a very large batch interval.
    let req = t
        .collector_authorized_req(
            task_config.version,
            MEDIA_TYPE_COLLECT_REQ,
            CollectReq {
                task_id: task_id.clone(),
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: t.now - (t.now % task_config.time_precision),
                        duration: t.leader.global_config.max_batch_duration
                            + task_config.time_precision,
                    },
                },
                agg_param: Vec::default(),
            },
            task_config.helper_url.join("collect").unwrap(),
        )
        .await;

    // Leader: Handle the CollectReq received from Collector.
    let err = t.leader.http_post_collect(&req).await.unwrap_err();

    // Fails because the requested batch interval is too large.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too large".to_string()));

    // Collector: Create a CollectReq with a batch interval in the past.
    let req = t
        .collector_authorized_req(
            task_config.version,
            MEDIA_TYPE_COLLECT_REQ,
            CollectReq {
                task_id: task_id.clone(),
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: t.now
                            - (t.now % task_config.time_precision)
                            - t.leader.global_config.min_batch_interval_start
                            - task_config.time_precision,
                        duration: task_config.time_precision * 2,
                    },
                },
                agg_param: Vec::default(),
            },
            task_config.helper_url.join("collect").unwrap(),
        )
        .await;

    // Leader: Handle the CollectReq received from Collector.
    let err = t.leader.http_post_collect(&req).await.unwrap_err();

    // Fails because the requested batch interval is too far into the past.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too far into past".to_string()));

    // Collector: Create a CollectReq with a batch interval in the future.
    let req = t
        .collector_authorized_req(
            task_config.version,
            MEDIA_TYPE_COLLECT_REQ,
            CollectReq {
                task_id: task_id.clone(),
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: t.now - (t.now % task_config.time_precision)
                            + t.leader.global_config.max_batch_interval_end
                            - task_config.time_precision,
                        duration: task_config.time_precision * 2,
                    },
                },
                agg_param: Vec::default(),
            },
            task_config.leader_url.join("collect").unwrap(),
        )
        .await;

    // Leader: Handle the CollectReq received from Collector.
    let err = t.leader.http_post_collect(&req).await.unwrap_err();

    // Fails because the requested batch interval is too far into the future.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too far into future".to_string()));
}

#[tokio::test]
async fn http_post_collect_succeed_max_batch_interval() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Collector: Create a CollectReq with a very large batch interval.
    let req = t
        .collector_authorized_req(
            task_config.version,
            MEDIA_TYPE_COLLECT_REQ,
            CollectReq {
                task_id: task_id.clone(),
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: t.now
                            - (t.now % task_config.time_precision)
                            - t.leader.global_config.max_batch_duration / 2,
                        duration: t.leader.global_config.max_batch_duration,
                    },
                },
                agg_param: Vec::default(),
            },
            task_config.leader_url.join("collect").unwrap(),
        )
        .await;

    // Leader: Handle the CollectReq received from Collector.
    let _collect_uri = t.leader.http_post_collect(&req).await.unwrap();
}

// Send a collect request with an overlapping batch interval.
#[tokio::test]
async fn http_post_collect_fail_overlapping_batch_interval() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Create a report.
    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report.clone());

    // Client: Send upload request to Leader.
    t.leader.http_post_upload(&req).await.unwrap();

    // Leader: Run aggregation job.
    t.run_agg_job(task_id).await.unwrap();

    // Run first collect job (expect success).
    let query = task_config.query_for_current_batch_window(t.now);
    t.run_col_job(task_id, &query).await.unwrap();

    // run a second collect job (expect failure due to overlapping batch).
    assert_matches!(
        t.run_col_job(task_id, &query).await.unwrap_err(),
        DapAbort::BatchOverlap
    );
}

// Test a successful collect request submission.
// This checks that the Leader reponds with the collect ID with the ID associated to the request.
#[tokio::test]
async fn http_post_collect_success() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Collector: Create a CollectReq.
    let collector_collect_req = CollectReq {
        task_id: task_id.clone(),
        query: task_config.query_for_current_batch_window(t.now),
        agg_param: Vec::default(),
    };
    let req = t
        .collector_authorized_req(
            task_config.version,
            MEDIA_TYPE_COLLECT_REQ,
            collector_collect_req.clone(),
            task_config.leader_url.join("collect").unwrap(),
        )
        .await;

    // Leader: Handle the CollectReq received from Collector.
    let url = t.leader.http_post_collect(&req).await.unwrap();
    let resp = t.leader.get_pending_collect_jobs().await.unwrap();
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

// Test that the Leader handles queries from the Collector properly.
#[tokio::test]
async fn http_post_collect_invalid_query() {
    let mut rng = thread_rng();
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Leader expects "time_interval" query, but Collector sent "fixed_size".
    let req = t
        .collector_authorized_req(
            task_config.version,
            MEDIA_TYPE_COLLECT_REQ,
            CollectReq {
                task_id: task_id.clone(),
                query: Query::FixedSize {
                    batch_id: Id(rng.gen()),
                },
                agg_param: Vec::default(),
            },
            task_config.leader_url.join("collect").unwrap(),
        )
        .await;
    assert_matches!(
        t.leader.http_post_collect(&req).await.unwrap_err(),
        DapAbort::QueryMismatch
    );
}

// Test HTTP POST requests with a wrong DAP version.
#[tokio::test]
async fn http_post_fail_wrong_dap_version() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.tasks.get(task_id).unwrap();

    // Send a request with the wrong DAP version.
    let report = t.gen_test_report(task_id).await;
    let mut req = t.gen_test_upload_req(report);
    req.version = DapVersion::Unknown;
    req.url = task_config.leader_url.join("upload").unwrap();

    let err = t.leader.http_post_upload(&req).await.unwrap_err();
    assert_matches!(err, DapAbort::InvalidProtocolVersion);
}

// Test the upload sub-protocol.
#[tokio::test]
async fn successful_http_post_upload() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report);

    t.leader
        .http_post_upload(&req)
        .await
        .expect("upload failed unexpectedly");
}

// Test the end-to-end protocol.
#[tokio::test]
async fn e2e() {
    let t = Test::new();
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report);

    // Client: Send upload request to Leader.
    t.leader.http_post_upload(&req).await.unwrap();

    // Leader: Run aggregation job.
    t.run_agg_job(task_id).await.unwrap();

    // Collector: Create collection job and poll result.
    let query = t
        .leader
        .tasks
        .get(task_id)
        .unwrap()
        .query_for_current_batch_window(t.now);
    t.run_col_job(task_id, &query).await.unwrap();
}
