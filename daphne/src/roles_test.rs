// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    assert_metrics_include, assert_metrics_include_auxiliary_function, async_test_version,
    async_test_versions,
    auth::BearerToken,
    constants::DapMediaType,
    hpke::{HpkeDecrypter, HpkeKemId, HpkeReceiverConfig},
    messages::{
        taskprov, AggregateShareReq, AggregationJobContinueReq, AggregationJobInitReq,
        AggregationJobResp, BatchId, BatchSelector, Collection, CollectionJobId, CollectionReq,
        Extension, Interval, PartialBatchSelector, Query, Report, ReportId, ReportMetadata,
        ReportShare, TaskId, Time, Transition, TransitionFailure, TransitionVar,
    },
    metrics::DaphneMetrics,
    roles::{early_metadata_check, DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    taskprov::TaskprovVersion,
    test_version, test_versions,
    testing::{
        AggStore, DapBatchBucketOwned, MockAggregator, MockAggregatorReportSelector, MockAuditLog,
    },
    vdaf::VdafVerifyKey,
    DapAbort, DapAggregateShare, DapCollectJob, DapGlobalConfig, DapMeasurement, DapQueryConfig,
    DapRequest, DapResource, DapTaskConfig, DapVersion, MetaAggregationJobId, Prio3Config,
    VdafConfig,
};
use assert_matches::assert_matches;
use matchit::Router;
use paste::paste;
use prio::codec::{Decode, ParameterizedEncode};
use rand::{thread_rng, Rng};
use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{Arc, Mutex},
    time::SystemTime,
    vec,
};
use url::Url;

macro_rules! get_reports {
    ($leader:expr, $selector:expr) => {{
        let reports_per_task = $leader.get_reports($selector).await.unwrap();
        assert_eq!(reports_per_task.len(), 1);
        let (task_id, reports_per_part_batch_sel) = reports_per_task.into_iter().next().unwrap();
        assert_eq!(reports_per_part_batch_sel.len(), 1);
        let (part_batch_sel, reports) = reports_per_part_batch_sel.into_iter().next().unwrap();
        (task_id, part_batch_sel, reports)
    }};
}

struct Test {
    now: Time,
    leader: Arc<MockAggregator>,
    helper: Arc<MockAggregator>,
    collector_token: BearerToken,
    time_interval_task_id: TaskId,
    fixed_size_task_id: TaskId,
    expired_task_id: TaskId,
    version: DapVersion,
    prometheus_registry: prometheus::Registry,
}

impl Test {
    fn new(version: DapVersion) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut rng = thread_rng();

        // Global config. In a real deployment, the Leader and Helper may make different choices
        // here.
        let global_config = DapGlobalConfig {
            report_storage_epoch_duration: 604800,    // one week
            report_storage_max_future_time_skew: 300, // 5 minutes
            max_batch_duration: 360000,
            min_batch_interval_start: 259200,
            max_batch_interval_end: 259200,
            supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
            allow_taskprov: true,
            taskprov_version: TaskprovVersion::Draft02,
        };

        // Task Parameters that the Leader and Helper must agree on.
        let vdaf_config = VdafConfig::Prio3(Prio3Config::Count);
        let leader_url = Url::parse("https://leader.com/v02/").unwrap();
        let helper_url = Url::parse("http://helper.org:8788/v02/").unwrap();
        let time_precision = 3600;
        let collector_hpke_receiver_config =
            HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256).unwrap();

        // Create the task list.
        let time_interval_task_id = TaskId(rng.gen());
        let fixed_size_task_id = TaskId(rng.gen());
        let expired_task_id = TaskId(rng.gen());
        let mut tasks = HashMap::new();
        tasks.insert(
            time_interval_task_id.clone(),
            DapTaskConfig {
                version,
                collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                leader_url: leader_url.clone(),
                helper_url: helper_url.clone(),
                time_precision,
                expiration: now + 3600,
                min_batch_size: 1,
                query: DapQueryConfig::TimeInterval,
                vdaf: vdaf_config.clone(),
                dp_config: None,
                vdaf_verify_key: VdafVerifyKey::Prio3(rng.gen()),
                taskprov: false,
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
                expiration: now + 3600,
                min_batch_size: 1,
                query: DapQueryConfig::FixedSize { max_batch_size: 2 },
                vdaf: vdaf_config.clone(),
                dp_config: None,
                vdaf_verify_key: VdafVerifyKey::Prio3(rng.gen()),
                taskprov: false,
            },
        );
        tasks.insert(
            expired_task_id.clone(),
            DapTaskConfig {
                version,
                collector_hpke_config: collector_hpke_receiver_config.config.clone(),
                leader_url,
                helper_url,
                time_precision,
                expiration: now, // Expires this second
                min_batch_size: 1,
                query: DapQueryConfig::TimeInterval,
                vdaf: vdaf_config,
                dp_config: None,
                vdaf_verify_key: VdafVerifyKey::Prio3(rng.gen()),
                taskprov: false,
            },
        );

        // Authorization tokens, used for all tasks.
        let leader_token = BearerToken::from("this is a bearer token!");
        let collector_token = BearerToken::from("This is a DIFFERENT token.");

        // taskprov: VDAF verification key.
        let taskprov_vdaf_verify_key_init = rng.gen::<[u8; 32]>();

        let prometheus_registry = prometheus::Registry::new();

        let helper_hpke_receiver_config_list = global_config
            .gen_hpke_receiver_config_list(rng.gen())
            .collect::<Result<Vec<HpkeReceiverConfig>, _>>()
            .expect("failed to generate HPKE receiver config");
        let helper = Arc::new(MockAggregator {
            global_config: global_config.clone(),
            tasks: Arc::new(Mutex::new(tasks.clone())),
            leader_token: leader_token.clone(),
            collector_token: None,
            hpke_receiver_config_list: helper_hpke_receiver_config_list,
            report_store: Arc::new(Mutex::new(HashMap::new())),
            leader_state_store: Arc::new(Mutex::new(HashMap::new())),
            helper_state_store: Arc::new(Mutex::new(HashMap::new())),
            agg_store: Arc::new(Mutex::new(HashMap::new())),
            collector_hpke_config: collector_hpke_receiver_config.config.clone(),
            taskprov_vdaf_verify_key_init,
            metrics: DaphneMetrics::register(&prometheus_registry, Some("test_helper")).unwrap(),
            audit_log: MockAuditLog::default(),
            peer: None,
        });

        let leader_hpke_receiver_config_list = global_config
            .gen_hpke_receiver_config_list(rng.gen())
            .collect::<Result<Vec<HpkeReceiverConfig>, _>>()
            .expect("failed to generate HPKE receiver config");
        let leader = Arc::new(MockAggregator {
            global_config,
            tasks: Arc::new(Mutex::new(tasks.clone())),
            hpke_receiver_config_list: leader_hpke_receiver_config_list,
            leader_token,
            collector_token: Some(collector_token.clone()),
            report_store: Arc::new(Mutex::new(HashMap::new())),
            leader_state_store: Arc::new(Mutex::new(HashMap::new())),
            helper_state_store: Arc::new(Mutex::new(HashMap::new())),
            agg_store: Arc::new(Mutex::new(HashMap::new())),
            collector_hpke_config: collector_hpke_receiver_config.config,
            taskprov_vdaf_verify_key_init,
            metrics: DaphneMetrics::register(&prometheus_registry, Some("test_leader")).unwrap(),
            audit_log: MockAuditLog::default(),
            peer: Some(Arc::clone(&helper)),
        });

        Self {
            now,
            leader,
            helper,
            collector_token,
            time_interval_task_id,
            fixed_size_task_id,
            expired_task_id,
            version,
            prometheus_registry,
        }
    }

    async fn gen_test_upload_req(
        &self,
        report: Report,
        task_id: &TaskId,
    ) -> DapRequest<BearerToken> {
        let task_config = self.leader.unchecked_get_task_config(task_id).await;
        let version = task_config.version;

        DapRequest {
            version,
            media_type: DapMediaType::Report,
            task_id: Some(task_id.clone()),
            resource: DapResource::Undefined,
            payload: report.get_encoded_with_param(&version),
            url: task_config.leader_url.join("upload").unwrap(),
            ..Default::default()
        }
    }

    async fn gen_test_agg_job_init_req(
        &self,
        task_id: &TaskId,
        version: DapVersion,
        report_shares: Vec<ReportShare>,
    ) -> DapRequest<BearerToken> {
        let mut rng = thread_rng();
        let task_config = self.leader.unchecked_get_task_config(task_id).await;
        let part_batch_sel = match task_config.query {
            DapQueryConfig::TimeInterval { .. } => PartialBatchSelector::TimeInterval,
            DapQueryConfig::FixedSize { .. } => PartialBatchSelector::FixedSizeByBatchId {
                batch_id: BatchId(rng.gen()),
            },
        };

        let agg_job_id = MetaAggregationJobId::gen_for_version(&version);
        self.leader_authorized_req_with_version(
            task_id,
            Some(&agg_job_id),
            task_config.version,
            DapMediaType::AggregationJobInitReq,
            AggregationJobInitReq {
                draft02_task_id: task_id.for_request_payload(&version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                agg_param: Vec::default(),
                part_batch_sel,
                report_shares,
            },
            task_config.helper_url.join("aggregate").unwrap(),
        )
        .await
    }

    async fn gen_test_agg_job_cont_req_with_round(
        &self,
        agg_job_id: &MetaAggregationJobId<'_>,
        transitions: Vec<Transition>,
        round: Option<u16>,
    ) -> DapRequest<BearerToken> {
        let task_id = &self.time_interval_task_id;
        let task_config = self.leader.unchecked_get_task_config(task_id).await;

        self.leader_authorized_req(
            task_id,
            Some(agg_job_id),
            task_config.version,
            DapMediaType::AggregationJobContinueReq,
            AggregationJobContinueReq {
                draft02_task_id: task_id.for_request_payload(&task_config.version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                round,
                transitions,
            },
            task_config.helper_url.join("aggregate").unwrap(),
        )
        .await
    }

    async fn gen_test_agg_job_cont_req(
        &self,
        agg_job_id: &MetaAggregationJobId<'_>,
        transitions: Vec<Transition>,
        version: DapVersion,
    ) -> DapRequest<BearerToken> {
        let round = if version == DapVersion::Draft02 {
            None
        } else {
            Some(1)
        };
        self.gen_test_agg_job_cont_req_with_round(agg_job_id, transitions, round)
            .await
    }

    async fn gen_test_agg_share_req(
        &self,
        report_count: u64,
        checksum: [u8; 32],
    ) -> DapRequest<BearerToken> {
        let task_id = &self.time_interval_task_id;
        let task_config = self.leader.unchecked_get_task_config(task_id).await;

        let url_path = if task_config.version == DapVersion::Draft02 {
            "aggregate_shares".to_string()
        } else {
            format!("tasks/{}/aggregate_shares", task_id.to_base64url())
        };

        self.leader_authorized_req_with_version(
            task_id,
            None,
            task_config.version,
            DapMediaType::AggregateShareReq,
            AggregateShareReq {
                draft02_task_id: task_id.for_request_payload(&task_config.version),
                batch_sel: BatchSelector::default(),
                agg_param: Vec::default(),
                report_count,
                checksum,
            },
            task_config.helper_url.join(&url_path).unwrap(),
        )
        .await
    }

    async fn gen_test_report(&self, task_id: &TaskId) -> Report {
        let version = self.leader.unchecked_get_task_config(task_id).await.version;

        // Construct HPKE config list.
        let hpke_config_list = [
            self.leader
                .get_hpke_config_for(version, Some(task_id))
                .await
                .unwrap()
                .as_ref()
                .clone(),
            self.helper
                .get_hpke_config_for(version, Some(task_id))
                .await
                .unwrap()
                .as_ref()
                .clone(),
        ];

        // Construct report.
        let vdaf_config: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Count);
        vdaf_config
            .produce_report(
                &hpke_config_list,
                self.now,
                task_id,
                DapMeasurement::U64(1),
                self.version,
            )
            .unwrap()
    }

    async fn run_agg_job(&self, task_id: &TaskId) -> Result<(), DapAbort> {
        let wrapped = self
            .leader
            .get_task_config_for(Cow::Owned(task_id.clone()))
            .await
            .unwrap();
        let task_config = wrapped.as_ref().unwrap();

        let report_sel = MockAggregatorReportSelector(task_id.clone());
        let (task_id, part_batch_sel, reports) = get_reports!(self.leader, &report_sel);

        // Leader->Helper: Run aggregation job.
        let _reports_aggregated = self
            .leader
            .run_agg_job(
                &task_id,
                task_config,
                &part_batch_sel,
                reports,
                task_config.leader_url.host_str().unwrap(),
            )
            .await?;
        Ok(())
    }

    async fn run_col_job(&self, task_id: &TaskId, query: &Query) -> Result<(), DapAbort> {
        let wrapped = self
            .leader
            .get_task_config_for(Cow::Owned(task_id.clone()))
            .await
            .unwrap();
        let task_config = wrapped.as_ref().unwrap();

        // Collector->Leader: Initialize collection job.
        let req = self
            .collector_authorized_req(
                task_config.version,
                DapMediaType::CollectReq,
                task_id,
                CollectionReq {
                    draft02_task_id: task_id.for_request_payload(&task_config.version),
                    query: query.clone(),
                    agg_param: Vec::default(),
                },
                task_config.helper_url.join("collect").unwrap(),
            )
            .await;

        // Leader: Handle request from Collector.
        self.leader.handle_collect_job_req(&req).await?;
        let resp = self.leader.get_pending_collect_jobs().await?;
        let (task_id, collect_id, collect_req) = &resp[0];

        // Leader->Helper: Complete collection job.
        let _reports_collected = self
            .leader
            .run_collect_job(
                task_id,
                collect_id,
                task_config,
                collect_req,
                task_config.leader_url.host_str().unwrap(),
            )
            .await?;
        Ok(())
    }

    async fn leader_authorized_req<M: ParameterizedEncode<DapVersion>>(
        &self,
        task_id: &TaskId,
        agg_job_id: Option<&MetaAggregationJobId<'_>>,
        version: DapVersion,
        media_type: DapMediaType,
        msg: M,
        url: Url,
    ) -> DapRequest<BearerToken> {
        let payload = msg.get_encoded_with_param(&version);
        let sender_auth = Some(
            self.leader
                .authorize(task_id, &media_type, &payload)
                .await
                .unwrap(),
        );
        DapRequest {
            version,
            media_type,
            task_id: Some(task_id.clone()),
            resource: agg_job_id.map_or(DapResource::Undefined, |id| id.for_request_path()),
            payload,
            url,
            sender_auth,
            ..Default::default()
        }
    }

    async fn leader_authorized_req_with_version<M: ParameterizedEncode<DapVersion>>(
        &self,
        task_id: &TaskId,
        agg_job_id: Option<&MetaAggregationJobId<'_>>,
        version: DapVersion,
        media_type: DapMediaType,
        msg: M,
        url: Url,
    ) -> DapRequest<BearerToken> {
        let payload = msg.get_encoded_with_param(&version);
        let sender_auth = Some(
            self.leader
                .authorize(task_id, &media_type, &payload)
                .await
                .unwrap(),
        );
        DapRequest {
            version,
            media_type,
            task_id: Some(task_id.clone()),
            resource: agg_job_id.map_or(DapResource::Undefined, |id| id.for_request_path()),
            payload,
            url,
            sender_auth,
            ..Default::default()
        }
    }

    async fn collector_authorized_req<M: ParameterizedEncode<DapVersion>>(
        &self,
        version: DapVersion,
        media_type: DapMediaType,
        task_id: &TaskId,
        msg: M,
        url: Url,
    ) -> DapRequest<BearerToken> {
        let mut rng = thread_rng();
        let collect_job_id = CollectionJobId(rng.gen());
        DapRequest {
            version,
            media_type,
            task_id: Some(task_id.clone()),
            resource: if version == DapVersion::Draft02 {
                DapResource::Undefined
            } else {
                DapResource::CollectionJob(collect_job_id)
            },
            payload: msg.get_encoded_with_param(&version),
            url,
            sender_auth: Some(self.collector_token.clone()),
            ..Default::default()
        }
    }
}

// Test that the Helper properly handles the batch parameter in the AggregationJobInitReq.
async fn handle_agg_job_req_invalid_batch_sel(version: DapVersion) {
    let mut rng = thread_rng();
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;
    let agg_job_id = MetaAggregationJobId::gen_for_version(&version);

    // Helper expects "time_interval" query, but Leader indicates "fixed_size".
    let req = t
        .leader_authorized_req_with_version(
            task_id,
            Some(&agg_job_id),
            task_config.version,
            DapMediaType::AggregationJobInitReq,
            AggregationJobInitReq {
                draft02_task_id: task_id.for_request_payload(&version),
                draft02_agg_job_id: agg_job_id.for_request_payload(),
                agg_param: Vec::default(),
                part_batch_sel: PartialBatchSelector::FixedSizeByBatchId {
                    batch_id: BatchId(rng.gen()),
                },
                report_shares: Vec::default(),
            },
            task_config.helper_url.join("aggregate").unwrap(),
        )
        .await;
    assert_matches!(
        t.helper.handle_agg_job_req(&req).await.unwrap_err(),
        DapAbort::QueryMismatch { .. }
    );

    assert_eq!(t.helper.audit_log.invocations(), 0);
}

async_test_versions! { handle_agg_job_req_invalid_batch_sel }

async fn handle_agg_job_req_init_unauthorized_request(version: DapVersion) {
    let t = Test::new(version);
    let mut req = t
        .gen_test_agg_job_init_req(&t.time_interval_task_id, version, Vec::default())
        .await;
    req.sender_auth = None;

    // Expect failure due to missing bearer token.
    assert_matches!(
        t.helper.handle_agg_job_req(&req).await,
        Err(DapAbort::UnauthorizedRequest { .. })
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        t.helper.handle_agg_job_req(&req).await,
        Err(DapAbort::UnauthorizedRequest { .. })
    );

    assert_eq!(t.helper.audit_log.invocations(), 0);
}

async_test_versions! { handle_agg_job_req_init_unauthorized_request }

// Test that the Helper rejects reports past the expiration date.
async fn handle_agg_job_req_init_expired_task(version: DapVersion) {
    let t = Test::new(version);

    let report = t.gen_test_report(&t.expired_task_id).await;
    let report_share = ReportShare {
        report_metadata: report.report_metadata,
        public_share: report.public_share,
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    };
    let req = t
        .gen_test_agg_job_init_req(&t.expired_task_id, version, vec![report_share])
        .await;

    let resp = t.helper.handle_agg_job_req(&req).await.unwrap();
    let agg_job_resp = AggregationJobResp::get_decoded(&resp.payload).unwrap();
    assert_eq!(agg_job_resp.transitions.len(), 1);
    assert_matches!(
        agg_job_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::TaskExpired)
    );

    assert_eq!(t.helper.audit_log.invocations(), 1);
}

async_test_versions! { handle_agg_job_req_init_expired_task }

// Test that the Helper rejects reports with a bad round number.
async fn handle_agg_job_req_bad_round(version: DapVersion) {
    let t = Test::new(version);
    if version == DapVersion::Draft02 {
        // Nothing to test.
        return;
    }

    let report = t.gen_test_report(&t.time_interval_task_id).await;
    let report_share = ReportShare {
        report_metadata: report.report_metadata,
        public_share: report.public_share,
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    };
    let req = t
        .gen_test_agg_job_init_req(&t.time_interval_task_id, version, vec![report_share])
        .await;
    let agg_job_id = match &req.resource {
        DapResource::AggregationJob(agg_job_id) => agg_job_id.clone(),
        _ => panic!("agg_job_id resource missing!"),
    };
    let resp = t.helper.handle_agg_job_req(&req).await.unwrap();

    // AggregationJobInitReq succeeds
    assert_eq!(t.helper.audit_log.invocations(), 1);

    let agg_job_resp = AggregationJobResp::get_decoded(&resp.payload).unwrap();
    assert_eq!(agg_job_resp.transitions.len(), 1);
    assert_matches!(agg_job_resp.transitions[0].var, TransitionVar::Continued(_));
    // Test wrong round
    let req = t
        .gen_test_agg_job_cont_req_with_round(
            &MetaAggregationJobId::Draft05(Cow::Borrowed(&agg_job_id)),
            Vec::default(),
            Some(2),
        )
        .await;
    assert_matches!(
        t.helper.handle_agg_job_req(&req).await,
        Err(DapAbort::RoundMismatch { .. })
    );

    // AggregationJobContinueReq fails
    assert_eq!(t.helper.audit_log.invocations(), 1);
}

async_test_versions! { handle_agg_job_req_bad_round }

// Test that the Helper rejects reports with a bad round id
async fn handle_agg_job_req_zero_round(version: DapVersion) {
    let t = Test::new(version);
    if version == DapVersion::Draft02 {
        // Nothing to test.
        return;
    }

    let report = t.gen_test_report(&t.time_interval_task_id).await;
    let report_share = ReportShare {
        report_metadata: report.report_metadata,
        public_share: report.public_share,
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    };
    let req = t
        .gen_test_agg_job_init_req(&t.time_interval_task_id, version, vec![report_share])
        .await;
    let agg_job_id = match &req.resource {
        DapResource::AggregationJob(agg_job_id) => agg_job_id.clone(),
        _ => panic!("agg_job_id resource missing!"),
    };
    let resp = t.helper.handle_agg_job_req(&req).await.unwrap();

    // AggregationJobInitReq succeeds
    assert_eq!(t.helper.audit_log.invocations(), 1);

    let agg_job_resp = AggregationJobResp::get_decoded(&resp.payload).unwrap();
    assert_eq!(agg_job_resp.transitions.len(), 1);
    assert_matches!(agg_job_resp.transitions[0].var, TransitionVar::Continued(_));
    // Test wrong round
    let req = t
        .gen_test_agg_job_cont_req_with_round(
            &MetaAggregationJobId::Draft05(Cow::Borrowed(&agg_job_id)),
            Vec::default(),
            Some(0),
        )
        .await;
    assert_matches!(
        t.helper.handle_agg_job_req(&req).await,
        Err(DapAbort::UnrecognizedMessage { .. })
    );

    // AggregationJobContinueReq fails
    assert_eq!(t.helper.audit_log.invocations(), 1);
}

async_test_versions! { handle_agg_job_req_zero_round }

async fn handle_hpke_config_req_unrecognized_task(version: DapVersion) {
    let t = Test::new(version);
    let mut rng = thread_rng();
    let task_id = TaskId(rng.gen());
    let req = DapRequest {
        version: DapVersion::Draft02,
        media_type: DapMediaType::HpkeConfigList,
        payload: Vec::new(),
        task_id: Some(task_id.clone()),
        resource: DapResource::Undefined,
        url: Url::parse(&format!(
            "http://aggregator.biz/v02/hpke_config?task_id={}",
            task_id.to_base64url()
        ))
        .unwrap(),
        ..Default::default()
    };

    assert_matches!(
        t.leader.handle_hpke_config_req(&req).await,
        Err(DapAbort::UnrecognizedTask)
    );
}

async_test_versions! { handle_hpke_config_req_unrecognized_task }

async fn handle_hpke_config_req_missing_task_id(version: DapVersion) {
    let t = Test::new(version);
    let req = DapRequest {
        version: DapVersion::Draft02,
        media_type: DapMediaType::HpkeConfigList,
        task_id: Some(t.time_interval_task_id.clone()),
        resource: DapResource::Undefined,
        payload: Vec::new(),
        url: Url::parse("http://aggregator.biz/v02/hpke_config").unwrap(),
        ..Default::default()
    };

    // An Aggregator is permitted to abort an HPKE config request if the task ID is missing. Note
    // that Daphne-Workder does not implement this behavior. Instead it returns the HPKE config
    // used for all tasks.
    assert_matches!(
        t.leader.handle_hpke_config_req(&req).await,
        Err(DapAbort::MissingTaskId)
    );
}

async_test_versions! { handle_hpke_config_req_missing_task_id }

async fn handle_agg_job_req_cont_unauthorized_request(version: DapVersion) {
    let t = Test::new(version);
    let agg_job_id = MetaAggregationJobId::gen_for_version(&version);
    let mut req = t
        .gen_test_agg_job_cont_req(&agg_job_id, Vec::default(), version)
        .await;
    req.sender_auth = None;

    // Expect failure due to missing bearer token.
    assert_matches!(
        t.helper.handle_agg_job_req(&req).await,
        Err(DapAbort::UnauthorizedRequest { .. })
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        t.helper.handle_agg_job_req(&req).await,
        Err(DapAbort::UnauthorizedRequest { .. })
    );

    assert_eq!(t.helper.audit_log.invocations(), 0);
}

async_test_versions! { handle_agg_job_req_cont_unauthorized_request }

async fn handle_agg_share_req_unauthorized_request(version: DapVersion) {
    let t = Test::new(version);
    let mut req = t.gen_test_agg_share_req(0, [0; 32]).await;
    req.sender_auth = None;

    // Expect failure due to missing bearer token.
    assert_matches!(
        t.helper.handle_agg_share_req(&req).await,
        Err(DapAbort::UnauthorizedRequest { .. })
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        t.helper.handle_agg_share_req(&req).await,
        Err(DapAbort::UnauthorizedRequest { .. })
    );
}

async_test_versions! { handle_agg_share_req_unauthorized_request }

// Test that the Helper handles the batch selector sent from the Leader properly.
async fn handle_agg_share_req_invalid_batch_sel(version: DapVersion) {
    let mut rng = thread_rng();
    let t = Test::new(version);

    // Helper expects "time_interval" query, but Leader sent "fixed_size".
    let task_config = t
        .leader
        .unchecked_get_task_config(&t.time_interval_task_id)
        .await;
    let req = t
        .leader_authorized_req_with_version(
            &t.time_interval_task_id,
            None,
            task_config.version,
            DapMediaType::AggregateShareReq,
            AggregateShareReq {
                draft02_task_id: t.time_interval_task_id.for_request_payload(&version),
                batch_sel: BatchSelector::FixedSizeByBatchId {
                    batch_id: BatchId(rng.gen()),
                },
                agg_param: Vec::default(),
                report_count: 0,
                checksum: [0; 32],
            },
            task_config.helper_url.join("aggregate_share").unwrap(),
        )
        .await;
    assert_matches!(
        t.helper.handle_agg_share_req(&req).await.unwrap_err(),
        DapAbort::QueryMismatch { .. }
    );

    // Leader sends aggregate share request for unrecognized batch ID.
    let task_config = t
        .leader
        .unchecked_get_task_config(&t.fixed_size_task_id)
        .await;
    let req = t
        .leader_authorized_req_with_version(
            &t.fixed_size_task_id,
            None,
            task_config.version,
            DapMediaType::AggregateShareReq,
            AggregateShareReq {
                draft02_task_id: t.fixed_size_task_id.for_request_payload(&version),
                batch_sel: BatchSelector::FixedSizeByBatchId {
                    batch_id: BatchId(rng.gen()), // Unrecognized batch ID
                },
                agg_param: Vec::default(),
                report_count: 0,
                checksum: [0; 32],
            },
            task_config.helper_url.join("aggregate_share").unwrap(),
        )
        .await;
    assert_matches!(
        t.helper.handle_agg_share_req(&req).await.unwrap_err(),
        DapAbort::BatchInvalid { .. }
    );
}

async_test_versions! { handle_agg_share_req_invalid_batch_sel }

async fn handle_collect_job_req_unauthorized_request(version: DapVersion) {
    let mut rng = thread_rng();
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;
    let collect_job_id = CollectionJobId(rng.gen());
    let url_path = if task_config.version == DapVersion::Draft02 {
        "collect".to_string()
    } else {
        format!(
            "tasks/{}/collection_jobs/{}",
            task_id.to_base64url(),
            collect_job_id.to_base64url()
        )
    };
    let mut req = DapRequest {
        version: task_config.version,
        media_type: DapMediaType::CollectReq,
        task_id: Some(task_id.clone()),
        resource: if version == DapVersion::Draft02 {
            DapResource::Undefined
        } else {
            DapResource::CollectionJob(collect_job_id)
        },
        payload: CollectionReq {
            draft02_task_id: task_id.for_request_payload(&version),
            query: Query::default(),
            agg_param: Vec::default(),
        }
        .get_encoded_with_param(&task_config.version),
        url: task_config.leader_url.join(&url_path).unwrap(),
        ..Default::default() // Unauthorized request.
    };

    // Expect failure due to missing bearer token.
    assert_matches!(
        t.leader.handle_collect_job_req(&req).await,
        Err(DapAbort::UnauthorizedRequest { .. })
    );

    // Expect failure due to incorrect bearer token.
    req.sender_auth = Some(BearerToken::from("incorrect auth token!".to_string()));
    assert_matches!(
        t.leader.handle_collect_job_req(&req).await,
        Err(DapAbort::UnauthorizedRequest { .. })
    );
}

async_test_versions! { handle_collect_job_req_unauthorized_request }

async fn handle_agg_job_req_failure_hpke_decrypt_error(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let (report_metadata, public_share, mut encrypted_input_share) = (
        report.report_metadata,
        report.public_share,
        report.encrypted_input_shares[1].clone(),
    );
    encrypted_input_share.payload[0] ^= 0xff; // Cause decryption to fail
    let report_shares = vec![ReportShare {
        report_metadata,
        public_share,
        encrypted_input_share,
    }];
    let req = t
        .gen_test_agg_job_init_req(task_id, version, report_shares)
        .await;

    // Get AggregationJobResp and then extract the transition data from inside.
    let agg_job_resp =
        AggregationJobResp::get_decoded(&t.helper.handle_agg_job_req(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_job_resp.transitions[0];

    // Expect failure due to invalid ciphertext.
    assert_matches!(
        transition.var,
        TransitionVar::Failed(TransitionFailure::HpkeDecryptError)
    );
}

async_test_versions! { handle_agg_job_req_failure_hpke_decrypt_error }

async fn handle_agg_job_req_transition_continue(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let report_shares = vec![ReportShare {
        report_metadata: report.report_metadata.clone(),
        public_share: report.public_share,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let req = t
        .gen_test_agg_job_init_req(task_id, version, report_shares)
        .await;

    // Get AggregationJobResp and then extract the transition data from inside.
    let agg_job_resp =
        AggregationJobResp::get_decoded(&t.helper.handle_agg_job_req(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_job_resp.transitions[0];

    // Expect success due to valid ciphertext.
    assert_matches!(transition.var, TransitionVar::Continued(_));
}

async_test_versions! { handle_agg_job_req_transition_continue }

async fn handle_agg_job_req_failure_report_replayed(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let report_shares = vec![ReportShare {
        report_metadata: report.report_metadata.clone(),
        public_share: report.public_share,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let req = t
        .gen_test_agg_job_init_req(task_id, version, report_shares)
        .await;

    // Add dummy data to report store backend. This is done in a new scope so that the lock on the
    // report store is released before running the test.
    {
        let mut guard = t
            .helper
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        let report_store = guard.entry(task_id.clone()).or_default();
        report_store
            .processed
            .insert(report.report_metadata.id.clone());
    }

    // Get AggregationJobResp and then extract the transition data from inside.
    let agg_job_resp =
        AggregationJobResp::get_decoded(&t.helper.handle_agg_job_req(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_job_resp.transitions[0];

    // Expect failure due to report store marked as collected.
    assert_matches!(
        transition.var,
        TransitionVar::Failed(TransitionFailure::ReportReplayed)
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_helper_report_counter{host="helper.org",status="rejected_report_replayed"}"#: 1,
        r#"test_helper_inbound_request_counter{host="helper.org",type="aggregate"}"#: 1,
        r#"test_helper_aggregation_job_counter{host="helper.org",status="started"}"#: 1,
    });
}

async_test_versions! { handle_agg_job_req_failure_report_replayed }

async fn handle_agg_job_req_failure_batch_collected(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.helper.unchecked_get_task_config(task_id).await;

    let report = t.gen_test_report(task_id).await;
    let report_shares = vec![ReportShare {
        report_metadata: report.report_metadata.clone(),
        public_share: report.public_share,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let req = t
        .gen_test_agg_job_init_req(task_id, version, report_shares)
        .await;

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
            DapBatchBucketOwned::TimeInterval {
                batch_window: task_config.quantized_time_lower_bound(t.now),
            },
            AggStore {
                agg_share: DapAggregateShare::default(),
                collected: true,
            },
        );
    }

    // Get AggregationJobResp and then extract the transition data from inside.
    let agg_job_resp =
        AggregationJobResp::get_decoded(&t.helper.handle_agg_job_req(&req).await.unwrap().payload)
            .unwrap();
    let transition = &agg_job_resp.transitions[0];

    assert_eq!(t.helper.audit_log.invocations(), 1);

    // Expect failure due to report store marked as collected.
    assert_matches!(
        transition.var,
        TransitionVar::Failed(TransitionFailure::BatchCollected)
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_helper_report_counter{host="helper.org",status="rejected_batch_collected"}"#: 1,
        r#"test_helper_inbound_request_counter{host="helper.org",type="aggregate"}"#: 1,
        r#"test_helper_aggregation_job_counter{host="helper.org",status="started"}"#: 1,
    });
}

async_test_versions! { handle_agg_job_req_failure_batch_collected }

async fn handle_agg_job_req_abort_helper_state_overwritten(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let report_shares = vec![ReportShare {
        report_metadata: report.report_metadata.clone(),
        public_share: report.public_share,
        // 1st share is for Leader and the rest is for Helpers (note that there is only 1 helper).
        encrypted_input_share: report.encrypted_input_shares[1].clone(),
    }];
    let req = t
        .gen_test_agg_job_init_req(task_id, version, report_shares)
        .await;

    // Send aggregate request.
    let _ = t.helper.handle_agg_job_req(&req).await;

    assert_eq!(t.helper.audit_log.invocations(), 1);

    // Send another aggregate request.
    let err = t.helper.handle_agg_job_req(&req).await.unwrap_err();

    assert_eq!(t.helper.audit_log.invocations(), 1);

    // Expect failure due to overwriting existing helper state.
    assert_matches!(err, DapAbort::BadRequest(e) =>
        assert_eq!(e, "unexpected message for aggregation job (already exists)")
    );
}

async_test_versions! { handle_agg_job_req_abort_helper_state_overwritten }

async fn handle_agg_job_req_fail_send_cont_req(version: DapVersion) {
    let t = Test::new(version);
    let agg_job_id = MetaAggregationJobId::gen_for_version(&version);
    let req = t
        .gen_test_agg_job_cont_req(&agg_job_id, Vec::default(), version)
        .await;

    assert_eq!(t.helper.audit_log.invocations(), 0);

    // Send aggregate continue request to helper.
    let err = t.helper.handle_agg_job_req(&req).await.unwrap_err();

    // Expect failure due to sending continue request before initialization request.
    assert_matches!(err, DapAbort::UnrecognizedAggregationJob { .. });
}

async_test_versions! { handle_agg_job_req_fail_send_cont_req }

async fn handle_upload_req_fail_send_invalid_report(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    // Construct a report payload with an invalid task ID.
    let report_invalid_task_id = t.gen_test_report(task_id).await;
    let req = DapRequest {
        version: task_config.version,
        media_type: DapMediaType::Report,
        task_id: Some(TaskId([0; 32])),
        resource: DapResource::Undefined,
        payload: report_invalid_task_id.get_encoded_with_param(&task_config.version),
        url: task_config.leader_url.join("upload").unwrap(),
        ..Default::default()
    };

    // Expect failure due to invalid task ID in report.
    assert_matches!(
        t.leader.handle_upload_req(&req).await,
        Err(DapAbort::UnrecognizedTask)
    );

    // Construct an invalid report payload that only has one input share.
    let mut report_one_input_share = t.gen_test_report(task_id).await;
    report_one_input_share.encrypted_input_shares =
        vec![report_one_input_share.encrypted_input_shares[0].clone()];
    let req = t.gen_test_upload_req(report_one_input_share, task_id).await;

    // Expect failure due to incorrect number of input shares
    assert_matches!(
        t.leader.handle_upload_req(&req).await,
        Err(DapAbort::UnrecognizedMessage { .. })
    );
}

async_test_versions! { handle_upload_req_fail_send_invalid_report }

// Test that the Leader rejects reports past the expiration date.
async fn handle_upload_req_task_expired(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.expired_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    let report = t.gen_test_report(task_id).await;
    let req = DapRequest {
        version: task_config.version,
        media_type: DapMediaType::Report,
        task_id: Some(task_id.clone()),
        resource: DapResource::Undefined,
        payload: report.get_encoded_with_param(&version),
        url: task_config.leader_url.join("upload").unwrap(),
        ..Default::default()
    };

    assert_matches!(
        t.leader.handle_upload_req(&req).await.unwrap_err(),
        DapAbort::ReportTooLate
    );
}

async_test_versions! { handle_upload_req_task_expired }

async fn get_reports_empty_response(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report.clone(), task_id).await;

    // Upload report.
    t.leader
        .handle_upload_req(&req)
        .await
        .expect("upload failed unexpectedly");

    // Get one report. This should return with the report that was uploaded earlier.
    // We also check that the task ID associated to the report is the same one we
    // requested.
    let report_sel = MockAggregatorReportSelector(task_id.clone());
    let (returned_task_id, _part_batch_sel, reports) = get_reports!(t.leader, &report_sel);
    assert_eq!(reports.len(), 1);
    assert_eq!(&returned_task_id, task_id);

    // Try to get another report. This should not return an error, but simply
    // an empty vector, as we drained the ReportStore above. The task ID
    // associated to the report should be the same one we requested.
    let (returned_task_id, _part_batch_sel, reports) = get_reports!(t.leader, &report_sel);
    assert_eq!(reports.len(), 0);
    assert_eq!(&returned_task_id, task_id);
}

async_test_versions! { get_reports_empty_response }

async fn poll_collect_job_test_results(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    // Collector: Create a CollectReq.
    let version = task_config.version;
    let req = t
        .collector_authorized_req(
            version,
            DapMediaType::CollectReq,
            task_id,
            CollectionReq {
                draft02_task_id: task_id.for_request_payload(&version),
                query: task_config.query_for_current_batch_window(t.now),
                agg_param: Vec::default(),
            },
            task_config.helper_url.join("collect").unwrap(),
        )
        .await;

    // Leader: Handle the CollectReq received from Collector.
    t.leader.handle_collect_job_req(&req).await.unwrap();

    // Expect DapCollectJob::Unknown due to invalid collect ID.
    assert_eq!(
        t.leader
            .poll_collect_job(task_id, &CollectionJobId::default())
            .await
            .unwrap(),
        DapCollectJob::Unknown
    );

    // Leader: Get pending collect job to obtain collect_id
    let resp = t.leader.get_pending_collect_jobs().await.unwrap();
    let (_task_id, collect_id, _collect_req) = &resp[0];
    let collect_resp = Collection {
        part_batch_sel: PartialBatchSelector::TimeInterval,
        report_count: 0,
        interval: if version == DapVersion::Draft02 {
            None
        } else {
            Some(Interval {
                start: 0,
                duration: 2000000000,
            })
        },
        encrypted_agg_shares: Vec::default(),
    };

    // Expect DapCollectJob::Pending due to pending collect job.
    assert_eq!(
        t.leader
            .poll_collect_job(task_id, collect_id)
            .await
            .unwrap(),
        DapCollectJob::Pending
    );

    // Leader: Complete the collect job by storing CollectResp in LeaderStore.processed.
    t.leader
        .finish_collect_job(task_id, collect_id, &collect_resp)
        .await
        .unwrap();

    // Expect DapCollectJob::Done due to processed collect job.
    assert_matches!(
        t.leader
            .poll_collect_job(task_id, collect_id)
            .await
            .unwrap(),
        DapCollectJob::Done(..)
    );
}

async_test_versions! { poll_collect_job_test_results }

async fn handle_collect_job_req_fail_invalid_batch_interval(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    // Collector: Create a CollectReq with a very large batch interval.
    let req = t
        .collector_authorized_req(
            version,
            DapMediaType::CollectReq,
            task_id,
            CollectionReq {
                draft02_task_id: task_id.for_request_payload(&version),
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: task_config.quantized_time_lower_bound(t.now),
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
    let err = t.leader.handle_collect_job_req(&req).await.unwrap_err();

    // Fails because the requested batch interval is too large.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too large".to_string()));

    // Collector: Create a CollectReq with a batch interval in the past.
    let req = t
        .collector_authorized_req(
            version,
            DapMediaType::CollectReq,
            task_id,
            CollectionReq {
                draft02_task_id: task_id.for_request_payload(&version),
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: task_config.quantized_time_lower_bound(t.now)
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
    let err = t.leader.handle_collect_job_req(&req).await.unwrap_err();

    // Fails because the requested batch interval is too far into the past.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too far into past".to_string()));

    // Collector: Create a CollectReq with a batch interval in the future.
    let req = t
        .collector_authorized_req(
            version,
            DapMediaType::CollectReq,
            task_id,
            CollectionReq {
                draft02_task_id: task_id.for_request_payload(&version),
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: task_config.quantized_time_lower_bound(t.now)
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
    let err = t.leader.handle_collect_job_req(&req).await.unwrap_err();

    // Fails because the requested batch interval is too far into the future.
    assert_matches!(err, DapAbort::BadRequest(s) => assert_eq!(s, "batch interval too far into future".to_string()));
}

async_test_versions! { handle_collect_job_req_fail_invalid_batch_interval }

async fn handle_collect_job_req_succeed_max_batch_interval(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    // Collector: Create a CollectReq with a very large batch interval.
    let req = t
        .collector_authorized_req(
            version,
            DapMediaType::CollectReq,
            task_id,
            CollectionReq {
                draft02_task_id: task_id.for_request_payload(&version),
                query: Query::TimeInterval {
                    batch_interval: Interval {
                        start: task_config.quantized_time_lower_bound(t.now)
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
    let _collect_uri = t.leader.handle_collect_job_req(&req).await.unwrap();
}

async_test_versions! { handle_collect_job_req_succeed_max_batch_interval }

// Send a collect request with an overlapping batch interval.
async fn handle_collect_job_req_fail_overlapping_batch_interval(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    // Create a report.
    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report.clone(), task_id).await;

    // Client: Send upload request to Leader.
    t.leader.handle_upload_req(&req).await.unwrap();

    // Leader: Run aggregation job.
    t.run_agg_job(task_id).await.unwrap();

    // Run first collect job (expect success).
    let query = task_config.query_for_current_batch_window(t.now);
    t.run_col_job(task_id, &query).await.unwrap();

    // run a second collect job (expect failure due to overlapping batch).
    assert_matches!(
        t.run_col_job(task_id, &query).await.unwrap_err(),
        DapAbort::BatchOverlap { .. }
    );
}

async_test_versions! { handle_collect_job_req_fail_overlapping_batch_interval }

// Test a successful collect request submission.
// This checks that the Leader reponds with the collect ID with the ID associated to the request.
async fn handle_collect_job_req_success(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    // Collector: Create a CollectReq.
    let collector_collect_req = CollectionReq {
        draft02_task_id: task_id.for_request_payload(&version),
        query: task_config.query_for_current_batch_window(t.now),
        agg_param: Vec::default(),
    };
    let req = t
        .collector_authorized_req(
            version,
            DapMediaType::CollectReq,
            task_id,
            collector_collect_req.clone(),
            task_config.leader_url.join("collect").unwrap(),
        )
        .await;

    // Leader: Handle the CollectReq received from Collector.
    let url = t.leader.handle_collect_job_req(&req).await.unwrap();
    let resp = t.leader.get_pending_collect_jobs().await.unwrap();
    let (_leader_task_id, leader_collect_id, leader_collect_req) = &resp[0];

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

async_test_versions! { handle_collect_job_req_success }

// Test that the Leader handles queries from the Collector properly.
async fn handle_collect_job_req_invalid_query(version: DapVersion) {
    let mut rng = thread_rng();
    let t = Test::new(version);

    // Leader expects "time_interval" query, but Collector sent "fixed_size".
    let task_config = t
        .leader
        .unchecked_get_task_config(&t.time_interval_task_id)
        .await;
    let req = t
        .collector_authorized_req(
            task_config.version,
            DapMediaType::CollectReq,
            &t.time_interval_task_id,
            CollectionReq {
                draft02_task_id: t.time_interval_task_id.for_request_payload(&version),
                query: Query::FixedSizeByBatchId {
                    batch_id: BatchId(rng.gen()),
                },
                agg_param: Vec::default(),
            },
            task_config.leader_url.join("collect").unwrap(),
        )
        .await;
    assert_matches!(
        t.leader.handle_collect_job_req(&req).await.unwrap_err(),
        DapAbort::QueryMismatch { .. }
    );

    // Collector indicates unrecognized batch ID.
    let task_config = t
        .leader
        .unchecked_get_task_config(&t.fixed_size_task_id)
        .await;
    let req = t
        .collector_authorized_req(
            task_config.version,
            DapMediaType::CollectReq,
            &t.fixed_size_task_id,
            CollectionReq {
                draft02_task_id: t.fixed_size_task_id.for_request_payload(&version),
                query: Query::FixedSizeByBatchId {
                    batch_id: BatchId(rng.gen()), // Unrecognized batch ID
                },
                agg_param: Vec::default(),
            },
            task_config.leader_url.join("collect").unwrap(),
        )
        .await;
    assert_matches!(
        t.leader.handle_collect_job_req(&req).await.unwrap_err(),
        DapAbort::BatchInvalid { .. }
    );
}

async_test_versions! { handle_collect_job_req_invalid_query }

// Test HTTP POST requests with a wrong DAP version.
async fn http_post_fail_unknown_version(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    // Send a request with the wrong DAP version.
    let report = t.gen_test_report(task_id).await;
    let mut req = t.gen_test_upload_req(report, task_id).await;
    req.version = DapVersion::Unknown;
    req.url = task_config.leader_url.join("upload").unwrap();

    let err = t.leader.handle_upload_req(&req).await.unwrap_err();
    assert_matches!(err, DapAbort::BadRequest(details) => assert_eq!(details, "DAP version of request is not recognized"));
}

async_test_versions! { http_post_fail_unknown_version }

async fn handle_upload_req(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;

    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report, task_id).await;

    t.leader
        .handle_upload_req(&req)
        .await
        .expect("upload failed unexpectedly");
}

async_test_versions! { handle_upload_req }

async fn e2e_time_interval(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.time_interval_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report, task_id).await;

    // Client: Send upload request to Leader.
    t.leader.handle_upload_req(&req).await.unwrap();

    // Leader: Run aggregation job.
    t.run_agg_job(task_id).await.unwrap();

    // Collector: Create collection job and poll result.
    let query = task_config.query_for_current_batch_window(t.now);
    t.run_col_job(task_id, &query).await.unwrap();

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_helper_inbound_request_counter{host="helper.org",type="aggregate"}"#: 2,
        r#"test_helper_inbound_request_counter{host="helper.org",type="collect"}"#: 1,
        r#"test_leader_report_counter{host="leader.com",status="aggregated"}"#: 1,
        r#"test_helper_report_counter{host="helper.org",status="aggregated"}"#: 1,
        r#"test_leader_report_counter{host="leader.com",status="collected"}"#: 1,
        r#"test_helper_report_counter{host="helper.org",status="collected"}"#: 1,
        r#"test_helper_aggregation_job_counter{host="helper.org",status="started"}"#: 1,
        r#"test_helper_aggregation_job_counter{host="helper.org",status="completed"}"#: 1,
    });
}

async_test_versions! { e2e_time_interval }

async fn e2e_fixed_size(version: DapVersion) {
    let t = Test::new(version);
    let task_id = &t.fixed_size_task_id;
    let task_config = t.leader.unchecked_get_task_config(task_id).await;

    let report = t.gen_test_report(task_id).await;
    let req = t.gen_test_upload_req(report, task_id).await;

    // Client: Send upload request to Leader.
    t.leader.handle_upload_req(&req).await.unwrap();

    // Leader: Run aggregation job.
    t.run_agg_job(task_id).await.unwrap();

    // Collector: Create collection job and poll result.
    let query = Query::FixedSizeByBatchId {
        batch_id: t.leader.current_batch_id(task_id, &task_config).unwrap(),
    };
    t.run_col_job(task_id, &query).await.unwrap();

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_helper_inbound_request_counter{host="helper.org",type="aggregate"}"#: 2,
        r#"test_helper_inbound_request_counter{host="helper.org",type="collect"}"#: 1,
        r#"test_leader_report_counter{host="leader.com",status="aggregated"}"#: 1,
        r#"test_helper_report_counter{host="helper.org",status="aggregated"}"#: 1,
        r#"test_leader_report_counter{host="leader.com",status="collected"}"#: 1,
        r#"test_helper_report_counter{host="helper.org",status="collected"}"#: 1,
        r#"test_helper_aggregation_job_counter{host="helper.org",status="started"}"#: 1,
        r#"test_helper_aggregation_job_counter{host="helper.org",status="completed"}"#: 1,
    });
}

async_test_versions! { e2e_fixed_size }

async fn e2e_taskprov(version: DapVersion) {
    let t = Test::new(version);
    let vdaf = VdafConfig::Prio3(Prio3Config::Count);

    // Create the upload extension.
    let taskprov_ext_payload = taskprov::TaskConfig {
        task_info: "cool task".as_bytes().to_vec(),
        aggregator_endpoints: vec![
            taskprov::UrlBytes {
                bytes: b"https://leader.com/".to_vec(),
            },
            taskprov::UrlBytes {
                bytes: b"http://helper.org:8788/".to_vec(),
            },
        ],
        query_config: taskprov::QueryConfig {
            time_precision: 3600,
            max_batch_query_count: 1,
            min_batch_size: 1,
            var: taskprov::QueryConfigVar::FixedSize { max_batch_size: 2 },
        },
        task_expiration: t.now + 86400 * 14,
        vdaf_config: taskprov::VdafConfig {
            dp_config: taskprov::DpConfig::None,
            var: taskprov::VdafTypeVar::Prio3Aes128Count,
        },
    }
    .get_encoded_with_param(&t.helper.global_config.taskprov_version);
    let taskprov_id = crate::taskprov::compute_task_id(
        t.helper.global_config.taskprov_version,
        &taskprov_ext_payload,
    )
    .unwrap();

    // Client: Send upload request to Leader.
    let hpke_config_list = [
        t.leader
            .get_hpke_config_for(version, Some(&taskprov_id))
            .await
            .unwrap()
            .as_ref()
            .clone(),
        t.helper
            .get_hpke_config_for(version, Some(&taskprov_id))
            .await
            .unwrap()
            .as_ref()
            .clone(),
    ];
    let report = vdaf
        .produce_report_with_extensions(
            &hpke_config_list,
            t.now,
            &taskprov_id,
            DapMeasurement::U64(1),
            vec![Extension::Taskprov {
                payload: taskprov_ext_payload,
            }],
            version,
        )
        .unwrap();

    let req = DapRequest {
        version,
        media_type: DapMediaType::Report,
        task_id: Some(taskprov_id.clone()),
        resource: DapResource::Undefined,
        payload: report.get_encoded_with_param(&version),
        url: Url::parse("https://leader.com/upload").unwrap(),
        ..Default::default()
    };
    t.leader.handle_upload_req(&req).await.unwrap();

    // Leader: Run aggregation job.
    t.run_agg_job(&taskprov_id).await.unwrap();

    // The Leader is now configured with the task.
    let task_config = t.leader.unchecked_get_task_config(&taskprov_id).await;

    // Collector: Create collection job and poll result.
    let query = Query::FixedSizeByBatchId {
        batch_id: t
            .leader
            .current_batch_id(&taskprov_id, &task_config)
            .unwrap(),
    };
    t.run_col_job(&taskprov_id, &query).await.unwrap();

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_helper_inbound_request_counter{host="helper.org",type="aggregate"}"#: 2,
        r#"test_helper_inbound_request_counter{host="helper.org",type="collect"}"#: 1,
        r#"test_leader_report_counter{host="leader.com",status="aggregated"}"#: 1,
        r#"test_helper_report_counter{host="helper.org",status="aggregated"}"#: 1,
        r#"test_leader_report_counter{host="leader.com",status="collected"}"#: 1,
        r#"test_helper_report_counter{host="helper.org",status="collected"}"#: 1,
        r#"test_helper_aggregation_job_counter{host="helper.org",status="started"}"#: 1,
        r#"test_helper_aggregation_job_counter{host="helper.org",status="completed"}"#: 1,
    });
}

async_test_version! { e2e_taskprov, Draft02 }

fn early_metadata_checks(version: DapVersion) {
    let t = Test::new(version);
    let mut rng = thread_rng();
    let metadata = ReportMetadata {
        id: ReportId(rng.gen()),
        time: t.now,
        extensions: vec![],
    };
    // We declare these so the first call to early_metadata_check() is more readable.
    let processed = false;
    let collected = false;
    // A current not processed, not collected report is OK!
    assert_matches!(
        early_metadata_check(&metadata, processed, collected, t.now - 100, t.now + 100),
        None
    );
    // A current processed, not collected report is TransitionFailure::ReportReplayed.
    assert_matches!(
        early_metadata_check(&metadata, true, false, t.now - 100, t.now + 100),
        Some(TransitionFailure::ReportReplayed)
    );
    // A current not processed but collected report is TransitionFailure::BatchCollected.
    assert_matches!(
        early_metadata_check(&metadata, false, true, t.now - 100, t.now + 100),
        Some(TransitionFailure::BatchCollected)
    );
    // A current processed and collected report is TransitionFailure::ReportReplayed.
    assert_matches!(
        early_metadata_check(&metadata, true, true, t.now - 100, t.now + 100),
        Some(TransitionFailure::ReportReplayed)
    );
    // A not collected and not processed report at the future boundary is OK.
    let metadata = ReportMetadata {
        id: ReportId(rng.gen()),
        time: t.now + 100,
        extensions: vec![],
    };
    assert_matches!(
        early_metadata_check(&metadata, false, false, t.now - 100, t.now + 100),
        None
    );
    // A not collected and not processed report too far in the future is TransitionFailure::ReportTooEarly.
    let metadata = ReportMetadata {
        id: ReportId(rng.gen()),
        time: t.now + 101,
        extensions: vec![],
    };
    assert_matches!(
        early_metadata_check(&metadata, false, false, t.now - 100, t.now + 100),
        Some(TransitionFailure::ReportTooEarly)
    );
    // A not collected and not processed report at the past boundary is OK.
    let metadata = ReportMetadata {
        id: ReportId(rng.gen()),
        time: t.now - 100,
        extensions: vec![],
    };
    assert_matches!(
        early_metadata_check(&metadata, false, false, t.now - 100, t.now + 100),
        None
    );
    // A not collected and not processed report too far in the past is TransitionFailure::ReportDropped.
    let metadata = ReportMetadata {
        id: ReportId(rng.gen()),
        time: t.now - 101,
        extensions: vec![],
    };
    assert_matches!(
        early_metadata_check(&metadata, false, false, t.now - 100, t.now + 100),
        Some(TransitionFailure::ReportDropped)
    );
}

test_versions! { early_metadata_checks }
