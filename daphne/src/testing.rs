// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Mock backend functionality to test DAP protocol.

use crate::{
    audit_log::{AggregationJobAuditAction, AuditLog},
    auth::{BearerToken, BearerTokenProvider},
    constants::DapMediaType,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter, HpkeKemId, HpkeReceiverConfig},
    messages::{
        AggregationJobContinueReq, AggregationJobId, AggregationJobInitReq, AggregationJobResp,
        BatchId, BatchSelector, Collection, CollectionJobId, CollectionReq,
        Draft02AggregationJobId, HpkeCiphertext, Interval, PartialBatchSelector, Report, ReportId,
        TaskId, Time, TransitionFailure,
    },
    metrics::DaphneMetrics,
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader, DapReportInitializer},
    vdaf::{EarlyReportState, EarlyReportStateConsumed, EarlyReportStateInitialized},
    DapAbort, DapAggregateResult, DapAggregateShare, DapAggregateSpan, DapAggregationJobState,
    DapAggregationJobUncommitted, DapBatchBucket, DapCollectJob, DapError, DapGlobalConfig,
    DapHelperAggregationJobTransition, DapLeaderAggregationJobTransition, DapMeasurement,
    DapQueryConfig, DapRequest, DapResponse, DapTaskConfig, DapVersion, MetaAggregationJobId,
    VdafConfig,
};
use assert_matches::assert_matches;
use async_trait::async_trait;
use deepsize::DeepSizeOf;
use prio::codec::Encode;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    ops::DerefMut,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::SystemTime,
};
use url::Url;

/// Scaffolding for testing the aggregation flow.
pub struct AggregationJobTest {
    // task parameters
    pub(crate) task_id: TaskId,
    pub(crate) task_config: DapTaskConfig,
    pub(crate) leader_hpke_receiver_config: HpkeReceiverConfig,
    pub(crate) helper_hpke_receiver_config: HpkeReceiverConfig,
    pub(crate) client_hpke_config_list: Vec<HpkeConfig>,
    pub(crate) collector_hpke_receiver_config: HpkeReceiverConfig,

    // aggregation job ID
    pub(crate) agg_job_id: MetaAggregationJobId,

    // the current time
    pub(crate) now: Time,

    // operational parameters
    #[allow(dead_code)]
    pub(crate) leader_registry: prometheus::Registry,
    #[allow(dead_code)]
    pub(crate) helper_registry: prometheus::Registry,
    pub(crate) leader_metrics: DaphneMetrics,
    pub(crate) helper_metrics: DaphneMetrics,
    pub(crate) leader_reports_processed: Arc<Mutex<HashSet<ReportId>>>,
    pub(crate) helper_reports_processed: Arc<Mutex<HashSet<ReportId>>>,
}

// NOTE(cjpatton) This implementation of the report initializer is not feature complete. Since
// [`AggrregationJobTest`], is only used to test the aggregation flow, features that are not
// directly relevant to the tests aren't implemented.
#[async_trait(?Send)]
impl DapReportInitializer for AggregationJobTest {
    async fn initialize_reports<'req>(
        &self,
        is_leader: bool,
        _task_id: &TaskId,
        task_config: &DapTaskConfig,
        _part_batch_sel: &PartialBatchSelector,
        consumed_reports: Vec<EarlyReportStateConsumed<'req>>,
    ) -> Result<Vec<EarlyReportStateInitialized<'req>>, DapError> {
        let mut reports_processed = if is_leader {
            self.leader_reports_processed.lock().unwrap()
        } else {
            self.helper_reports_processed.lock().unwrap()
        };

        Ok(consumed_reports
            .into_iter()
            .map(|consumed| {
                if reports_processed.contains(&consumed.metadata().id) {
                    Ok(
                        consumed
                            .into_initialized_rejected_due_to(TransitionFailure::ReportReplayed),
                    )
                } else {
                    reports_processed.insert(consumed.metadata().id);
                    EarlyReportStateInitialized::initialize(
                        is_leader,
                        &task_config.vdaf_verify_key,
                        &task_config.vdaf,
                        consumed,
                    )
                }
            })
            .collect::<Result<Vec<_>, _>>()?)
    }
}

impl AggregationJobTest {
    /// Create an aggregation job test with the given VDAF config, HPKE KEM algorithm, DAP protocol
    /// version. The KEM algorithm is used to generate an HPKE config for each party.
    pub fn new(vdaf: &VdafConfig, kem_id: HpkeKemId, version: DapVersion) -> Self {
        let mut rng = thread_rng();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let task_id = TaskId(rng.gen());
        let agg_job_id = MetaAggregationJobId::gen_for_version(&version);
        let vdaf_verify_key = vdaf.gen_verify_key();
        let leader_hpke_receiver_config = HpkeReceiverConfig::gen(rng.gen(), kem_id).unwrap();
        let helper_hpke_receiver_config = HpkeReceiverConfig::gen(rng.gen(), kem_id).unwrap();
        let collector_hpke_receiver_config = HpkeReceiverConfig::gen(rng.gen(), kem_id).unwrap();
        let leader_hpke_config = leader_hpke_receiver_config.clone().config;
        let helper_hpke_config = helper_hpke_receiver_config.clone().config;
        let collector_hpke_config = collector_hpke_receiver_config.clone().config;
        let leader_registry = prometheus::Registry::new_custom(
            Option::None,
            Option::Some(HashMap::from([
                ("env".to_string(), "test_leader".to_string()),
                ("host".to_string(), "leader.com".to_string()),
            ])),
        )
        .unwrap();
        let helper_registry = prometheus::Registry::new_custom(
            Option::None,
            Option::Some(HashMap::from([
                ("env".to_string(), "test_helper".to_string()),
                ("host".to_string(), "helper.org".to_string()),
            ])),
        )
        .unwrap();
        let leader_metrics = DaphneMetrics::register(&leader_registry).unwrap();
        let helper_metrics = DaphneMetrics::register(&helper_registry).unwrap();

        Self {
            now,
            task_id,
            agg_job_id,
            leader_hpke_receiver_config,
            helper_hpke_receiver_config,
            client_hpke_config_list: vec![leader_hpke_config, helper_hpke_config],
            collector_hpke_receiver_config,
            task_config: DapTaskConfig {
                version,
                leader_url: Url::parse("http://leader.com").unwrap(),
                helper_url: Url::parse("https://helper.org").unwrap(),
                time_precision: 500,
                expiration: now + 500,
                min_batch_size: 10,
                query: DapQueryConfig::TimeInterval,
                vdaf: vdaf.clone(),
                vdaf_verify_key,
                collector_hpke_config,
                taskprov: false,
            },
            leader_registry,
            helper_registry,
            leader_metrics,
            helper_metrics,
            leader_reports_processed: Default::default(),
            helper_reports_processed: Default::default(),
        }
    }

    /// For each measurement, generate a report for the given task.
    ///
    /// Panics if a measurement is incompatible with the given VDAF.
    pub fn produce_reports(&self, measurements: Vec<DapMeasurement>) -> Vec<Report> {
        let mut reports = Vec::with_capacity(measurements.len());

        for measurement in measurements {
            reports.push(
                self.task_config
                    .vdaf
                    .produce_report(
                        &self.client_hpke_config_list,
                        self.now,
                        &self.task_id,
                        measurement,
                        self.task_config.version,
                    )
                    .unwrap(),
            );
        }
        reports
    }

    /// Leader: Produce `AggregationJobInitReq`.
    ///
    /// Panics if the Leader aborts.
    pub async fn produce_agg_job_init_req(
        &self,
        reports: Vec<Report>,
    ) -> DapLeaderAggregationJobTransition<AggregationJobInitReq> {
        self.task_config
            .vdaf
            .produce_agg_job_init_req(
                &self.leader_hpke_receiver_config,
                self,
                &self.task_id,
                &self.task_config,
                &self.agg_job_id,
                &PartialBatchSelector::TimeInterval,
                reports,
                &self.leader_metrics,
            )
            .await
            .unwrap()
    }

    /// Helper: Handle `AggregationJobInitReq`, produce first `AggregationJobResp`.
    ///
    /// Panics if the Helper aborts.
    pub async fn handle_agg_job_init_req(
        &self,
        agg_job_init_req: &AggregationJobInitReq,
    ) -> DapHelperAggregationJobTransition<AggregationJobResp> {
        self.task_config
            .vdaf
            .handle_agg_job_init_req(
                &self.task_id,
                &self.task_config,
                &HashMap::default(),
                &self
                    .task_config
                    .vdaf
                    .helper_initialize_reports(
                        &self.helper_hpke_receiver_config,
                        self,
                        &self.task_id,
                        &self.task_config,
                        agg_job_init_req,
                    )
                    .await
                    .unwrap(),
                agg_job_init_req,
                &self.helper_metrics,
            )
            .unwrap()
    }

    /// Leader: Handle first `AggregationJobResp`, produce `AggregationJobContinueReq`.
    ///
    /// Panics if the Leader aborts.
    pub fn handle_agg_job_resp(
        &self,
        leader_state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
    ) -> DapLeaderAggregationJobTransition<AggregationJobContinueReq> {
        self.task_config
            .vdaf
            .handle_agg_job_resp(
                &self.task_id,
                &self.task_config,
                &self.agg_job_id,
                leader_state,
                agg_job_resp,
                &self.leader_metrics,
            )
            .unwrap()
    }

    /// Like [`handle_agg_job_resp`] but expect the Leader to abort.
    pub fn handle_agg_job_resp_expect_err(
        &self,
        leader_state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
    ) -> DapAbort {
        let metrics = &self.leader_metrics;
        self.task_config
            .vdaf
            .handle_agg_job_resp(
                &self.task_id,
                &self.task_config,
                &self.agg_job_id,
                leader_state,
                agg_job_resp,
                metrics,
            )
            .expect_err("handle_agg_job_resp() succeeded; expected failure")
    }

    /// Helper: Handle `AggregationJobContinueReq`, produce second `AggregationJobResp`.
    ///
    /// Panics if the Helper aborts.
    pub fn handle_agg_job_cont_req(
        &self,
        helper_state: &DapAggregationJobState,
        agg_job_cont_req: &AggregationJobContinueReq,
    ) -> (DapAggregateSpan<DapAggregateShare>, AggregationJobResp) {
        self.task_config
            .vdaf
            .handle_agg_job_cont_req(
                &self.task_id,
                &self.task_config,
                helper_state,
                &HashMap::default(),
                &self.agg_job_id,
                agg_job_cont_req,
            )
            .expect("error while handling request")
    }

    /// Like [`handle_agg_job_cont_req`] but expect the Helper to abort.
    pub fn handle_agg_job_cont_req_expect_err(
        &self,
        helper_state: DapAggregationJobState,
        agg_job_cont_req: &AggregationJobContinueReq,
    ) -> DapAbort {
        self.task_config
            .vdaf
            .handle_agg_job_cont_req(
                &self.task_id,
                &self.task_config,
                &helper_state,
                &HashMap::default(),
                &self.agg_job_id,
                agg_job_cont_req,
            )
            .expect_err("handle_agg_job_cont_req() succeeded; expected failure")
    }

    /// Leader: Handle the last `AggregationJobResp`.
    ///
    /// Panics if the Leader aborts.
    pub fn handle_final_agg_job_resp(
        &self,
        leader_uncommitted: DapAggregationJobUncommitted,
        agg_job_resp: AggregationJobResp,
    ) -> DapAggregateSpan<DapAggregateShare> {
        let metrics = &self.leader_metrics;
        self.task_config
            .vdaf
            .handle_final_agg_job_resp(&self.task_config, leader_uncommitted, agg_job_resp, metrics)
            .unwrap()
    }

    /// Produce the Leader's encrypted aggregate share.
    pub fn produce_leader_encrypted_agg_share(
        &self,
        batch_selector: &BatchSelector,
        agg_share: &DapAggregateShare,
    ) -> HpkeCiphertext {
        self.task_config
            .vdaf
            .produce_leader_encrypted_agg_share(
                &self.task_config.collector_hpke_config,
                &self.task_id,
                batch_selector,
                agg_share,
                self.task_config.version,
            )
            .unwrap()
    }

    /// Produce the Helper's encrypted aggregate share.
    pub fn produce_helper_encrypted_agg_share(
        &self,
        batch_selector: &BatchSelector,
        agg_share: &DapAggregateShare,
    ) -> HpkeCiphertext {
        self.task_config
            .vdaf
            .produce_helper_encrypted_agg_share(
                &self.task_config.collector_hpke_config,
                &self.task_id,
                batch_selector,
                agg_share,
                self.task_config.version,
            )
            .unwrap()
    }

    /// Collector: Consume the aggregate shares.
    pub async fn consume_encrypted_agg_shares(
        &self,
        batch_selector: &BatchSelector,
        report_count: u64,
        enc_agg_shares: Vec<HpkeCiphertext>,
    ) -> DapAggregateResult {
        self.task_config
            .vdaf
            .consume_encrypted_agg_shares(
                &self.collector_hpke_receiver_config,
                &self.task_id,
                batch_selector,
                report_count,
                enc_agg_shares,
                self.task_config.version,
            )
            .await
            .unwrap()
    }

    /// Generate a set of reports, aggregate them, and unshard the result.
    pub async fn roundtrip(&mut self, measurements: Vec<DapMeasurement>) -> DapAggregateResult {
        let batch_selector = BatchSelector::TimeInterval {
            batch_interval: Interval {
                start: self.now,
                duration: 3600,
            },
        };

        // Clients: Shard
        let reports = self.produce_reports(measurements);

        // Aggregators: Preparation
        let DapLeaderAggregationJobTransition::Continued(leader_state, agg_job_init_req) =
            self.produce_agg_job_init_req(reports).await
        else {
            panic!("unexpected transition");
        };

        let (leader_agg_span, helper_agg_span) =
            match self.handle_agg_job_init_req(&agg_job_init_req).await {
                DapHelperAggregationJobTransition::Continued(helper_state, agg_job_resp) => {
                    let got = DapAggregationJobState::get_decoded(
                        &self.task_config.vdaf,
                        &helper_state.get_encoded(),
                    )
                    .expect("failed to decode helper state");
                    assert_eq!(got.get_encoded(), helper_state.get_encoded());

                    let DapLeaderAggregationJobTransition::Uncommitted(uncommitted, agg_cont) =
                        self.handle_agg_job_resp(leader_state, agg_job_resp)
                    else {
                        panic!("unexpected transition");
                    };
                    let (helper_agg_span, transitions) =
                        self.handle_agg_job_cont_req(&helper_state, &agg_cont);
                    let leader_agg_span = self.handle_final_agg_job_resp(uncommitted, transitions);
                    (leader_agg_span, helper_agg_span)
                }
                DapHelperAggregationJobTransition::Finished(helper_agg_span, agg_job_resp) => {
                    let DapLeaderAggregationJobTransition::Finished(leader_agg_span) =
                        self.handle_agg_job_resp(leader_state, agg_job_resp)
                    else {
                        panic!("unexpected transition");
                    };
                    (leader_agg_span, helper_agg_span)
                }
            };

        let report_count = u64::try_from(leader_agg_span.report_count()).unwrap();

        // Leader: Aggregation
        let leader_agg_share = leader_agg_span.collapsed();
        let leader_encrypted_agg_share =
            self.produce_leader_encrypted_agg_share(&batch_selector, &leader_agg_share);

        // Helper: Aggregation
        let helper_encrypted_agg_share =
            self.produce_helper_encrypted_agg_share(&batch_selector, &helper_agg_span.collapsed());

        // Collector: Unshard
        self.consume_encrypted_agg_shares(
            &batch_selector,
            report_count,
            vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
        )
        .await
    }
}

// These are declarative macros which let us generate a test point for
// each DapVersion given a test which takes a version parameter.
//
// E.g. currently
//
//     async_test_versions! { something }
//
// would generate async tests named
//
//     something_draft02
//
// and
//
//     something_draft07
//
// that called something(version) with the appropriate version.
//
// We use the "paste" crate to get a macro that can paste tokens and also
// fiddle case.
#[macro_export]
macro_rules! test_version {
    ($fname:ident, $version:ident) => {
        ::paste::paste! {
            #[test]
            fn [<$fname _ $version:lower>]() {
                $fname ($crate::DapVersion::$version);
            }
        }
    };
}

#[macro_export]
macro_rules! test_versions {
    ($($fname:ident),*) => {
        $(
            $crate::test_version! { $fname, Draft02 }
            $crate::test_version! { $fname, Draft07 }
        )*
    };
}

#[macro_export]
macro_rules! async_test_version {
    ($fname:ident, $version:ident) => {
        ::paste::paste! {
            #[tokio::test]
            async fn [<$fname _ $version:lower>]() {
                $fname ($crate::DapVersion::$version) . await;
            }
        }
    };
}

#[macro_export]
macro_rules! async_test_versions {
    ($($fname:ident),*) => {
        $(
            $crate::async_test_version! { $fname, Draft02 }
            $crate::async_test_version! { $fname, Draft07 }
        )*
    };
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub(crate) enum MetaAggregationJobIdOwned {
    Draft02(Draft02AggregationJobId),
    Draft07(AggregationJobId),
}

impl From<&MetaAggregationJobId> for MetaAggregationJobIdOwned {
    fn from(agg_job_id: &MetaAggregationJobId) -> Self {
        match agg_job_id {
            MetaAggregationJobId::Draft02(agg_job_id) => Self::Draft02(*agg_job_id),
            MetaAggregationJobId::Draft07(agg_job_id) => Self::Draft07(*agg_job_id),
        }
    }
}

impl From<DapBatchBucket> for PartialBatchSelector {
    fn from(bucket: DapBatchBucket) -> Self {
        match bucket {
            DapBatchBucket::FixedSize { batch_id } => Self::FixedSizeByBatchId { batch_id },
            DapBatchBucket::TimeInterval { .. } => Self::TimeInterval,
        }
    }
}

#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct MockAggregatorReportSelector(pub(crate) TaskId);

#[derive(Default)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct MockAuditLog(AtomicU32);

impl MockAuditLog {
    #[allow(dead_code)]
    pub(crate) fn invocations(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

impl AuditLog for MockAuditLog {
    fn on_aggregation_job(
        &self,
        _host: &str,
        _task_id: &TaskId,
        _task_config: &DapTaskConfig,
        _report_count: u64,
        _action: AggregationJobAuditAction,
    ) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct MockAggregator {
    pub global_config: DapGlobalConfig,
    pub tasks: Arc<Mutex<HashMap<TaskId, DapTaskConfig>>>,
    pub hpke_receiver_config_list: Vec<HpkeReceiverConfig>,
    pub leader_token: BearerToken,
    pub collector_token: Option<BearerToken>, // Not set by Helper
    pub report_store: Arc<Mutex<HashMap<TaskId, ReportStore>>>,
    pub leader_state_store: Arc<Mutex<HashMap<TaskId, LeaderState>>>,
    pub helper_state_store: Arc<Mutex<HashMap<HelperStateInfo, DapAggregationJobState>>>,
    pub agg_store: Arc<Mutex<HashMap<TaskId, HashMap<DapBatchBucket, AggStore>>>>,
    pub collector_hpke_config: HpkeConfig,
    pub metrics: DaphneMetrics,
    pub audit_log: MockAuditLog,

    // taskprov
    pub taskprov_vdaf_verify_key_init: [u8; 32],
    pub taskprov_leader_token: BearerToken,
    pub taskprov_collector_token: Option<BearerToken>, // Not set by Helper

    // Leader: Reference to peer. Used to simulate HTTP requests from Leader to Helper, i.e.,
    // implement `DapLeader::send_http_post()` for `MockAggregator`. Not set by the Helper.
    pub peer: Option<Arc<MockAggregator>>,
}

impl DeepSizeOf for MockAggregator {
    fn deep_size_of_children(&self, context: &mut deepsize::Context) -> usize {
        self.global_config.deep_size_of_children(context)
                + self.tasks.deep_size_of_children(context)
                + self
                    .hpke_receiver_config_list
                    .deep_size_of_children(context)
                + self.leader_token.deep_size_of_children(context)
                + self.collector_token.deep_size_of_children(context)
                + self.report_store.deep_size_of_children(context)
                + self.leader_state_store.deep_size_of_children(context)
                + self.helper_state_store.deep_size_of_children(context)
                + self.agg_store.deep_size_of_children(context)
                + self.collector_hpke_config.deep_size_of_children(context)
                // + self.metrics.deep_size_of_children(context)
                // + self.audit_log.deep_size_of_children(context)
                + self
                    .taskprov_vdaf_verify_key_init
                    .deep_size_of_children(context)
                + self.taskprov_leader_token.deep_size_of_children(context)
                + self.taskprov_collector_token.deep_size_of_children(context)
                + self.peer.deep_size_of_children(context)
    }
}

impl MockAggregator {
    #[allow(clippy::too_many_arguments)]
    pub fn new_helper(
        tasks: impl IntoIterator<Item = (TaskId, DapTaskConfig)>,
        hpke_receiver_config_list: impl IntoIterator<Item = HpkeReceiverConfig>,
        global_config: DapGlobalConfig,
        leader_token: BearerToken,
        collector_hpke_config: HpkeConfig,
        registry: &prometheus::Registry,
        taskprov_vdaf_verify_key_init: [u8; 32],
        taskprov_leader_token: BearerToken,
    ) -> Self {
        Self {
            global_config,
            tasks: Arc::new(Mutex::new(tasks.into_iter().collect())),
            hpke_receiver_config_list: hpke_receiver_config_list.into_iter().collect(),
            leader_token,
            collector_token: None,
            report_store: Default::default(),
            leader_state_store: Default::default(),
            helper_state_store: Default::default(),
            agg_store: Default::default(),
            collector_hpke_config,
            metrics: DaphneMetrics::register(registry).unwrap(),
            audit_log: MockAuditLog::default(),
            taskprov_vdaf_verify_key_init,
            taskprov_leader_token,
            taskprov_collector_token: None,
            peer: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_leader(
        tasks: impl IntoIterator<Item = (TaskId, DapTaskConfig)>,
        hpke_receiver_config_list: impl IntoIterator<Item = HpkeReceiverConfig>,
        global_config: DapGlobalConfig,
        leader_token: BearerToken,
        collector_token: impl Into<Option<BearerToken>>,
        collector_hpke_config: HpkeConfig,
        registry: &prometheus::Registry,
        taskprov_vdaf_verify_key_init: [u8; 32],
        taskprov_leader_token: BearerToken,
        taskprov_collector_token: impl Into<Option<BearerToken>>,
        peer: impl Into<Option<Arc<Self>>>,
    ) -> Self {
        Self {
            global_config,
            tasks: Arc::new(Mutex::new(tasks.into_iter().collect())),
            hpke_receiver_config_list: hpke_receiver_config_list.into_iter().collect(),
            leader_token,
            collector_token: collector_token.into(),
            report_store: Default::default(),
            leader_state_store: Default::default(),
            helper_state_store: Default::default(),
            agg_store: Default::default(),
            collector_hpke_config,
            metrics: DaphneMetrics::register(registry).unwrap(),
            audit_log: MockAuditLog::default(),
            taskprov_vdaf_verify_key_init,
            taskprov_leader_token,
            taskprov_collector_token: taskprov_collector_token.into(),
            peer: peer.into(),
        }
    }

    /// Conducts checks on a received report to see whether:
    /// 1) the report falls into a batch that has been already collected, or
    /// 2) the report has been submitted by the client in the past.
    async fn check_report_early_fail(
        &self,
        task_id: &TaskId,
        bucket: &DapBatchBucket,
        id: &ReportId,
    ) -> Option<TransitionFailure> {
        // Check AggStateStore to see whether the report is part of a batch that has already
        // been collected.
        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(*task_id).or_default();
        if matches!(agg_store.get(bucket), Some(inner_agg_store) if inner_agg_store.collected) {
            return Some(TransitionFailure::BatchCollected);
        }

        // Check whether the same report has been submitted in the past.
        let mut guard = self
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        let report_store = guard.entry(*task_id).or_default();
        if report_store.processed.contains(id) {
            return Some(TransitionFailure::ReportReplayed);
        }

        None
    }

    fn get_hpke_receiver_config_for(&self, hpke_config_id: u8) -> Option<&HpkeReceiverConfig> {
        self.hpke_receiver_config_list
            .iter()
            .find(|&hpke_receiver_config| hpke_config_id == hpke_receiver_config.config.id)
    }

    /// Assign the report to a bucket.
    ///
    /// TODO(cjpatton) Figure out if we can avoid returning and owned thing here.
    async fn assign_report_to_bucket(
        &self,
        report: &Report,
        task_id: &TaskId,
    ) -> Option<DapBatchBucket> {
        let mut rng = thread_rng();
        let task_config = self
            .get_task_config_for(task_id)
            .await
            .unwrap()
            .expect("tasks: unrecognized task");

        match task_config.query {
            // For fixed-size queries, the bucket corresponds to a single batch.
            DapQueryConfig::FixedSize { .. } => {
                let mut guard = self
                    .leader_state_store
                    .lock()
                    .expect("leader_state_store: failed to lock");
                let leader_state_store = guard.entry(*task_id).or_default();

                // Assign the report to the first unsaturated batch.
                for (batch_id, report_count) in &mut leader_state_store.batch_queue {
                    if *report_count < task_config.min_batch_size {
                        *report_count += 1;
                        return Some(DapBatchBucket::FixedSize {
                            batch_id: *batch_id,
                        });
                    }
                }

                // No unsaturated batch exists, so create a new batch.
                let batch_id = BatchId(rng.gen());
                leader_state_store.batch_queue.push_back((batch_id, 1));
                Some(DapBatchBucket::FixedSize { batch_id })
            }

            // For time-interval queries, the bucket is the batch window computed by truncating the
            // report timestamp.
            DapQueryConfig::TimeInterval => Some(DapBatchBucket::TimeInterval {
                batch_window: task_config.quantized_time_lower_bound(report.report_metadata.time),
            }),
        }
    }

    /// Return the ID of the batch currently being filled with reports. Panics unless the task is
    /// configured for fixed-size queries.
    pub(crate) fn current_batch_id(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
    ) -> Option<BatchId> {
        // Calling current_batch() is only well-defined for fixed-size tasks.
        assert_matches!(task_config.query, DapQueryConfig::FixedSize { .. });

        let guard = self
            .leader_state_store
            .lock()
            .expect("leader_state_store: failed to lock");
        let leader_state_store = guard
            .get(task_id)
            .expect("leader_state_store: unrecognized task");

        leader_state_store
            .batch_queue
            .front()
            .map(|(batch_id, _report_count)| *batch_id)
    }

    pub(crate) async fn unchecked_get_task_config(&self, task_id: &TaskId) -> DapTaskConfig {
        self.get_task_config_for(task_id)
            .await
            .expect("encountered unexpected error")
            .expect("missing task config")
    }
}

#[async_trait(?Send)]
impl BearerTokenProvider for MockAggregator {
    type WrappedBearerToken<'a> = &'a BearerToken;

    async fn get_leader_bearer_token_for<'s>(
        &'s self,
        _task_id: &'s TaskId,
        task_config: &DapTaskConfig,
    ) -> Result<Option<Self::WrappedBearerToken<'s>>, DapError> {
        if task_config.taskprov {
            Ok(Some(&self.taskprov_leader_token))
        } else {
            Ok(Some(&self.leader_token))
        }
    }

    async fn get_collector_bearer_token_for<'s>(
        &'s self,
        _task_id: &'s TaskId,
        task_config: &DapTaskConfig,
    ) -> Result<Option<Self::WrappedBearerToken<'s>>, DapError> {
        if task_config.taskprov {
            Ok(Some(self.taskprov_collector_token.as_ref().expect(
                "MockAggregator not configured with taskprov collector token",
            )))
        } else {
            Ok(Some(self.collector_token.as_ref().expect(
                "MockAggregator not configured with collector token",
            )))
        }
    }
}

#[async_trait(?Send)]
impl HpkeDecrypter for MockAggregator {
    type WrappedHpkeConfig<'a> = &'a HpkeConfig;

    async fn get_hpke_config_for<'s>(
        &'s self,
        _version: DapVersion,
        task_id: Option<&TaskId>,
    ) -> Result<Self::WrappedHpkeConfig<'s>, DapError> {
        if self.hpke_receiver_config_list.is_empty() {
            return Err(fatal_error!(err = "empty HPKE receiver config list"));
        }

        // Aggregators MAY abort if the HPKE config request does not specify a task ID. While not
        // required for MockAggregator, we simulate this behavior for testing purposes.
        //
        // TODO(cjpatton) To make this clearer, have MockAggregator store a map from task IDs to
        // HPKE receiver configs.
        if task_id.is_none() {
            return Err(DapError::Abort(DapAbort::MissingTaskId));
        }

        // Always advertise the first HPKE config in the list.
        Ok(&self.hpke_receiver_config_list[0].config)
    }

    async fn can_hpke_decrypt(&self, _task_id: &TaskId, config_id: u8) -> Result<bool, DapError> {
        Ok(self.get_hpke_receiver_config_for(config_id).is_some())
    }

    async fn hpke_decrypt(
        &self,
        _task_id: &TaskId,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        if let Some(hpke_receiver_config) = self.get_hpke_receiver_config_for(ciphertext.config_id)
        {
            Ok(hpke_receiver_config.decrypt(info, aad, &ciphertext.enc, &ciphertext.payload)?)
        } else {
            Err(DapError::Transition(TransitionFailure::HpkeUnknownConfigId))
        }
    }
}

#[async_trait(?Send)]
impl DapAuthorizedSender<BearerToken> for MockAggregator {
    async fn authorize(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        media_type: &DapMediaType,
        _payload: &[u8],
    ) -> Result<BearerToken, DapError> {
        Ok(self
            .authorize_with_bearer_token(task_id, task_config, media_type)
            .await?
            .clone())
    }
}

#[async_trait(?Send)]
impl DapReportInitializer for MockAggregator {
    async fn initialize_reports<'req>(
        &self,
        is_leader: bool,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        consumed_reports: Vec<EarlyReportStateConsumed<'req>>,
    ) -> Result<Vec<EarlyReportStateInitialized<'req>>, DapError> {
        let span = task_config.batch_span_for_meta(
            part_batch_sel,
            consumed_reports.iter().filter(|report| report.is_ready()),
        )?;

        let mut early_fails = HashMap::new();
        for (bucket, ((), report_ids_and_time)) in span.iter() {
            for (id, _) in report_ids_and_time {
                // Check whether Report has been collected or replayed.
                if let Some(transition_failure) =
                    self.check_report_early_fail(task_id, bucket, id).await
                {
                    early_fails.insert(*id, transition_failure);
                };
            }
        }

        Ok(consumed_reports
            .into_iter()
            .map(|consumed| {
                if let Some(failure) = early_fails.get(&consumed.metadata().id) {
                    Ok(consumed.into_initialized_rejected_due_to(*failure))
                } else {
                    EarlyReportStateInitialized::initialize(
                        is_leader,
                        &task_config.vdaf_verify_key,
                        &task_config.vdaf,
                        consumed,
                    )
                }
            })
            .collect::<Result<Vec<_>, _>>()?)
    }
}

#[async_trait(?Send)]
impl DapAggregator<BearerToken> for MockAggregator {
    // The lifetimes on the traits ensure that we can return a reference to a task config stored by
    // the DapAggregator. (See DaphneWorkerConfig for an example.) For simplicity, MockAggregator
    // clones the task config as needed.
    type WrappedDapTaskConfig<'a> = DapTaskConfig;

    async fn unauthorized_reason(
        &self,
        task_config: &DapTaskConfig,
        req: &DapRequest<BearerToken>,
    ) -> Result<Option<String>, DapError> {
        self.bearer_token_authorized(task_config, req).await
    }

    fn get_global_config(&self) -> &DapGlobalConfig {
        &self.global_config
    }

    fn taskprov_vdaf_verify_key_init(&self) -> Option<&[u8; 32]> {
        Some(&self.taskprov_vdaf_verify_key_init)
    }

    fn taskprov_collector_hpke_config(&self) -> Option<&HpkeConfig> {
        Some(&self.collector_hpke_config)
    }

    fn taskprov_opt_out_reason(
        &self,
        _task_config: &DapTaskConfig,
    ) -> Result<Option<String>, DapError> {
        // Always opt-in.
        Ok(None)
    }

    async fn taskprov_put(
        &self,
        req: &DapRequest<BearerToken>,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError> {
        let task_id = req.task_id().map_err(DapError::Abort)?;
        let mut tasks = self.tasks.lock().expect("tasks: lock failed");
        tasks.deref_mut().insert(*task_id, task_config);
        Ok(())
    }

    async fn get_task_config_for<'req>(
        &'req self,
        task_id: &'req TaskId,
    ) -> Result<Option<Self::WrappedDapTaskConfig<'req>>, DapError> {
        let tasks = self.tasks.lock().expect("tasks: lock failed");
        Ok(tasks.get(task_id).cloned())
    }

    fn get_current_time(&self) -> Time {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    async fn is_batch_overlapping(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<bool, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await
            .unwrap()
            .expect("tasks: unrecognized task");
        let guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let Some(agg_store) = guard.get(task_id) else {
            return Ok(false);
        };

        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            if let Some(inner_agg_store) = agg_store.get(&bucket) {
                if inner_agg_store.collected {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn batch_exists(&self, task_id: &TaskId, batch_id: &BatchId) -> Result<bool, DapError> {
        let guard = self.agg_store.lock().expect("agg_store: failed to lock");
        if let Some(agg_store) = guard.get(task_id) {
            Ok(agg_store
                .get(&DapBatchBucket::FixedSize {
                    batch_id: *batch_id,
                })
                .is_some())
        } else {
            Ok(false)
        }
    }

    async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        _task_config: &DapTaskConfig,
        agg_agg_span: DapAggregateSpan<DapAggregateShare>,
    ) -> DapAggregateSpan<Result<HashSet<ReportId>, DapError>> {
        let mut report_store_guard = self
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        let report_store = report_store_guard.entry(*task_id).or_default();
        let mut agg_store_guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = agg_store_guard.entry(*task_id).or_default();

        agg_agg_span
            .into_iter()
            .map(|(bucket, (agg_share, report_metadatas))| {
                let replayed = report_metadatas
                    .iter()
                    .map(|(id, _)| *id)
                    .filter(|id| report_store.processed.contains(id))
                    .collect::<HashSet<_>>();

                let result = if replayed.is_empty() {
                    report_store
                        .processed
                        .extend(report_metadatas.iter().map(|(id, _)| *id));
                    // Add to aggregate share.
                    agg_store
                        .entry(bucket.clone())
                        .or_default()
                        .agg_share
                        .merge(agg_share.clone())
                        .map(|_| HashSet::new())
                } else {
                    Ok(replayed)
                };
                (bucket, (result, report_metadatas))
            })
            .collect()
    }

    async fn get_agg_share(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await
            .unwrap()
            .expect("tasks: unrecognized task");
        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(*task_id).or_default();

        // Fetch aggregate shares.
        let mut agg_share = DapAggregateShare::default();
        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            if let Some(inner_agg_store) = agg_store.get(&bucket) {
                if inner_agg_store.collected {
                    return Err(DapError::Abort(DapAbort::batch_overlap(task_id, batch_sel)));
                }
                agg_share.merge(inner_agg_store.agg_share.clone())?;
            }
        }

        Ok(agg_share)
    }

    async fn mark_collected(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError> {
        let task_config = self.unchecked_get_task_config(task_id).await;
        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(*task_id).or_default();

        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            if let Some(inner_agg_store) = agg_store.get_mut(&bucket) {
                inner_agg_store.collected = true;
            }
        }

        Ok(())
    }

    async fn current_batch(&self, task_id: &TaskId) -> std::result::Result<BatchId, DapError> {
        let task_config = self.unchecked_get_task_config(task_id).await;
        if let Some(id) = self.current_batch_id(task_id, &task_config) {
            Ok(id)
        } else {
            Err(DapError::Abort(DapAbort::BadRequest(
                "unknown version".to_string(),
            )))
        }
    }

    fn metrics(&self) -> &DaphneMetrics {
        &self.metrics
    }

    fn audit_log(&self) -> &dyn AuditLog {
        &self.audit_log
    }
}

#[async_trait(?Send)]
impl DapHelper<BearerToken> for MockAggregator {
    async fn put_helper_state_if_not_exists(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        helper_state: &DapAggregationJobState,
    ) -> Result<bool, DapError> {
        let helper_state_info = HelperStateInfo {
            task_id: *task_id,
            agg_job_id_owned: agg_job_id.into(),
        };

        let mut helper_state_store = self
            .helper_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?;

        if helper_state_store.contains_key(&helper_state_info) {
            return Ok(false);
        }

        // NOTE: This code is only correct for VDAFs with exactly one round of preparation.
        // For VDAFs with more rounds, the helper state blob will need to be updated here.
        helper_state_store.insert(helper_state_info, helper_state.clone());

        Ok(true)
    }

    async fn get_helper_state(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
    ) -> Result<Option<DapAggregationJobState>, DapError> {
        let helper_state_info = HelperStateInfo {
            task_id: *task_id,
            agg_job_id_owned: agg_job_id.into(),
        };

        let helper_state_store = self
            .helper_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?;

        // NOTE: This code is only correct for VDAFs with exactly one round of preparation.
        // For VDAFs with more rounds, the helper state blob will need to be updated here.
        Ok(helper_state_store.get(&helper_state_info).cloned())
    }
}

#[async_trait(?Send)]
impl DapLeader<BearerToken> for MockAggregator {
    type ReportSelector = MockAggregatorReportSelector;

    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError> {
        let bucket = self
            .assign_report_to_bucket(report, task_id)
            .await
            .expect("could not determine batch for report");

        // Check whether Report has been collected or replayed.
        if let Some(transition_failure) = self
            .check_report_early_fail(task_id, &bucket, &report.report_metadata.id)
            .await
        {
            return Err(DapError::Transition(transition_failure));
        };

        // Store Report for future processing.
        let mut guard = self
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        let queue = guard
            .get_mut(task_id)
            .expect("report_store: unrecognized task")
            .pending
            .entry(bucket)
            .or_default();
        queue.push_back(report.clone());
        Ok(())
    }

    async fn get_reports(
        &self,
        report_sel: &MockAggregatorReportSelector,
    ) -> Result<HashMap<TaskId, HashMap<PartialBatchSelector, Vec<Report>>>, DapError> {
        let task_id = &report_sel.0;
        let task_config = self.unchecked_get_task_config(task_id).await;
        let mut guard = self
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        let report_store = guard.entry(*task_id).or_default();

        // For the task indicated by the report selector, choose a single report to aggregate.
        match task_config.query {
            DapQueryConfig::TimeInterval { .. } => {
                // Aggregate reports in any order.
                let mut reports = Vec::new();
                for queue in report_store.pending.values_mut() {
                    if !queue.is_empty() {
                        reports.append(&mut queue.drain(..1).collect());
                        break;
                    }
                }
                return Ok(HashMap::from([(
                    *task_id,
                    HashMap::from([(PartialBatchSelector::TimeInterval, reports)]),
                )]));
            }
            DapQueryConfig::FixedSize { .. } => {
                // Drain the batch that is being filled.

                let bucket = if let Some(batch_id) = self.current_batch_id(task_id, &task_config) {
                    DapBatchBucket::FixedSize { batch_id }
                } else {
                    return Ok(HashMap::default());
                };

                let queue = report_store
                    .pending
                    .get_mut(&bucket)
                    .expect("report_store: unknown bucket");
                let reports = queue.drain(..1).collect();
                return Ok(HashMap::from([(
                    *task_id,
                    HashMap::from([(bucket.into(), reports)]),
                )]));
            }
        }
    }

    // Called after receiving a CollectReq from Collector.
    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        collect_job_id: &Option<CollectionJobId>,
        collect_req: &CollectionReq,
    ) -> Result<Url, DapError> {
        let mut rng = thread_rng();
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| fatal_error!(err = "task not found"))?;

        let mut leader_state_store = self
            .leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?;

        // Construct a new Collect URI for this CollectReq.
        let collect_id = collect_job_id
            .as_ref()
            .map_or_else(|| CollectionJobId(rng.gen()), |cid| *cid);
        let collect_uri = task_config
            .leader_url
            .join(&format!(
                "collect/task/{}/req/{}",
                task_id.to_base64url(),
                collect_id.to_base64url(),
            ))
            .map_err(|e| fatal_error!(err = ?e))?;

        // Store Collect ID and CollectReq into LeaderState.
        let leader_state = leader_state_store.entry(*task_id).or_default();
        leader_state.collect_ids.push_back(collect_id);
        let collect_job_state = CollectJobState::Pending(collect_req.clone());
        leader_state
            .collect_jobs
            .insert(collect_id, collect_job_state);

        Ok(collect_uri)
    }

    // Called to retrieve completed CollectResp at the request of Collector.
    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
    ) -> Result<DapCollectJob, DapError> {
        let leader_state_store = self
            .leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?;

        let leader_state = leader_state_store
            .get(task_id)
            .ok_or_else(|| fatal_error!(err = "collect job not found for task_id", %task_id))?;
        if let Some(collect_job_state) = leader_state.collect_jobs.get(collect_id) {
            match collect_job_state {
                CollectJobState::Pending(_) => Ok(DapCollectJob::Pending),
                CollectJobState::Processed(resp) => Ok(DapCollectJob::Done(resp.clone())),
            }
        } else {
            Ok(DapCollectJob::Unknown)
        }
    }

    // Called to retrieve pending CollectReq.
    async fn get_pending_collect_jobs(
        &self,
    ) -> Result<Vec<(TaskId, CollectionJobId, CollectionReq)>, DapError> {
        let leader_state_store = self
            .leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?;

        let mut res = Vec::new();
        for (task_id, leader_state) in &*leader_state_store {
            // Iterate over collect IDs and copy them and their associated requests to the response.
            for collect_id in &leader_state.collect_ids {
                if let CollectJobState::Pending(collect_req) =
                    leader_state.collect_jobs.get(collect_id).unwrap()
                {
                    res.push((*task_id, *collect_id, collect_req.clone()));
                }
            }
        }
        Ok(res)
    }

    async fn finish_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
        collect_resp: &Collection,
    ) -> Result<(), DapError> {
        let mut leader_state_store = self
            .leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?;

        let leader_state = leader_state_store
            .get_mut(task_id)
            .ok_or_else(|| fatal_error!(err = "collect job not found for task_id", %task_id))?;
        let collect_job = leader_state
            .collect_jobs
            .get_mut(collect_id)
            .ok_or_else(|| fatal_error!(err = "collect job not found for collect_id", %task_id))?;

        // Remove the batch from the batch queue.
        if let PartialBatchSelector::FixedSizeByBatchId { ref batch_id } =
            collect_resp.part_batch_sel
        {
            leader_state
                .batch_queue
                .retain(|(id, _report_count)| id != batch_id);
        }

        match collect_job {
            CollectJobState::Pending(_) => {
                // Mark collect job as Processed.
                *collect_job = CollectJobState::Processed(collect_resp.clone());

                // Remove collect ID from queue.
                let index = leader_state
                    .collect_ids
                    .iter()
                    .position(|r| r == collect_id)
                    .unwrap();
                leader_state.collect_ids.remove(index);

                Ok(())
            }
            CollectJobState::Processed(_) => {
                Err(fatal_error!(err = "tried to overwrite collect response"))
            }
        }
    }

    async fn send_http_post(&self, req: DapRequest<BearerToken>) -> Result<DapResponse, DapError> {
        match req.media_type {
            DapMediaType::AggregationJobInitReq | DapMediaType::AggregationJobContinueReq => {
                Ok(self
                    .peer
                    .as_ref()
                    .expect("peer not configured")
                    .handle_agg_job_req(&req)
                    .await
                    .expect("peer aborted unexpectedly"))
            }
            DapMediaType::AggregateShareReq => Ok(self
                .peer
                .as_ref()
                .expect("peer not configured")
                .handle_agg_share_req(&req)
                .await
                .expect("peer aborted unexpectedly")),
            _ => unreachable!("unhandled media type: {:?}", req.media_type),
        }
    }

    async fn send_http_put(&self, req: DapRequest<BearerToken>) -> Result<DapResponse, DapError> {
        if req.media_type == DapMediaType::AggregationJobInitReq {
            Ok(self
                .peer
                .as_ref()
                .expect("peer not configured")
                .handle_agg_job_req(&req)
                .await
                .expect("peer aborted unexpectedly"))
        } else {
            unreachable!("unhandled media type: {:?}", req.media_type)
        }
    }
}

/// Information associated to a certain helper state for a given task ID and aggregate job ID.
#[derive(Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct HelperStateInfo {
    task_id: TaskId,
    agg_job_id_owned: MetaAggregationJobIdOwned,
}

/// Stores the reports received from Clients.
#[derive(Default)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct ReportStore {
    pub(crate) pending: HashMap<DapBatchBucket, VecDeque<Report>>,
    pub(crate) processed: HashSet<ReportId>,
}

/// Stores the state of the collect job.
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum CollectJobState {
    Pending(CollectionReq),
    Processed(Collection),
}

/// `LeaderState` keeps track of the following:
/// * Collect IDs in their order of arrival.
/// * The state of the collect job associated to the Collect ID.
#[derive(Default)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct LeaderState {
    collect_ids: VecDeque<CollectionJobId>,
    collect_jobs: HashMap<CollectionJobId, CollectJobState>,
    batch_queue: VecDeque<(BatchId, u64)>, // Batch ID, batch size
}

/// `AggStore` keeps track of the following:
/// * Aggregate share
/// * Whether this aggregate share has been collected
#[derive(Default)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct AggStore {
    pub(crate) agg_share: DapAggregateShare,
    pub(crate) collected: bool,
}

/// Helper macro used by `assert_metrics_include`.
#[macro_export]
macro_rules! assert_metrics_include_auxiliary_function {
    ($set:expr, $k:tt: $v:expr,) => {{
        let line = format!("{} {}", $k, $v);
        $set.insert(line);
    }};

    ($set:expr, $k:tt: $v:expr, $($ks:tt: $vs:expr),+,) => {{
        let line = format!("{} {}", $k, $v);
        $set.insert(line);
        $crate::assert_metrics_include_auxiliary_function!($set, $($ks: $vs),+,)
    }}
}

/// Gather metrics from a registry and assert that a list of metrics are present and have the
/// correct value. For example:
/// ```ignore
/// let registry = prometheus::Registry::new();
///
/// // ... Register a metric called "report_counter" and use it.
///
/// assert_metrics_include!(t.helper_prometheus_registry, {
///      r#"report_counter{status="aggregated"}"#: 23,
/// });
/// ```
#[macro_export]
macro_rules! assert_metrics_include {
    ($registry:expr, {$($ks:tt: $vs:expr),+,}) => {{
        use prometheus::{Encoder, TextEncoder};
        use regex::{Captures,Regex};

        let mut want = std::collections::HashSet::<String>::new();
        $crate::assert_metrics_include_auxiliary_function!(&mut want, $($ks: $vs),+,);

        // Encode the metrics and iterate over each line. For each line, if the line appears in the
        // list of expected output lines, then remove it.
        let mut got_buf = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&$registry.gather(), &mut got_buf).unwrap();
        let got_str = String::from_utf8(got_buf).unwrap();
        let lines = got_str.split('\n');

        // sort all terms to ensure deterministic comparisons
        let pat = Regex::new(r"\{([^]]*)}").unwrap();
        let lines = lines.map(|line| {
            pat.replace(line, |c:&Captures| {
                let mut terms: Vec<_> = c[1].split(",").collect();
                terms.sort();
                format!("{{{}}}", terms.join(","))
            }).to_string()
        }).collect::<Vec<String>>();

        for line in &lines {
            want.remove(line);
        }

        // The metrics contain the expected lines if the the set is now empty.
        if !want.is_empty() {
            panic!("unexpected metrics: got:\n{}\nmust contain:\n{}\n",
                   lines.join("\n"), want.into_iter().collect::<Vec<String>>().join("\n"));
        }
    }}
}
