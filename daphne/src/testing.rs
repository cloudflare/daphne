// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Mock backend functionality to test DAP protocol.

use crate::{
    audit_log::{AggregationJobAuditAction, AuditLog},
    auth::{BearerToken, BearerTokenProvider},
    constants::DapMediaType,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter, HpkeKemId, HpkeProvider, HpkeReceiverConfig},
    messages::{
        AggregationJobId, AggregationJobInitReq, AggregationJobResp, BatchId, BatchSelector,
        Collection, CollectionJobId, HpkeCiphertext, Interval, PartialBatchSelector, Report,
        ReportId, TaskId, Time, TransitionFailure,
    },
    metrics::{prometheus::DaphnePromMetrics, DaphneMetrics},
    protocol::aggregator::{EarlyReportStateConsumed, EarlyReportStateInitialized},
    roles::{
        aggregator::MergeAggShareError,
        helper,
        leader::{in_memory_leader::InMemoryLeaderState, WorkItem},
        DapAggregator, DapAuthorizedSender, DapHelper, DapLeader, DapReportInitializer,
    },
    DapAbort, DapAggregateResult, DapAggregateShare, DapAggregateSpan, DapAggregationJobState,
    DapAggregationParam, DapBatchBucket, DapCollectionJob, DapError, DapGlobalConfig,
    DapMeasurement, DapQueryConfig, DapRequest, DapResponse, DapTaskConfig, DapVersion, VdafConfig,
};
use async_trait::async_trait;
use deepsize::DeepSizeOf;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
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

    // the current time
    pub(crate) now: Time,

    // operational parameters
    #[allow(dead_code)]
    pub(crate) leader_registry: prometheus::Registry,
    pub(crate) leader_metrics: DaphnePromMetrics,
}

fn initialize_reports(
    is_leader: bool,
    task_config: &DapTaskConfig,
    agg_param: &DapAggregationParam,
    consumed_reports: Vec<EarlyReportStateConsumed>,
) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
    consumed_reports
        .into_iter()
        .map(|consumed| {
            EarlyReportStateInitialized::initialize(
                is_leader,
                &task_config.vdaf_verify_key,
                &task_config.vdaf,
                agg_param,
                consumed,
            )
        })
        .collect()
}

#[async_trait]
impl DapReportInitializer for AggregationJobTest {
    async fn initialize_reports(
        &self,
        is_leader: bool,
        task_config: &DapTaskConfig,
        agg_param: &DapAggregationParam,
        consumed_reports: Vec<EarlyReportStateConsumed>,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        initialize_reports(is_leader, task_config, agg_param, consumed_reports)
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
        let leader_metrics = DaphnePromMetrics::register(&leader_registry).unwrap();

        Self {
            now,
            task_id,
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
                vdaf: *vdaf,
                vdaf_verify_key,
                collector_hpke_config,
                method: Default::default(),
            },
            leader_registry,
            leader_metrics,
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
    pub async fn produce_agg_job_req(
        &self,
        agg_param: &DapAggregationParam,
        reports: Vec<Report>,
    ) -> (DapAggregationJobState, AggregationJobInitReq) {
        self.task_config
            .produce_agg_job_req(
                &self.leader_hpke_receiver_config,
                self,
                &self.task_id,
                &PartialBatchSelector::TimeInterval,
                agg_param,
                futures::stream::iter(reports),
                &self.leader_metrics,
            )
            .await
            .unwrap()
    }

    /// Helper: Handle `AggregationJobInitReq`, produce first `AggregationJobResp`.
    ///
    /// Panics if the Helper aborts.
    pub async fn handle_agg_job_req(
        &self,
        agg_job_init_req: AggregationJobInitReq,
    ) -> (DapAggregateSpan<DapAggregateShare>, AggregationJobResp) {
        self.task_config
            .produce_agg_job_resp(
                &HashMap::default(),
                &agg_job_init_req.part_batch_sel.clone(),
                &self
                    .task_config
                    .consume_agg_job_req(
                        &self.helper_hpke_receiver_config,
                        self,
                        &self.task_id,
                        agg_job_init_req,
                    )
                    .await
                    .unwrap(),
            )
            .unwrap()
    }

    /// Leader: Handle `AggregationJobResp`, produce `AggregationJobContinueReq`.
    ///
    /// Panics if the Leader aborts.
    pub fn consume_agg_job_resp(
        &self,
        leader_state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
    ) -> DapAggregateSpan<DapAggregateShare> {
        self.task_config
            .consume_agg_job_resp(
                &self.task_id,
                leader_state,
                agg_job_resp,
                &self.leader_metrics,
            )
            .unwrap()
    }

    /// Like [`consume_agg_job_resp`] but expect the Leader to abort.
    pub fn consume_agg_job_resp_expect_err(
        &self,
        leader_state: DapAggregationJobState,
        agg_job_resp: AggregationJobResp,
    ) -> DapError {
        let metrics = &self.leader_metrics;
        self.task_config
            .consume_agg_job_resp(&self.task_id, leader_state, agg_job_resp, metrics)
            .expect_err("consume_agg_job_resp() succeeded; expected failure")
    }

    /// Produce the Leader's encrypted aggregate share.
    pub fn produce_leader_encrypted_agg_share(
        &self,
        batch_selector: &BatchSelector,
        agg_param: &DapAggregationParam,
        agg_share: &DapAggregateShare,
    ) -> HpkeCiphertext {
        self.task_config
            .produce_leader_encrypted_agg_share(
                &self.task_config.collector_hpke_config,
                &self.task_id,
                batch_selector,
                agg_param,
                agg_share,
                self.task_config.version,
            )
            .unwrap()
    }

    /// Produce the Helper's encrypted aggregate share.
    pub fn produce_helper_encrypted_agg_share(
        &self,
        batch_selector: &BatchSelector,
        agg_param: &DapAggregationParam,
        agg_share: &DapAggregateShare,
    ) -> HpkeCiphertext {
        self.task_config
            .produce_helper_encrypted_agg_share(
                &self.task_config.collector_hpke_config,
                &self.task_id,
                batch_selector,
                agg_param,
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
        agg_param: &DapAggregationParam,
        enc_agg_shares: Vec<HpkeCiphertext>,
    ) -> DapAggregateResult {
        self.task_config
            .vdaf
            .consume_encrypted_agg_shares(
                &self.collector_hpke_receiver_config,
                &self.task_id,
                batch_selector,
                report_count,
                agg_param,
                enc_agg_shares,
                self.task_config.version,
            )
            .await
            .unwrap()
    }

    /// Generate a set of reports, aggregate them, and unshard the result.
    pub async fn roundtrip(
        &mut self,
        agg_param: DapAggregationParam,
        measurements: Vec<DapMeasurement>,
    ) -> DapAggregateResult {
        let batch_selector = BatchSelector::TimeInterval {
            batch_interval: Interval {
                start: self.now,
                duration: 3600,
            },
        };

        // Clients: Shard
        let reports = self.produce_reports(measurements);

        // Aggregators: Preparation
        let (leader_state, agg_job_init_req) = self.produce_agg_job_req(&agg_param, reports).await;

        let (leader_agg_span, helper_agg_span) = {
            let (helper_agg_span, agg_job_resp) = self.handle_agg_job_req(agg_job_init_req).await;
            let leader_agg_span = self.consume_agg_job_resp(leader_state, agg_job_resp);
            (leader_agg_span, helper_agg_span)
        };

        let report_count = u64::try_from(leader_agg_span.report_count()).unwrap();

        // Leader: Aggregation
        let leader_agg_share = leader_agg_span.collapsed();
        let leader_encrypted_agg_share =
            self.produce_leader_encrypted_agg_share(&batch_selector, &agg_param, &leader_agg_share);

        // Helper: Aggregation
        let helper_encrypted_agg_share = self.produce_helper_encrypted_agg_share(
            &batch_selector,
            &agg_param,
            &helper_agg_span.collapsed(),
        );

        // Collector: Unshard
        self.consume_encrypted_agg_shares(
            &batch_selector,
            report_count,
            &agg_param,
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
//     something_draft09
//
// and
//
//     something_latest
//
// that called something(version) with the appropriate version.
//
// We use the "paste" crate to get a macro that can paste tokens and also
// fiddle with the case.
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
            $crate::test_version! { $fname, Draft09 }
            $crate::test_version! { $fname, Latest }
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
            $crate::async_test_version! { $fname, Draft09 }
            $crate::async_test_version! { $fname, Latest }
        )*
    };
}

impl From<DapBatchBucket> for PartialBatchSelector {
    fn from(bucket: DapBatchBucket) -> Self {
        match bucket {
            DapBatchBucket::FixedSize { batch_id } => Self::FixedSizeByBatchId { batch_id },
            DapBatchBucket::TimeInterval { .. } => Self::TimeInterval,
        }
    }
}

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

/// Aggregate share and associated book-keeping data for a bucket of reports.
//
// TODO heavy hitters: Move this code into a space where `daphne_server` can use it. We need the
// same logic there.
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct AggregateStore {
    pub agg_share: DapAggregateShare,

    /// Indication of whether the bucket has been collected at least once. If set, new reports for
    /// this bucket will be rejected.
    pub collected: bool,

    /// The reports included in the current aggregate share. If a report wants to be aggregated is
    /// already in this set, it will be rejected.
    pub reports: HashSet<ReportId>,

    /// The current aggregation parameter.
    pub(crate) agg_param: DapAggregationParam,
}

impl AggregateStore {
    /// Check if the given aggregation parameter can be used to aggregate the reports in this bucket.
    ///
    /// For IDPF-based VDAFs (e.g., Mastic), this returns true only if the aggregation parameter
    /// results in a valid tree traversal, that is, each prefix encoded by the aggregation
    /// parameter is equal to or a child of a prefix in the current aggregation parameter.
    ///
    /// For simple VDAFs (e.g., Prio3), only the empty aggregation parameter is valid.
    //
    // TODO heavy hitters: Enforce the maximum tree depth.
    fn is_valid(&self, next_agg_param: &DapAggregationParam) -> bool {
        if matches!(self.agg_param, DapAggregationParam::Empty) {
            return matches!(next_agg_param, DapAggregationParam::Empty);
        }

        let curr_level = self.agg_param.level();
        let next_level = next_agg_param.level();

        // Ensure the aggregation level increases monotonically.
        if next_level < curr_level {
            return false;
        }

        // If the level is the same, then ensure the parameter hasn't changed.
        if next_level == curr_level && next_agg_param != &self.agg_param {
            return false;
        }

        // If the next level is greater than the previous, then check that the next parameter is
        // consistent with the current one.
        if next_level > curr_level {
            todo!("TODO heavy hitters: prefix consistency check")
        }

        true
    }

    /// If the given aggregation parameter is valid, then advance to it.
    pub fn goto(&mut self, agg_param: &DapAggregationParam) -> Option<&mut Self> {
        if !self.is_valid(agg_param) {
            return None;
        }

        if agg_param.level() > self.agg_param.level() {
            // Advance to the next level.
            self.agg_share.reset();
            self.collected = false;
            self.reports.clear();
            self.agg_param = agg_param.clone();
        }

        Some(self)
    }
}

#[derive(Default)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub(crate) struct InMemoryAggregateStore(HashMap<String, AggregateStore>);

impl InMemoryAggregateStore {
    /// Return the aggregate store for the given bucket.
    pub(crate) fn for_bucket(
        &mut self,
        task_id: &TaskId,
        bucket: &DapBatchBucket,
        agg_param: &DapAggregationParam,
    ) -> Option<&mut AggregateStore> {
        let agg_store = self
            .0
            .entry(format!("{task_id}/{bucket}"))
            .or_insert(AggregateStore {
                agg_share: Default::default(),
                collected: false,
                reports: Default::default(),
                agg_param: agg_param.clone(),
            });

        agg_store.goto(agg_param)
    }
}

/// An implementation of a DAP Aggregator without long-term storage. This is intended to be used
/// for testing purposes only.
pub struct InMemoryAggregator {
    pub global_config: DapGlobalConfig,
    pub(crate) tasks: Arc<Mutex<HashMap<TaskId, DapTaskConfig>>>,
    pub hpke_receiver_config_list: Vec<HpkeReceiverConfig>,
    pub leader_token: BearerToken,
    pub collector_token: Option<BearerToken>, // Not set by Helper
    pub(crate) leader_state_store: Arc<Mutex<InMemoryLeaderState>>,
    helper_state_store: Arc<Mutex<HashMap<HelperStateInfo, DapAggregationJobState>>>,
    pub(crate) agg_store: Arc<Mutex<InMemoryAggregateStore>>,
    pub collector_hpke_config: HpkeConfig,
    pub metrics: DaphnePromMetrics,
    pub(crate) audit_log: MockAuditLog,

    // taskprov
    pub taskprov_vdaf_verify_key_init: [u8; 32],
    pub taskprov_leader_token: BearerToken,
    pub taskprov_collector_token: Option<BearerToken>, // Not set by Helper

    // Leader: Reference to peer. Used to simulate HTTP requests from Leader to Helper, i.e.,
    // implement `DapLeader::send_http_post()` for `InMemoryAggregator`. Not set by the Helper.
    pub peer: Option<Arc<InMemoryAggregator>>,
}

impl DeepSizeOf for InMemoryAggregator {
    fn deep_size_of_children(&self, context: &mut deepsize::Context) -> usize {
        self.global_config.deep_size_of_children(context)
                + self.tasks.deep_size_of_children(context)
                + self
                    .hpke_receiver_config_list
                    .deep_size_of_children(context)
                + self.leader_token.deep_size_of_children(context)
                + self.collector_token.deep_size_of_children(context)
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

impl InMemoryAggregator {
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
            leader_state_store: Default::default(),
            helper_state_store: Default::default(),
            agg_store: Default::default(),
            collector_hpke_config,
            metrics: DaphnePromMetrics::register(registry).unwrap(),
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
            leader_state_store: Default::default(),
            helper_state_store: Default::default(),
            agg_store: Default::default(),
            collector_hpke_config,
            metrics: DaphnePromMetrics::register(registry).unwrap(),
            audit_log: MockAuditLog::default(),
            taskprov_vdaf_verify_key_init,
            taskprov_leader_token,
            taskprov_collector_token: taskprov_collector_token.into(),
            peer: peer.into(),
        }
    }

    fn is_leader(&self) -> bool {
        self.peer.is_some()
    }

    fn get_hpke_receiver_config_for(&self, hpke_config_id: u8) -> Option<&HpkeReceiverConfig> {
        self.hpke_receiver_config_list
            .iter()
            .find(|&hpke_receiver_config| hpke_config_id == hpke_receiver_config.config.id)
    }

    pub(crate) async fn unchecked_get_task_config(&self, task_id: &TaskId) -> DapTaskConfig {
        self.get_task_config_for(task_id)
            .await
            .expect("encountered unexpected error")
            .expect("missing task config")
    }
}

#[async_trait]
impl BearerTokenProvider for InMemoryAggregator {
    type WrappedBearerToken<'a> = &'a BearerToken;

    async fn get_leader_bearer_token_for<'s>(
        &'s self,
        _task_id: &'s TaskId,
        task_config: &DapTaskConfig,
    ) -> Result<Option<Self::WrappedBearerToken<'s>>, DapError> {
        if task_config.method_is_taskprov() {
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
        if task_config.method_is_taskprov() {
            Ok(Some(self.taskprov_collector_token.as_ref().expect(
                "InMemoryAggregator not configured with taskprov collector token",
            )))
        } else {
            Ok(Some(self.collector_token.as_ref().expect(
                "InMemoryAggregator not configured with collector token",
            )))
        }
    }
}

#[async_trait]
impl HpkeProvider for InMemoryAggregator {
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
        // required for InMemoryAggregator, we simulate this behavior for testing purposes.
        //
        // TODO(cjpatton) To make this clearer, have InMemoryAggregator store a map from task IDs to
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
}

#[async_trait]
impl HpkeDecrypter for InMemoryAggregator {
    async fn hpke_decrypt(
        &self,
        _task_id: &TaskId,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        if let Some(hpke_receiver_config) = self.get_hpke_receiver_config_for(ciphertext.config_id)
        {
            Ok(hpke_receiver_config.decrypt(info, aad, ciphertext)?)
        } else {
            Err(DapError::Transition(TransitionFailure::HpkeUnknownConfigId))
        }
    }
}

#[async_trait]
impl DapAuthorizedSender<BearerToken> for InMemoryAggregator {
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

#[async_trait]
impl DapReportInitializer for InMemoryAggregator {
    async fn initialize_reports(
        &self,
        is_leader: bool,
        task_config: &DapTaskConfig,
        agg_param: &DapAggregationParam,
        consumed_reports: Vec<EarlyReportStateConsumed>,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        initialize_reports(is_leader, task_config, agg_param, consumed_reports)
    }
}

#[async_trait]
impl DapAggregator<BearerToken> for InMemoryAggregator {
    // The lifetimes on the traits ensure that we can return a reference to a task config stored by
    // the DapAggregator. (See DaphneWorkerConfig for an example.) For simplicity, InMemoryAggregator
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
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;
        let mut agg_store = self.agg_store.lock().map_err(|e| fatal_error!(err = ?e))?;
        // TODO heavy hitters: Replace this with the agg param specified by the Collector.
        let agg_param = DapAggregationParam::Empty;

        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            if agg_store
                .for_bucket(task_id, &bucket, &agg_param)
                .ok_or_else(|| DapAbort::BadRequest("invalid aggregation parameter".into()))?
                .collected
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn batch_exists(&self, task_id: &TaskId, batch_id: &BatchId) -> Result<bool, DapError> {
        let bucket = DapBatchBucket::FixedSize {
            batch_id: *batch_id,
        };

        let aggregated = {
            let mut agg_store = self.agg_store.lock().map_err(|e| fatal_error!(err = ?e))?;
            // TODO heavy hitters: Replace this with the agg param specified by the Collector.
            let agg_param = DapAggregationParam::Empty;
            !agg_store
                .for_bucket(task_id, &bucket, &agg_param)
                .ok_or_else(|| DapAbort::BadRequest("invalid aggregation parameter".into()))?
                .agg_share
                .empty()
        };

        let uploaded = {
            let leader_state = self
                .leader_state_store
                .lock()
                .map_err(|e| fatal_error!(err = ?e))?;
            self.is_leader() && leader_state.contains_queued_task_of_batch(task_id, batch_id)
        };

        Ok(aggregated || uploaded)
    }

    async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        _task_config: &DapTaskConfig,
        agg_span: DapAggregateSpan<DapAggregateShare>,
    ) -> DapAggregateSpan<Result<(), MergeAggShareError>> {
        let mut agg_store = self.agg_store.lock().unwrap();
        // TODO heavy hitters: Replace this with the agg param specified by the Collector.
        let agg_param = DapAggregationParam::Empty;

        agg_span
            .into_iter()
            .map(|(bucket, (agg_share_delta, report_metadatas))| {
                let Some( agg_store_for_bucket) = agg_store.for_bucket(task_id, &bucket, &agg_param) else {
                    todo!("TODO heavy hitters: reject all reports in the bucket due to invalid aggregation parameter");
                };

                let replayed = report_metadatas
                    .iter()
                    .map(|(id, _)| *id)
                    .filter(|id| agg_store_for_bucket.reports.contains(id))
                    .collect::<HashSet<_>>();

                let result = if replayed.is_empty() {
                    agg_store_for_bucket
                        .reports
                        .extend(report_metadatas.iter().map(|(id, _)| *id));
                    // Add to aggregate share.
                    if agg_store_for_bucket.collected {
                        Err(MergeAggShareError::AlreadyCollected)
                    } else {
                        agg_store_for_bucket
                            .agg_share
                            .merge(agg_share_delta.clone())
                            .map_err(MergeAggShareError::Other)
                    }
                } else {
                    Err(MergeAggShareError::ReplaysDetected(replayed))
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
        let mut agg_store = self.agg_store.lock().map_err(|e| fatal_error!(err = ?e))?;
        // TODO heavy hitters: Replace this with the agg param specified by the Collector.
        let agg_param = DapAggregationParam::Empty;

        // Fetch aggregate shares.
        let mut agg_share = DapAggregateShare::default();
        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            let agg_store_for_bucket = agg_store
                .for_bucket(task_id, &bucket, &agg_param)
                .ok_or_else(|| {
                    DapError::Abort(DapAbort::BadRequest(
                        "unexpected aggregation parameter".to_string(),
                    ))
                })?;
            if agg_store_for_bucket.collected {
                return Err(DapError::Abort(DapAbort::batch_overlap(task_id, batch_sel)));
            }
            agg_share.merge(agg_store_for_bucket.agg_share.clone())?;
        }

        Ok(agg_share)
    }

    async fn mark_collected(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError> {
        let task_config = self.unchecked_get_task_config(task_id).await;
        let mut agg_store = self.agg_store.lock().map_err(|e| fatal_error!(err = ?e))?;
        // TODO heavy hitters: Replace this with the agg param specified by the Collector.
        let agg_param = DapAggregationParam::Empty;

        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            agg_store
                .for_bucket(task_id, &bucket, &agg_param)
                .ok_or_else(|| {
                    DapError::Abort(DapAbort::BadRequest(
                        "unexpected aggregation parameter".to_string(),
                    ))
                })?
                .collected = true;
        }

        Ok(())
    }

    fn metrics(&self) -> &dyn DaphneMetrics {
        &self.metrics
    }

    fn audit_log(&self) -> &dyn AuditLog {
        &self.audit_log
    }

    fn host(&self) -> &str {
        "unspecified-host"
    }
}

#[async_trait]
impl DapHelper<BearerToken> for InMemoryAggregator {
    async fn put_helper_state_if_not_exists(
        &self,
        task_id: &TaskId,
        agg_job_id: &AggregationJobId,
        helper_state: &DapAggregationJobState,
    ) -> Result<bool, DapError> {
        let helper_state_info = HelperStateInfo {
            task_id: *task_id,
            agg_job_id: *agg_job_id,
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
        agg_job_id: &AggregationJobId,
    ) -> Result<Option<DapAggregationJobState>, DapError> {
        let helper_state_info = HelperStateInfo {
            task_id: *task_id,
            agg_job_id: *agg_job_id,
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

#[async_trait]
impl DapLeader<BearerToken> for InMemoryAggregator {
    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| fatal_error!(err = "task not found"))?;

        self.leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?
            .put_report(task_id, &task_config, report.clone())
    }

    async fn current_batch(&self, task_id: &TaskId) -> std::result::Result<BatchId, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| fatal_error!(err = "task not found"))?;

        self.leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?
            .current_batch(task_id, &task_config)
    }

    async fn dequeue_work(&self, num_items: usize) -> Result<Vec<WorkItem>, DapError> {
        self.leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?
            .dequeue_work(num_items)
    }

    async fn enqueue_work(&self, work_items: Vec<WorkItem>) -> Result<(), DapError> {
        let mut leader_state = self
            .leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?;

        for work_item in work_items {
            leader_state.work_queue_mut().push_back(work_item);
        }
        Ok(())
    }

    // Called after receiving a CollectReq from Collector.
    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
        batch_sel: BatchSelector,
        agg_param: DapAggregationParam,
    ) -> Result<Url, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| fatal_error!(err = "task not found"))?;

        self.leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?
            .init_collect_job(task_id, &task_config, coll_job_id, batch_sel, agg_param)
    }

    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
    ) -> Result<DapCollectionJob, DapError> {
        self.leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?
            .poll_collect_job(task_id, coll_job_id)
    }

    async fn finish_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
        collection: &Collection,
    ) -> Result<(), DapError> {
        self.leader_state_store
            .lock()
            .map_err(|e| fatal_error!(err = ?e))?
            .finish_collect_job(task_id, coll_job_id, collection)
    }

    async fn send_http_post(
        &self,
        req: DapRequest<BearerToken>,
        _url: Url,
    ) -> Result<DapResponse, DapError> {
        match req.media_type {
            Some(DapMediaType::AggregationJobInitReq) => Ok(helper::handle_agg_job_req(
                &**self.peer.as_ref().expect("peer not configured"),
                &req,
            )
            .await
            .expect("peer aborted unexpectedly")),
            Some(DapMediaType::AggregateShareReq) => Ok(helper::handle_agg_share_req(
                &**self.peer.as_ref().expect("peer not configured"),
                &req,
            )
            .await
            .expect("peer aborted unexpectedly")),
            _ => unreachable!("unhandled media type: {:?}", req.media_type),
        }
    }

    async fn send_http_put(
        &self,
        req: DapRequest<BearerToken>,
        _url: Url,
    ) -> Result<DapResponse, DapError> {
        if req.media_type == Some(DapMediaType::AggregationJobInitReq) {
            Ok(helper::handle_agg_job_req(
                &**self.peer.as_ref().expect("peer not configured"),
                &req,
            )
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
struct HelperStateInfo {
    task_id: TaskId,
    agg_job_id: AggregationJobId,
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
