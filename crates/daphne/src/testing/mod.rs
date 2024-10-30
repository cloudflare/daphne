// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Mock backend functionality to test DAP protocol.

#[cfg(feature = "report-generator")]
pub mod report_generator;

use crate::{
    audit_log::AuditLog,
    constants::DapMediaType,
    fatal_error,
    hpke::{HpkeConfig, HpkeKemId, HpkeProvider, HpkeReceiverConfig},
    messages::{
        self, request::resource, AggregationJobId, AggregationJobInitReq, AggregationJobResp,
        Base64Encode, BatchId, BatchSelector, Collection, CollectionJobId, HpkeCiphertext,
        Interval, PartialBatchSelector, Report, ReportId, TaskId, Time,
    },
    metrics::{prometheus::DaphnePromMetrics, DaphneMetrics},
    protocol::aggregator::{EarlyReportStateConsumed, EarlyReportStateInitialized},
    roles::{
        aggregator::{MergeAggShareError, TaskprovConfig},
        helper,
        leader::{in_memory_leader::InMemoryLeaderState, WorkItem},
        DapAggregator, DapHelper, DapLeader, DapReportInitializer,
    },
    taskprov,
    vdaf::VdafVerifyKey,
    DapAbort, DapAggregateResult, DapAggregateShare, DapAggregateSpan, DapAggregationJobState,
    DapAggregationParam, DapBatchBucket, DapCollectionJob, DapError, DapGlobalConfig,
    DapMeasurement, DapQueryConfig, DapRequest, DapRequestMeta, DapResponse, DapTaskConfig,
    DapVersion, ReplayProtection, VdafConfig,
};
use async_trait::async_trait;
use deepsize::DeepSizeOf;
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    num::NonZeroUsize,
    ops::{DerefMut, Range},
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
    pub(crate) client_hpke_config_list: [HpkeConfig; 2],
    pub(crate) collector_hpke_receiver_config: HpkeReceiverConfig,

    replay_protection: ReplayProtection,

    // the current time
    pub(crate) now: Time,
    pub(crate) valid_report_range: Range<Time>,

    // operational parameters
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) leader_registry: prometheus::Registry,
    pub(crate) leader_metrics: DaphnePromMetrics,
}

#[cfg(test)]
async fn initialize_reports(
    is_leader: bool,
    vdaf_verify_key: VdafVerifyKey,
    vdaf: VdafConfig,
    agg_param: &DapAggregationParam,
    consumed_reports: Vec<EarlyReportStateConsumed>,
) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    let agg_param = agg_param.clone();
    tokio::task::spawn_blocking(move || {
        consumed_reports
            .into_par_iter()
            .map(|consumed| {
                EarlyReportStateInitialized::initialize(
                    is_leader,
                    &vdaf_verify_key,
                    &vdaf,
                    &agg_param,
                    consumed,
                )
            })
            .collect()
    })
    .await
    .unwrap()
}

#[cfg(not(test))]
#[expect(clippy::unused_async)]
async fn initialize_reports(
    is_leader: bool,
    vdaf_verify_key: VdafVerifyKey,
    vdaf: VdafConfig,
    agg_param: &DapAggregationParam,
    consumed_reports: Vec<EarlyReportStateConsumed>,
) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
    consumed_reports
        .into_iter()
        .map(|consumed| {
            EarlyReportStateInitialized::initialize(
                is_leader,
                &vdaf_verify_key,
                &vdaf,
                agg_param,
                consumed,
            )
        })
        .collect()
}

#[async_trait]
impl DapReportInitializer for AggregationJobTest {
    fn valid_report_time_range(&self) -> Range<Time> {
        self.valid_report_range.clone()
    }

    async fn initialize_reports(
        &self,
        is_leader: bool,
        task_config: &DapTaskConfig,
        agg_param: &DapAggregationParam,
        consumed_reports: Vec<EarlyReportStateConsumed>,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        initialize_reports(
            is_leader,
            task_config.vdaf_verify_key.clone(),
            task_config.vdaf,
            agg_param,
            consumed_reports,
        )
        .await
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
            // Accept reports within two minutes of the current time.
            valid_report_range: now - 60..now + 60,
            task_id,
            leader_hpke_receiver_config,
            helper_hpke_receiver_config,
            client_hpke_config_list: [leader_hpke_config, helper_hpke_config],
            collector_hpke_receiver_config,
            task_config: DapTaskConfig {
                version,
                leader_url: Url::parse("http://leader.com").unwrap(),
                helper_url: Url::parse("https://helper.org").unwrap(),
                time_precision: 500,
                not_before: now,
                not_after: now + 500,
                min_batch_size: 10,
                query: DapQueryConfig::TimeInterval,
                vdaf: *vdaf,
                vdaf_verify_key,
                collector_hpke_config,
                method: Default::default(),
                num_agg_span_shards: NonZeroUsize::new(3).unwrap(),
            },
            replay_protection: ReplayProtection::Enabled,
            leader_registry,
            leader_metrics,
        }
    }

    pub fn disable_replay_protection(&mut self) {
        self.replay_protection = ReplayProtection::InsecureDisabled;
    }

    pub fn change_vdaf(&mut self, vdaf: VdafConfig) {
        self.task_config.vdaf = vdaf;
        self.task_config.vdaf_verify_key = vdaf.gen_verify_key();
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

    pub fn produce_repeated_reports(
        &self,
        measurement: DapMeasurement,
    ) -> impl Iterator<Item = Report> + Clone {
        std::iter::repeat(
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
        )
    }

    /// Leader: Produce `AggregationJobInitReq`.
    ///
    /// Panics if the Leader aborts.
    pub async fn produce_agg_job_req(
        &self,
        agg_param: &DapAggregationParam,
        reports: impl IntoIterator<Item = Report>,
    ) -> (DapAggregationJobState, AggregationJobInitReq) {
        self.task_config
            .test_produce_agg_job_req(
                &self.leader_hpke_receiver_config,
                self,
                &self.task_id,
                &PartialBatchSelector::TimeInterval,
                agg_param,
                futures::stream::iter(reports),
                &self.leader_metrics,
                self.replay_protection,
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
                        self.replay_protection,
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

    /// Like [`Self::consume_agg_job_resp`] but expect the Leader to abort.
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
    pub fn consume_encrypted_agg_shares(
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

#[derive(Default)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct MockAuditLog(AtomicU32);

impl MockAuditLog {
    #[cfg(test)]
    pub(crate) fn invocations(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

impl AuditLog for MockAuditLog {
    fn on_aggregation_job(
        &self,
        _task_id: &TaskId,
        _task_config: &DapTaskConfig,
        _report_count: u64,
        _vdaf_step: u8,
    ) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Aggregate share and associated book-keeping data for a bucket of reports.
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct AggregateStore {
    pub agg_share: DapAggregateShare,

    /// Indication of whether the bucket has been collected at least once. If set, new reports for
    /// this bucket will be rejected.
    pub collected: bool,

    /// The reports included in the current aggregate share. If a report wants to be aggregated is
    /// already in this set, it will be rejected.
    pub reports: HashSet<ReportId>,
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
    ) -> &mut AggregateStore {
        let agg_store = self
            .0
            .entry(format!("{task_id}/{bucket}"))
            .or_insert(AggregateStore {
                agg_share: Default::default(),
                collected: false,
                reports: Default::default(),
            });

        agg_store
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// An implementation of a DAP Aggregator without long-term storage. This is intended to be used
/// for testing purposes only.
pub struct InMemoryAggregator {
    pub(crate) global_config: DapGlobalConfig,
    tasks: Mutex<HashMap<TaskId, DapTaskConfig>>,
    pub hpke_receiver_config_list: Box<[HpkeReceiverConfig]>,
    collector_hpke_config: HpkeConfig,

    // aggregation state
    leader_state_store: Arc<Mutex<InMemoryLeaderState>>,
    pub(crate) agg_store: Arc<Mutex<InMemoryAggregateStore>>,

    // telemetry
    metrics: DaphnePromMetrics,
    pub audit_log: MockAuditLog,

    // taskprov
    taskprov_vdaf_verify_key_init: [u8; 32],

    // Leader: Reference to peer. Used to simulate HTTP requests from Leader to Helper, i.e.,
    // implement `DapLeader::send_http_post()` for `InMemoryAggregator`. Not set by the Helper.
    peer: Option<Arc<InMemoryAggregator>>,
}

impl DeepSizeOf for InMemoryAggregator {
    fn deep_size_of_children(&self, context: &mut deepsize::Context) -> usize {
        let Self {
            global_config,
            tasks,
            hpke_receiver_config_list,
            leader_state_store,
            agg_store,
            collector_hpke_config,
            metrics: _,
            audit_log: _,
            taskprov_vdaf_verify_key_init,
            peer,
        } = self;
        global_config.deep_size_of_children(context)
            + tasks.deep_size_of_children(context)
            + hpke_receiver_config_list.deep_size_of_children(context)
            + leader_state_store.deep_size_of_children(context)
            + agg_store.deep_size_of_children(context)
            + collector_hpke_config.deep_size_of_children(context)
            + taskprov_vdaf_verify_key_init.deep_size_of_children(context)
            + peer.deep_size_of_children(context)
    }
}

impl InMemoryAggregator {
    pub fn new_helper(
        tasks: impl IntoIterator<Item = (TaskId, DapTaskConfig)>,
        hpke_receiver_config_list: impl IntoIterator<Item = HpkeReceiverConfig>,
        global_config: DapGlobalConfig,
        collector_hpke_config: HpkeConfig,
        registry: &prometheus::Registry,
        taskprov_vdaf_verify_key_init: [u8; 32],
    ) -> Self {
        Self {
            global_config,
            tasks: Mutex::new(tasks.into_iter().collect()),
            hpke_receiver_config_list: hpke_receiver_config_list.into_iter().collect(),
            leader_state_store: Default::default(),
            agg_store: Default::default(),
            collector_hpke_config,
            metrics: DaphnePromMetrics::register(registry).unwrap(),
            audit_log: MockAuditLog::default(),
            taskprov_vdaf_verify_key_init,
            peer: None,
        }
    }

    pub fn new_leader(
        tasks: impl IntoIterator<Item = (TaskId, DapTaskConfig)>,
        hpke_receiver_config_list: impl IntoIterator<Item = HpkeReceiverConfig>,
        global_config: DapGlobalConfig,
        collector_hpke_config: HpkeConfig,
        registry: &prometheus::Registry,
        taskprov_vdaf_verify_key_init: [u8; 32],
        peer: Arc<Self>,
    ) -> Self {
        Self {
            global_config,
            tasks: Mutex::new(tasks.into_iter().collect()),
            hpke_receiver_config_list: hpke_receiver_config_list.into_iter().collect(),
            leader_state_store: Default::default(),
            agg_store: Default::default(),
            collector_hpke_config,
            metrics: DaphnePromMetrics::register(registry).unwrap(),
            audit_log: MockAuditLog::default(),
            taskprov_vdaf_verify_key_init,
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

    pub fn clear_storage(&self) {
        self.leader_state_store.lock().unwrap().delete_all();
        self.agg_store.lock().unwrap().clear();
    }
}

#[async_trait]
impl HpkeProvider for InMemoryAggregator {
    type WrappedHpkeConfig<'a> = &'a HpkeConfig;

    type ReceiverConfigs<'a> = &'a [HpkeReceiverConfig];

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

    async fn get_receiver_configs<'s>(
        &'s self,
        _version: DapVersion,
    ) -> Result<Self::ReceiverConfigs<'s>, DapError> {
        Ok(&self.hpke_receiver_config_list)
    }

    async fn can_hpke_decrypt(&self, _task_id: &TaskId, config_id: u8) -> Result<bool, DapError> {
        Ok(self.get_hpke_receiver_config_for(config_id).is_some())
    }
}

#[async_trait]
impl DapReportInitializer for InMemoryAggregator {
    fn valid_report_time_range(&self) -> Range<messages::Time> {
        // Accept reports with any timestmap.
        0..u64::MAX
    }

    async fn initialize_reports(
        &self,
        is_leader: bool,
        task_config: &DapTaskConfig,
        agg_param: &DapAggregationParam,
        consumed_reports: Vec<EarlyReportStateConsumed>,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        initialize_reports(
            is_leader,
            task_config.vdaf_verify_key.clone(),
            task_config.vdaf,
            agg_param,
            consumed_reports,
        )
        .await
    }
}

#[async_trait]
impl DapAggregator for InMemoryAggregator {
    // The lifetimes on the traits ensure that we can return a reference to a task config stored by
    // the DapAggregator. (See DaphneWorkerConfig for an example.) For simplicity, InMemoryAggregator
    // clones the task config as needed.
    type WrappedDapTaskConfig<'a> = DapTaskConfig;

    async fn get_global_config(&self) -> Result<DapGlobalConfig, DapError> {
        Ok(self.global_config.clone())
    }

    fn get_taskprov_config(&self) -> Option<TaskprovConfig<'_>> {
        Some(TaskprovConfig {
            hpke_collector_config: &self.collector_hpke_config,
            vdaf_verify_key_init: &self.taskprov_vdaf_verify_key_init,
        })
    }

    async fn taskprov_opt_in(
        &self,
        _task_id: &TaskId,
        task_config: taskprov::DapTaskConfigNeedsOptIn,
    ) -> Result<DapTaskConfig, DapError> {
        // Always opt-in with four shards.
        Ok(task_config.into_opted_in(&taskprov::OptInParam {
            not_before: self.get_current_time(),
            num_agg_span_shards: NonZeroUsize::new(4).unwrap(),
        }))
    }

    async fn taskprov_put(
        &self,
        req: &DapRequestMeta,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError> {
        let mut tasks = self.tasks.lock().expect("tasks: lock failed");
        tasks.deref_mut().insert(req.task_id, task_config);
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
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: *task_id,
            }))?;
        let mut agg_store = self
            .agg_store
            .lock()
            .map_err(|_| fatal_error!(err = "agg_store poisoned"))?;

        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            if agg_store.for_bucket(task_id, &bucket).collected {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn batch_exists(&self, task_id: &TaskId, batch_id: &BatchId) -> Result<bool, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: *task_id,
            }))?;

        let aggregated = {
            let mut agg_store = self
                .agg_store
                .lock()
                .map_err(|_| fatal_error!(err = "agg_store poisoned"))?;
            let mut aggregated = false;
            for bucket in task_config.batch_span_for_sel(&BatchSelector::FixedSizeByBatchId {
                batch_id: *batch_id,
            })? {
                if !agg_store.for_bucket(task_id, &bucket).agg_share.empty() {
                    aggregated = true;
                    break;
                }
            }
            aggregated
        };

        let uploaded = {
            let leader_state = self
                .leader_state_store
                .lock()
                .map_err(|_| fatal_error!(err = "leader_state_store poisoned"))?;
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

        agg_span
            .into_iter()
            .map(|(bucket, (agg_share_delta, report_metadatas))| {
                let agg_store_for_bucket = agg_store.for_bucket(task_id, &bucket);

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
        let mut agg_store = self
            .agg_store
            .lock()
            .map_err(|_| fatal_error!(err = "agg_store poisoned"))?;

        // Fetch aggregate shares.
        let mut agg_share = DapAggregateShare::default();
        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            let agg_store_for_bucket = agg_store.for_bucket(task_id, &bucket);
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
        let mut agg_store = self
            .agg_store
            .lock()
            .map_err(|_| fatal_error!(err = "agg_store poisoned"))?;

        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            agg_store.for_bucket(task_id, &bucket).collected = true;
        }

        Ok(())
    }

    fn metrics(&self) -> &dyn DaphneMetrics {
        &self.metrics
    }

    fn audit_log(&self) -> &dyn AuditLog {
        &self.audit_log
    }
}

#[async_trait]
impl DapHelper for InMemoryAggregator {}

#[async_trait]
impl DapLeader for InMemoryAggregator {
    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| fatal_error!(err = "task not found"))?;

        self.leader_state_store
            .lock()
            .map_err(|_| fatal_error!(err = "leader_state_store poisoned"))?
            .put_report(task_id, &task_config, report.clone())
    }

    async fn current_batch(&self, task_id: &TaskId) -> std::result::Result<BatchId, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| fatal_error!(err = "task not found"))?;

        self.leader_state_store
            .lock()
            .map_err(|_| fatal_error!(err = "leader_state_store poisoned"))?
            .current_batch(task_id, &task_config)
    }

    async fn dequeue_work(&self, num_items: usize) -> Result<Vec<WorkItem>, DapError> {
        self.leader_state_store
            .lock()
            .map_err(|_| fatal_error!(err = "leader_state_store poisoned"))?
            .dequeue_work(num_items)
    }

    async fn enqueue_work(&self, work_items: Vec<WorkItem>) -> Result<(), DapError> {
        let mut leader_state = self
            .leader_state_store
            .lock()
            .map_err(|_| fatal_error!(err = "leader_state_store poisoned"))?;

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
    ) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| fatal_error!(err = "task not found"))?;

        self.leader_state_store
            .lock()
            .map_err(|_| fatal_error!(err = "leader_state_store poisoned"))?
            .init_collect_job(task_id, &task_config, coll_job_id, batch_sel, agg_param)
    }

    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
    ) -> Result<DapCollectionJob, DapError> {
        self.leader_state_store
            .lock()
            .map_err(|_| fatal_error!(err = "leader_state_store poisoned"))?
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
            .map_err(|_| fatal_error!(err = "leader_state_store poisoned"))?
            .finish_collect_job(task_id, coll_job_id, collection)
    }

    async fn send_http_post<P>(
        &self,
        meta: DapRequestMeta,
        url: Url,
        payload: P,
    ) -> Result<DapResponse, DapError>
    where
        P: Send + ParameterizedEncode<DapVersion>,
    {
        match meta.media_type {
            Some(DapMediaType::AggregationJobInitReq) => Ok(helper::handle_agg_job_init_req(
                &**self.peer.as_ref().expect("peer not configured"),
                DapRequest {
                    payload: re_encode(&meta, payload),
                    resource_id: resource::AggregationJobId::try_from_base64url(
                        url.path().split('/').last().unwrap(),
                    )
                    .unwrap(),
                    meta,
                },
                Default::default(),
            )
            .await
            .expect("peer aborted unexpectedly")),
            Some(DapMediaType::AggregateShareReq) => Ok(helper::handle_agg_share_req(
                &**self.peer.as_ref().expect("peer not configured"),
                DapRequest {
                    payload: re_encode(&meta, payload),
                    resource_id: resource::None,
                    meta,
                },
            )
            .await
            .expect("peer aborted unexpectedly")),
            _ => unreachable!("unhandled media type: {:?}", meta.media_type),
        }
    }

    async fn send_http_put<P>(
        &self,
        meta: DapRequestMeta,
        url: Url,
        payload: P,
    ) -> Result<DapResponse, DapError>
    where
        P: Send + ParameterizedEncode<DapVersion>,
    {
        if meta.media_type == Some(DapMediaType::AggregationJobInitReq) {
            Ok(helper::handle_agg_job_init_req(
                &**self.peer.as_ref().expect("peer not configured"),
                DapRequest {
                    payload: re_encode(&meta, payload),
                    resource_id: resource::AggregationJobId::try_from_base64url(
                        url.path().split('/').last().unwrap(),
                    )
                    .unwrap(),
                    meta,
                },
                Default::default(),
            )
            .await
            .expect("peer aborted unexpectedly"))
        } else {
            unreachable!("unhandled media type: {:?}", meta.media_type)
        }
    }
}

// this is effectively simulates the network boundary the request goes through. We must write to
// the wire (ParameterizedEncode) and decode from the wire (ParameterizedDecode).
//
// This is only correct if I is the same type as O. But this can't be checked at compile time.
fn re_encode<I, O>(meta: &DapRequestMeta, payload: I) -> O
where
    I: ParameterizedEncode<DapVersion>,
    O: ParameterizedDecode<DapVersion>,
{
    let version = meta.version;
    O::get_decoded_with_param(&version, &payload.get_encoded_with_param(&version).unwrap()).unwrap()
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

impl VdafConfig {
    pub fn gen_measurement(&self) -> Result<DapMeasurement, DapError> {
        match self {
            Self::Prio2 { dimension } => Ok(DapMeasurement::U32Vec(vec![1; *dimension])),
            Self::Prio3(crate::vdaf::Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                length,
                ..
            }) => Ok(DapMeasurement::U64Vec(vec![0; *length])),
            _ => Err(fatal_error!(
                err = format!("gen_measurement_for currently does not support {self:?}")
            )),
        }
    }
}
