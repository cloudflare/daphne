// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Mock backend functionality to test DAP protocol.

use crate::{
    auth::{BearerToken, BearerTokenProvider},
    constants,
    hpke::{HpkeDecrypter, HpkeReceiverConfig},
    messages::{
        BatchSelector, CollectReq, CollectResp, HpkeCiphertext, HpkeConfig, Id,
        PartialBatchSelector, Report, ReportId, ReportMetadata, Time, TransitionFailure,
    },
    metrics::DaphneMetrics,
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    taskprov, DapAbort, DapAggregateShare, DapBatchBucket, DapCollectJob, DapError,
    DapGlobalConfig, DapHelperState, DapOutputShare, DapQueryConfig, DapRequest, DapResponse,
    DapTaskConfig, DapVersion,
};
use assert_matches::assert_matches;
use async_trait::async_trait;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    borrow::{Borrow, Cow},
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::SystemTime,
};
use url::Url;

#[derive(Eq, Hash, PartialEq)]
pub(crate) enum DapBatchBucketOwned {
    FixedSize { batch_id: Id },
    TimeInterval { batch_window: Time },
}

impl From<DapBatchBucketOwned> for PartialBatchSelector {
    fn from(bucket: DapBatchBucketOwned) -> Self {
        match bucket {
            DapBatchBucketOwned::FixedSize { batch_id } => Self::FixedSizeByBatchId { batch_id },
            DapBatchBucketOwned::TimeInterval { .. } => Self::TimeInterval,
        }
    }
}

impl<'a> DapBatchBucket<'a> {
    // TODO(cjpatton) Figure out how to use `ToOwned` properly. The lifetime parameter causes
    // confusion for the compiler for implementing `Borrow`. The goal is to avoid cloning the
    // bucket each time we need to check if it exists in the set.
    pub(crate) fn to_owned_bucket(&self) -> DapBatchBucketOwned {
        match self {
            Self::FixedSize { batch_id } => DapBatchBucketOwned::FixedSize {
                batch_id: (*batch_id).clone(),
            },
            Self::TimeInterval { batch_window } => DapBatchBucketOwned::TimeInterval {
                batch_window: *batch_window,
            },
        }
    }
}

pub(crate) struct MockAggregatorReportSelector(pub(crate) Id);

pub(crate) struct MockAggregator {
    pub(crate) global_config: DapGlobalConfig,
    pub(crate) tasks: Arc<Mutex<HashMap<Id, DapTaskConfig>>>,
    pub(crate) hpke_receiver_config_list: Vec<HpkeReceiverConfig>,
    pub(crate) leader_token: BearerToken,
    pub(crate) collector_token: Option<BearerToken>, // Not set by Helper
    pub(crate) report_store: Arc<Mutex<HashMap<Id, ReportStore>>>,
    pub(crate) leader_state_store: Arc<Mutex<HashMap<Id, LeaderState>>>,
    pub(crate) helper_state_store: Arc<Mutex<HashMap<HelperStateInfo, DapHelperState>>>,
    pub(crate) agg_store: Arc<Mutex<HashMap<Id, HashMap<DapBatchBucketOwned, AggStore>>>>,
    pub(crate) collector_hpke_config: HpkeConfig,
    pub(crate) taskprov_vdaf_verify_key_init: Vec<u8>,
    pub(crate) metrics: DaphneMetrics,

    // Leader: Reference to peer. Used to simulate HTTP requests from Leader to Helper, i.e.,
    // implement `DapLeader::send_http_post()` for `MockAggregator`. Not set by the Helper.
    pub(crate) peer: Option<Arc<MockAggregator>>,
}

impl MockAggregator {
    /// Conducts checks on a received report to see whether:
    /// 1) the report falls into a batch that has been already collected, or
    /// 2) the report has been submitted by the client in the past.
    async fn check_report_early_fail(
        &self,
        task_id: &Id,
        bucket: &DapBatchBucketOwned,
        metadata: &ReportMetadata,
    ) -> Option<TransitionFailure> {
        // Check AggStateStore to see whether the report is part of a batch that has already
        // been collected.
        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(task_id.clone()).or_default();
        if matches!(agg_store.get(bucket), Some(inner_agg_store) if inner_agg_store.collected) {
            return Some(TransitionFailure::BatchCollected);
        }

        // Check whether the same report has been submitted in the past.
        let mut guard = self
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        let report_store = guard.entry(task_id.clone()).or_default();
        if report_store.processed.contains(&metadata.id) {
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
    async fn assign_report_to_bucket(&self, report: &Report) -> Option<DapBatchBucketOwned> {
        let mut rng = thread_rng();
        let task_config = self
            .get_task_config_for(Cow::Borrowed(&report.task_id))
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
                let leader_state_store = guard.entry(report.task_id.clone()).or_default();

                // Assign the report to the first unsaturated batch.
                for (batch_id, report_count) in leader_state_store.batch_queue.iter_mut() {
                    if *report_count < task_config.min_batch_size {
                        *report_count += 1;
                        return Some(DapBatchBucketOwned::FixedSize {
                            batch_id: batch_id.clone(),
                        });
                    }
                }

                // No unsaturated batch exists, so create a new batch.
                let batch_id = Id(rng.gen());
                leader_state_store
                    .batch_queue
                    .push_back((batch_id.clone(), 1));
                Some(DapBatchBucketOwned::FixedSize { batch_id })
            }

            // For time-interval queries, the bucket is the batch window computed by truncating the
            // report timestamp.
            DapQueryConfig::TimeInterval => Some(DapBatchBucketOwned::TimeInterval {
                batch_window: task_config.truncate_time(report.metadata.time),
            }),
        }
    }

    /// Return the ID of the batch currently being filled with reports. Panics unless the task is
    /// configured for fixed-size queries.
    pub(crate) fn current_batch_id(&self, task_id: &Id, task_config: &DapTaskConfig) -> Option<Id> {
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
            .cloned() // TODO(cjpatton) Avoid clone by returning MutexGuard
            .map(|(batch_id, _report_count)| batch_id)
    }

    pub(crate) async fn unchecked_get_task_config(&self, task_id: &Id) -> DapTaskConfig {
        self.get_task_config_for(Cow::Borrowed(task_id))
            .await
            .expect("encountered unexpected error")
            .expect("missing task config")
    }
}

#[async_trait(?Send)]
impl<'a> BearerTokenProvider<'a> for MockAggregator {
    type WrappedBearerToken = &'a BearerToken;

    async fn get_leader_bearer_token_for(
        &'a self,
        _task_id: &'a Id,
    ) -> Result<Option<&'a BearerToken>, DapError> {
        Ok(Some(&self.leader_token))
    }

    async fn get_collector_bearer_token_for(
        &'a self,
        _task_id: &'a Id,
    ) -> Result<Option<&'a BearerToken>, DapError> {
        if let Some(ref collector_token) = self.collector_token {
            Ok(Some(collector_token))
        } else {
            Err(DapError::fatal(
                "MockAggregator not configured with Collector bearer token",
            ))
        }
    }

    fn is_taskprov_leader_bearer_token(&self, _token: &BearerToken) -> bool {
        // MockAggregator currently uses the same token for all tasks, regardless of how the task
        // is configured. As a result, we don't expect BearerTokenProver::bearer_token_authorized()
        // to ever reach this point.
        unreachable!("did not expect to check bearer token");
    }

    fn is_taskprov_collector_bearer_token(&self, _token: &BearerToken) -> bool {
        // MockAggregator currently uses the same token for all tasks, regardless of how the task
        // is configured. As a result, we don't expect BearerTokenProver::bearer_token_authorized()
        // to ever reach this point.
        unreachable!("did not expect to check bearer token");
    }
}

#[async_trait(?Send)]
impl<'a> HpkeDecrypter<'a> for MockAggregator {
    type WrappedHpkeConfig = &'a HpkeConfig;

    async fn get_hpke_config_for(
        &'a self,
        task_id: Option<&Id>,
    ) -> Result<&'a HpkeConfig, DapError> {
        if self.hpke_receiver_config_list.is_empty() {
            return Err(DapError::fatal("emtpy HPKE receiver config list"));
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

    async fn can_hpke_decrypt(&self, _task_id: &Id, config_id: u8) -> Result<bool, DapError> {
        Ok(self.get_hpke_receiver_config_for(config_id).is_some())
    }

    async fn hpke_decrypt(
        &self,
        _task_id: &Id,
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
        task_id: &Id,
        media_type: &'static str,
        _payload: &[u8],
    ) -> Result<BearerToken, DapError> {
        Ok(self
            .authorize_with_bearer_token(task_id, media_type)
            .await?
            .clone())
    }
}

#[async_trait(?Send)]
impl<'srv, 'req> DapAggregator<'srv, 'req, BearerToken> for MockAggregator
where
    'srv: 'req,
{
    // The lifetimes on the traits ensure that we can return a reference to a task config stored by
    // the DapAggregator. (See DaphneWorkerConfig for an example.) For simplicity, MockAggregator
    // clones the task config as needed.
    type WrappedDapTaskConfig = DapTaskConfig;

    async fn authorized(&self, req: &DapRequest<BearerToken>) -> Result<bool, DapError> {
        self.bearer_token_authorized(req).await
    }

    fn get_global_config(&self) -> &DapGlobalConfig {
        &self.global_config
    }

    fn taskprov_opt_in_decision(&self, _task_config: &DapTaskConfig) -> Result<bool, DapError> {
        Ok(true)
    }

    async fn get_task_config_considering_taskprov(
        &'srv self,
        version: DapVersion,
        task_id: Cow<'req, Id>,
        metadata: Option<&ReportMetadata>,
    ) -> Result<Option<DapTaskConfig>, DapError> {
        let taskprov_version = self.global_config.taskprov_version;

        // Before looking up the task configuration, first check if it needs to be configured from
        // the current request.
        if self.get_global_config().allow_taskprov
            && metadata.is_some()
            && metadata.unwrap().is_taskprov(taskprov_version, &task_id)
        {
            if let Some(taskprov_task_config) = taskprov::get_taskprov_task_config(
                taskprov_version,
                task_id.as_ref(),
                metadata.unwrap(),
            )? {
                let task_config = DapTaskConfig::try_from_taskprov(
                    version,
                    self.global_config.taskprov_version,
                    task_id.as_ref(),
                    taskprov_task_config,
                    &self.taskprov_vdaf_verify_key_init,
                    &self.collector_hpke_config,
                )?;

                let mut tasks = self.tasks.lock().expect("tasks: lock failed");
                if tasks.get(task_id.as_ref()).is_none() {
                    // Decide whether to opt-in to the task.
                    if !self.taskprov_opt_in_decision(&task_config)? {
                        return Err(DapError::Abort(DapAbort::InvalidTask));
                    }

                    tasks
                        .deref_mut()
                        .insert(task_id.into_owned(), task_config.clone());
                }

                return Ok(Some(task_config));
            }
        }

        let tasks = self.tasks.lock().expect("tasks: lock failed");
        Ok(tasks.get(task_id.as_ref()).cloned())
    }

    fn get_current_time(&self) -> Time {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    async fn is_batch_overlapping(
        &self,
        task_id: &Id,
        batch_sel: &BatchSelector,
    ) -> Result<bool, DapError> {
        let task_config = self
            .get_task_config_for(Cow::Borrowed(task_id))
            .await
            .unwrap()
            .expect("tasks: unrecognized task");
        let guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = if let Some(agg_store) = guard.get(task_id) {
            agg_store
        } else {
            return Ok(false);
        };

        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            if let Some(inner_agg_store) = agg_store.get(&bucket.to_owned_bucket()) {
                if inner_agg_store.collected {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn batch_exists(&self, task_id: &Id, batch_id: &Id) -> Result<bool, DapError> {
        let guard = self.agg_store.lock().expect("agg_store: failed to lock");
        if let Some(agg_store) = guard.get(task_id) {
            Ok(agg_store
                .get(&DapBatchBucketOwned::FixedSize {
                    batch_id: batch_id.clone(),
                })
                .is_some())
        } else {
            Ok(false)
        }
    }

    async fn put_out_shares(
        &self,
        task_id: &Id,
        part_batch_sel: &PartialBatchSelector,
        out_shares: Vec<DapOutputShare>,
    ) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(Cow::Borrowed(task_id))
            .await?
            .ok_or_else(|| DapError::fatal("task not found"))?;

        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(task_id.clone()).or_default();
        for (bucket, agg_share_delta) in task_config
            .batch_span_for_out_shares(part_batch_sel, out_shares)?
            .into_iter()
        {
            let inner_agg_store = agg_store.entry(bucket.to_owned_bucket()).or_default();
            inner_agg_store.agg_share.merge(agg_share_delta)?;
        }

        Ok(())
    }

    async fn get_agg_share(
        &self,
        task_id: &Id,
        batch_sel: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError> {
        let task_config = self
            .get_task_config_for(Cow::Borrowed(task_id))
            .await
            .unwrap()
            .expect("tasks: unrecognized task");
        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(task_id.clone()).or_default();

        // Fetch aggregate shares.
        let mut agg_share = DapAggregateShare::default();
        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            if let Some(inner_agg_store) = agg_store.get(&bucket.to_owned_bucket()) {
                if inner_agg_store.collected {
                    return Err(DapError::Abort(DapAbort::BatchOverlap));
                } else {
                    agg_share.merge(inner_agg_store.agg_share.clone())?;
                }
            }
        }

        Ok(agg_share)
    }

    async fn check_early_reject<'b>(
        &self,
        task_id: &Id,
        part_batch_sel: &'b PartialBatchSelector,
        report_meta: impl Iterator<Item = &'b ReportMetadata>,
    ) -> Result<HashMap<ReportId, TransitionFailure>, DapError> {
        let task_config = self
            .get_task_config_for(Cow::Borrowed(task_id))
            .await
            .unwrap()
            .expect("tasks: unrecognized task");
        let span = task_config.batch_span_for_meta(part_batch_sel, report_meta)?;
        let mut early_fails = HashMap::new();
        for (bucket, report_meta) in span.iter() {
            for metadata in report_meta.iter() {
                // Check whether Report has been collected or replayed.
                if let Some(transition_failure) = self
                    .check_report_early_fail(task_id, &bucket.to_owned_bucket(), metadata)
                    .await
                {
                    early_fails.insert(metadata.id.clone(), transition_failure);
                };

                // Mark report processed.
                let mut guard = self
                    .report_store
                    .lock()
                    .expect("report_store: failed to lock");
                let report_store = guard.entry(task_id.clone()).or_default();
                report_store.processed.insert(metadata.id.clone());
            }
        }

        Ok(early_fails)
    }

    async fn mark_collected(
        &self,
        task_id: &Id,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError> {
        let task_config = self.unchecked_get_task_config(task_id).await;
        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(task_id.clone()).or_default();

        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            if let Some(inner_agg_store) = agg_store.get_mut(&bucket.to_owned_bucket()) {
                inner_agg_store.collected = true;
            }
        }

        Ok(())
    }

    async fn current_batch(&self, task_id: &Id) -> std::result::Result<Id, DapError> {
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
}

#[async_trait(?Send)]
impl<'srv, 'req> DapHelper<'srv, 'req, BearerToken> for MockAggregator
where
    'srv: 'req,
{
    async fn put_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
        helper_state: &DapHelperState,
    ) -> Result<(), DapError> {
        let helper_state_info = HelperStateInfo {
            task_id: task_id.clone(),
            agg_job_id: agg_job_id.clone(),
        };

        let mut helper_state_store_mutex_guard = self
            .helper_state_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;

        let helper_state_store = helper_state_store_mutex_guard.deref_mut();

        if helper_state_store.contains_key(&helper_state_info) {
            return Err(DapError::Fatal(
                "overwriting existing helper state".to_string(),
            ));
        }

        // NOTE: This code is only correct for VDAFs with exactly one round of preparation.
        // For VDAFs with more rounds, the helper state blob will need to be updated here.
        helper_state_store.insert(helper_state_info, helper_state.clone());

        Ok(())
    }

    async fn get_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
    ) -> Result<Option<DapHelperState>, DapError> {
        let helper_state_info = HelperStateInfo {
            task_id: task_id.clone(),
            agg_job_id: agg_job_id.clone(),
        };

        let mut helper_state_store_mutex_guard = self
            .helper_state_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;

        let helper_state_store = helper_state_store_mutex_guard.deref_mut();

        // NOTE: This code is only correct for VDAFs with exactly one round of preparation.
        // For VDAFs with more rounds, the helper state blob will need to be updated here.
        if helper_state_store.contains_key(&helper_state_info) {
            let helper_state = helper_state_store.remove(&helper_state_info);

            return Ok(helper_state);
        }

        Ok(None)
    }
}

#[async_trait(?Send)]
impl<'srv, 'req> DapLeader<'srv, 'req, BearerToken> for MockAggregator
where
    'srv: 'req,
{
    type ReportSelector = MockAggregatorReportSelector;

    async fn put_report(&self, report: &Report) -> Result<(), DapError> {
        let bucket = self
            .assign_report_to_bucket(report)
            .await
            .expect("could not determine batch for report");

        // Check whether Report has been collected or replayed.
        if let Some(transition_failure) = self
            .check_report_early_fail(&report.task_id, bucket.borrow(), &report.metadata)
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
            .get_mut(&report.task_id)
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
    ) -> Result<HashMap<Id, HashMap<PartialBatchSelector, Vec<Report>>>, DapError> {
        let task_id = &report_sel.0;
        let task_config = self.unchecked_get_task_config(task_id).await;
        let mut guard = self
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        let report_store = guard.entry(task_id.clone()).or_default();

        // For the task indicated by the report selector, choose a single report to aggregate.
        match task_config.query {
            DapQueryConfig::TimeInterval { .. } => {
                // Aggregate reports in any order.
                let mut reports = Vec::new();
                for (_bucket, queue) in report_store.pending.iter_mut() {
                    if !queue.is_empty() {
                        reports.append(&mut queue.drain(..1).collect());
                        break;
                    }
                }
                return Ok(HashMap::from([(
                    task_id.clone(),
                    HashMap::from([(PartialBatchSelector::TimeInterval, reports)]),
                )]));
            }
            DapQueryConfig::FixedSize { .. } => {
                // Drain the batch that is being filled.

                let bucket = if let Some(batch_id) = self.current_batch_id(task_id, &task_config) {
                    DapBatchBucketOwned::FixedSize { batch_id }
                } else {
                    return Ok(HashMap::default());
                };

                let queue = report_store
                    .pending
                    .get_mut(&bucket)
                    .expect("report_store: unknown bucket");
                let reports = queue.drain(..1).collect();
                return Ok(HashMap::from([(
                    task_id.clone(),
                    HashMap::from([(bucket.into(), reports)]),
                )]));
            }
        }
    }

    // Called after receiving a CollectReq from Collector.
    async fn init_collect_job(&self, collect_req: &CollectReq) -> Result<Url, DapError> {
        let mut rng = thread_rng();
        let task_config = self
            .get_task_config_for(Cow::Borrowed(&collect_req.task_id))
            .await?
            .ok_or_else(|| DapError::fatal("task not found"))?;

        let mut leader_state_store_mutex_guard = self
            .leader_state_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let leader_state_store = leader_state_store_mutex_guard.deref_mut();

        // Construct a new Collect URI for this CollectReq.
        let collect_id = Id(rng.gen());
        let collect_uri = task_config
            .leader_url
            .join(&format!(
                "collect/task/{}/req/{}",
                collect_req.task_id.to_base64url(),
                collect_id.to_base64url(),
            ))
            .map_err(|e| DapError::Fatal(e.to_string()))?;

        // Store Collect ID and CollectReq into LeaderState.
        let leader_state = leader_state_store
            .entry(collect_req.task_id.clone())
            .or_default();
        leader_state.collect_ids.push_back(collect_id.clone());
        let collect_job_state = CollectJobState::Pending(collect_req.clone());
        leader_state
            .collect_jobs
            .insert(collect_id, collect_job_state);

        Ok(collect_uri)
    }

    // Called to retrieve completed CollectResp at the request of Collector.
    async fn poll_collect_job(
        &self,
        task_id: &Id,
        collect_id: &Id,
    ) -> Result<DapCollectJob, DapError> {
        let mut leader_state_store_mutex_guard = self
            .leader_state_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let leader_state_store = leader_state_store_mutex_guard.deref_mut();

        let leader_state = leader_state_store
            .get(task_id)
            .ok_or_else(|| DapError::fatal("collect job not found for task_id"))?;
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
    async fn get_pending_collect_jobs(&self) -> Result<Vec<(Id, CollectReq)>, DapError> {
        let mut leader_state_store_mutex_guard = self
            .leader_state_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let leader_state_store = leader_state_store_mutex_guard.deref_mut();

        let mut res = Vec::new();
        for (_task_id, leader_state) in leader_state_store.iter() {
            // Iterate over collect IDs and copy them and their associated requests to the response.
            for collect_id in leader_state.collect_ids.iter() {
                if let CollectJobState::Pending(collect_req) =
                    leader_state.collect_jobs.get(collect_id).unwrap()
                {
                    res.push((collect_id.clone(), collect_req.clone()));
                }
            }
        }
        Ok(res)
    }

    async fn finish_collect_job(
        &self,
        task_id: &Id,
        collect_id: &Id,
        collect_resp: &CollectResp,
    ) -> Result<(), DapError> {
        let mut leader_state_store_mutex_guard = self
            .leader_state_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let leader_state_store = leader_state_store_mutex_guard.deref_mut();

        let leader_state = leader_state_store
            .get_mut(task_id)
            .ok_or_else(|| DapError::fatal("collect job not found for task_id"))?;
        let collect_job = leader_state
            .collect_jobs
            .get_mut(collect_id)
            .ok_or_else(|| DapError::fatal("collect job not found for collect_id"))?;

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
                Err(DapError::fatal("tried to overwrite collect response"))
            }
        }
    }

    async fn send_http_post(&self, req: DapRequest<BearerToken>) -> Result<DapResponse, DapError> {
        match req
            .media_type
            .expect("tried to send request without media type")
        {
            constants::MEDIA_TYPE_AGG_INIT_REQ | constants::MEDIA_TYPE_AGG_CONT_REQ => Ok(self
                .peer
                .as_ref()
                .expect("peer not configured")
                .http_post_aggregate(&req)
                .await
                .expect("peer aborted unexpectedly")),
            constants::MEDIA_TYPE_AGG_SHARE_REQ => Ok(self
                .peer
                .as_ref()
                .expect("peer not configured")
                .http_post_aggregate_share(&req)
                .await
                .expect("peer aborted unexpectedly")),
            s => unreachable!("unhandled media type: {}", s),
        }
    }
}

/// Information associated to a certain helper state for a given task ID and aggregate job ID.
#[derive(Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub(crate) struct HelperStateInfo {
    task_id: Id,
    agg_job_id: Id,
}

/// Stores the reports received from Clients.
#[derive(Default)]
pub(crate) struct ReportStore {
    pub(crate) pending: HashMap<DapBatchBucketOwned, VecDeque<Report>>,
    pub(crate) processed: HashSet<ReportId>,
}

/// Stores the state of the collect job.
pub(crate) enum CollectJobState {
    Pending(CollectReq),
    Processed(CollectResp),
}

/// LeaderState keeps track of the following:
/// * Collect IDs in their order of arrival.
/// * The state of the collect job associated to the Collect ID.
#[derive(Default)]
pub(crate) struct LeaderState {
    collect_ids: VecDeque<Id>,
    collect_jobs: HashMap<Id, CollectJobState>,
    batch_queue: VecDeque<(Id, u64)>, // Batch ID, batch size
}

/// AggStore keeps track of the following:
/// * Aggregate share
/// * Whether this aggregate share has been collected
#[derive(Default)]
pub(crate) struct AggStore {
    pub(crate) agg_share: DapAggregateShare,
    pub(crate) collected: bool,
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
//     something_draft03
//
// that called something(version) with the appropriate version.
//
// We use the "paste" crate to get a macro that can paste tokens and also
// fiddle case.

#[macro_export]
macro_rules! test_version {
    ($fname:ident, $version:ident) => {
        paste! {
            #[test]
            fn [<$fname _ $version:lower>]() {
                $fname (DapVersion::$version);
            }
        }
    };
}

#[macro_export]
macro_rules! test_versions {
    ($($fname:ident),*) => {
        $(
            test_version! { $fname, Draft02 }
            test_version! { $fname, Draft03 }
        )*
    };
}

#[macro_export]
macro_rules! async_test_version {
    ($fname:ident, $version:ident) => {
        paste! {
            #[tokio::test]
            async fn [<$fname _ $version:lower>]() {
                $fname (DapVersion::$version) . await;
            }
        }
    };
}

#[macro_export]
macro_rules! async_test_versions {
    ($($fname:ident),*) => {
        $(
            async_test_version! { $fname, Draft02 }
            async_test_version! { $fname, Draft03 }
        )*
    };
}

/// Helper macro used by `assert_metrics_include`.
//
// TODO(cjpatton) Figure out how to bake this into `asssert_metrics_include` so that users don't
// have to import both macros.
#[cfg(test)]
#[macro_export]
macro_rules! assert_metrics_include_auxiliary_function {
    ($set:expr, $k:tt: $v:expr,) => {{
        let line = format!("{} {}", $k, $v);
        $set.insert(line);
    }};

    ($set:expr, $k:tt: $v:expr, $($ks:tt: $vs:expr),+,) => {{
        let line = format!("{} {}", $k, $v);
        $set.insert(line);
        assert_metrics_include_auxiliary_function!($set, $($ks: $vs),+,)
    }}
}

/// Gather metrics from a registry and assert that a list of metrics are present and have the
/// correct value. For example:
/// ```
/// let registry = prometheus::Registry::new();
///
/// // ... Register a metric called "report_counter" and use it.
///
/// assert_metrics_include!(t.helper_prometheus_registry, {
///      r#"report_counter{status="aggregated"}"#: 23,
/// });
/// ```
#[cfg(test)]
#[macro_export]
macro_rules! assert_metrics_include {
    ($registry:expr, {$($ks:tt: $vs:expr),+,}) => {{
        use prometheus::{Encoder, TextEncoder};
        use std::collections::HashSet;

        let mut want: HashSet<String> = HashSet::new();
        assert_metrics_include_auxiliary_function!(&mut want, $($ks: $vs),+,);

        // Encode the metrics and iterate over each line. For each line, if the line appears in the
        // list of expected output lines, then remove it.
        let mut got_buf = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&$registry.gather(), &mut got_buf).unwrap();
        let got_str = String::from_utf8(got_buf).unwrap();
        for line in got_str.split('\n') {
            want.remove(line);
        }

        // The metrics contain the expected lines if the the set is now empty.
        if !want.is_empty() {
            panic!("unexpected metrics: got:\n{}\nmust contain:\n{}\n",
                   got_str, want.into_iter().collect::<Vec<String>>().join("\n"));
        }
    }}
}
