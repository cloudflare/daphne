// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Mock backend functionality to test DAP protocol.

use crate::{
    auth::{BearerToken, BearerTokenProvider},
    hpke::{HpkeDecrypter, HpkeReceiverConfig},
    messages::{
        BatchSelector, CollectReq, CollectResp, HpkeCiphertext, HpkeConfig, Id, Interval, Nonce,
        Report, ReportMetadata, ReportShare, Time, TransitionFailure,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    DapAbort, DapAggregateShare, DapCollectJob, DapError, DapGlobalConfig, DapHelperState,
    DapOutputShare, DapQueryConfig, DapRequest, DapResponse, DapTaskConfig,
};
use async_trait::async_trait;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::SystemTime,
};
use url::Url;

pub(crate) struct MockAggregateInfo {
    pub(crate) task_id: Id,
    pub(crate) agg_rate: u64,
}

#[allow(dead_code)]
pub(crate) struct MockAggregator {
    pub(crate) now: Time,
    pub(crate) global_config: DapGlobalConfig,
    pub(crate) tasks: HashMap<Id, DapTaskConfig>,
    pub(crate) hpke_receiver_config_list: Vec<HpkeReceiverConfig>,
    pub(crate) leader_token: BearerToken,
    pub(crate) collector_token: Option<BearerToken>, // Not set by Helper
    pub(crate) report_store: Arc<Mutex<HashMap<Id, ReportStore>>>,
    pub(crate) leader_state_store: Arc<Mutex<HashMap<Id, LeaderState>>>,
    pub(crate) helper_state_store: Arc<Mutex<HashMap<HelperStateInfo, DapHelperState>>>,
    pub(crate) agg_store: Arc<Mutex<HashMap<Id, HashMap<BatchSelector, AggStore>>>>,
}

#[allow(dead_code)]
impl MockAggregator {
    /// Conducts checks on a received report to see whether:
    /// 1) the report falls into a batch that has been already collected, or
    /// 2) the report has been submitted by the client in the past.
    async fn check_report_early_fail(
        &self,
        task_id: &Id,
        metadata: &ReportMetadata,
    ) -> Option<TransitionFailure> {
        let task_config = self.tasks.get(task_id).expect("tasks: unrecognized task");
        if matches!(task_config.query, DapQueryConfig::FixedSize { .. }) {
            panic!("TODO(issue #100)");
        }

        let batch_selector = BatchSelector::TimeInterval {
            batch_interval: Interval {
                start: task_config.truncate_time(metadata.time),
                duration: task_config.time_precision,
            },
        };

        // Check AggStateStore to see whether the report is part of a batch that has already
        // been collected.
        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(task_id.clone()).or_default();
        if matches!(agg_store.get(&batch_selector), Some(inner_agg_store) if inner_agg_store.collected)
        {
            return Some(TransitionFailure::BatchCollected);
        }

        // Check whether the same report has been submitted in the past.
        let mut guard = self
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        if guard
            .entry(task_id.clone())
            .or_default()
            .processed
            .contains(&metadata.nonce)
        {
            return Some(TransitionFailure::ReportReplayed);
        }

        None
    }

    fn get_hpke_receiver_config_for(&self, hpke_config_id: u8) -> Option<&HpkeReceiverConfig> {
        self.hpke_receiver_config_list
            .iter()
            .find(|&hpke_receiver_config| hpke_config_id == hpke_receiver_config.config.id)
    }
}

#[async_trait(?Send)]
impl BearerTokenProvider for MockAggregator {
    async fn get_leader_bearer_token_for(
        &self,
        _task_id: &Id,
    ) -> Result<Option<BearerToken>, DapError> {
        Ok(Some(self.leader_token.clone()))
    }

    async fn get_collector_bearer_token_for(
        &self,
        _task_id: &Id,
    ) -> Result<Option<BearerToken>, DapError> {
        if let Some(ref collector_token) = self.collector_token {
            Ok(Some(collector_token.clone()))
        } else {
            Err(DapError::fatal(
                "MockAggregator not configured with Collector bearer token",
            ))
        }
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
        self.authorize_with_bearer_token(task_id, media_type).await
    }
}

#[async_trait(?Send)]
impl<'a> DapAggregator<'a, BearerToken> for MockAggregator {
    type WrappedDapTaskConfig = &'a DapTaskConfig;

    async fn authorized(&self, req: &DapRequest<BearerToken>) -> Result<bool, DapError> {
        self.bearer_token_authorized(req).await
    }

    fn get_global_config(&self) -> &DapGlobalConfig {
        &self.global_config
    }

    async fn get_task_config_for(
        &'a self,
        task_id: &Id,
    ) -> Result<Option<&'a DapTaskConfig>, DapError> {
        Ok(self.tasks.get(task_id))
    }

    fn get_current_time(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    async fn is_batch_overlapping(
        &self,
        task_id: &Id,
        batch_selector: &BatchSelector,
    ) -> Result<bool, DapError> {
        let guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = if let Some(agg_store) = guard.get(task_id) {
            agg_store
        } else {
            return Ok(false);
        };

        let batch_interval = batch_selector.unwrap_interval();
        for (inner_selector, inner_agg_store) in agg_store.iter() {
            let inner_interval = inner_selector.unwrap_interval();
            if batch_interval.start <= inner_interval.start
                && batch_interval.end() > inner_interval.start
                && inner_agg_store.collected
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn put_out_shares(
        &self,
        task_id: &Id,
        out_shares: Vec<DapOutputShare>,
    ) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| DapError::fatal("task not found"))?;
        if matches!(task_config.query, DapQueryConfig::FixedSize { .. }) {
            panic!("TODO(issue #100)");
        }

        let agg_shares =
            DapAggregateShare::batches_from_out_shares(out_shares, task_config.time_precision)?;

        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(task_id.clone()).or_default();
        for (window, agg_share_delta) in agg_shares.into_iter() {
            let batch_selector = BatchSelector::TimeInterval {
                batch_interval: Interval {
                    start: window,
                    duration: task_config.time_precision,
                },
            };

            let inner_agg_store = agg_store.entry(batch_selector).or_default();
            inner_agg_store.agg_share.merge(agg_share_delta)?;
        }

        Ok(())
    }

    async fn get_agg_share(
        &self,
        task_id: &Id,
        batch_selector: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError> {
        let guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.get(task_id).expect("agg_store: unrecognized task");

        // Fetch aggregate shares.
        let mut agg_share = DapAggregateShare::default();
        let batch_interval = batch_selector.unwrap_interval();
        for (inner_selector, inner_agg_store) in agg_store.iter() {
            let inner_interval = inner_selector.unwrap_interval();
            if batch_interval.start <= inner_interval.start
                && batch_interval.end() > inner_interval.start
            {
                if inner_agg_store.collected {
                    return Err(DapError::Abort(DapAbort::BatchOverlap));
                } else {
                    agg_share.merge(inner_agg_store.agg_share.clone())?;
                }
            }
        }

        Ok(agg_share)
    }

    async fn mark_collected(
        &self,
        task_id: &Id,
        batch_selector: &BatchSelector,
    ) -> Result<(), DapError> {
        let mut guard = self.agg_store.lock().expect("agg_store: failed to lock");
        let agg_store = guard.entry(task_id.clone()).or_default();

        let batch_interval = batch_selector.unwrap_interval();
        for (inner_selector, inner_agg_store) in agg_store.iter_mut() {
            let inner_interval = inner_selector.unwrap_interval();
            if batch_interval.start <= inner_interval.start
                && batch_interval.end() > inner_interval.start
            {
                inner_agg_store.collected = true;
            }
        }

        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> DapHelper<'a, BearerToken> for MockAggregator {
    async fn mark_aggregated(
        &self,
        task_id: &Id,
        report_shares: &[ReportShare],
    ) -> Result<HashMap<Nonce, TransitionFailure>, DapError> {
        let mut early_fails = HashMap::new();
        for report_share in report_shares.iter() {
            // Check whether Report has been collected or replayed.
            if let Some(transition_failure) = self
                .check_report_early_fail(task_id, &report_share.metadata)
                .await
            {
                early_fails.insert(report_share.metadata.nonce.clone(), transition_failure);
            };

            // Mark Report processed.
            let mut guard = self
                .report_store
                .lock()
                .expect("report_store: failed to lock");
            let report_store = guard.entry(task_id.clone()).or_default();
            report_store
                .processed
                .insert(report_share.metadata.nonce.clone());
        }

        Ok(early_fails)
    }

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
impl<'a> DapLeader<'a, BearerToken> for MockAggregator {
    type ReportSelector = MockAggregateInfo;

    async fn put_report(&self, report: &Report) -> Result<(), DapError> {
        let task_id = &report.task_id;
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| DapError::fatal("task not found"))?;
        if matches!(task_config.query, DapQueryConfig::FixedSize { .. }) {
            panic!("TODO(issue #100)");
        }

        // Check whether Report has been collected or replayed.
        if let Some(transition_failure) = self
            .check_report_early_fail(task_id, &report.metadata)
            .await
        {
            return Err(DapError::Transition(transition_failure));
        };

        // Store Report for future processing.
        let mut guard = self
            .report_store
            .lock()
            .expect("report_store: failed to lock");
        let report_store = guard.entry(task_id.clone()).or_default();
        report_store.pending.push_back(report.clone());
        Ok(())
    }

    async fn get_reports(
        &self,
        selector: &MockAggregateInfo,
    ) -> Result<HashMap<Id, Vec<Report>>, DapError> {
        // Lock report_store.
        let agg_rate = selector
            .agg_rate
            .try_into()
            .expect("agg_rate is larger than usize");
        let mut reports = Vec::with_capacity(agg_rate);
        let mut report_store_mutex_guard = self
            .report_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let report_store = report_store_mutex_guard.deref_mut();

        // Fetch reports.
        for (inner_task_id, store) in report_store.iter_mut() {
            if &selector.task_id == inner_task_id {
                let num_reports_remaining = agg_rate - reports.len();
                let num_reports_drained = std::cmp::min(num_reports_remaining, store.pending.len());
                let mut reports_drained: Vec<Report> =
                    store.pending.drain(..num_reports_drained).collect();
                if reports_drained.len() + reports.len() > agg_rate {
                    return Err(DapError::fatal(
                        "number of reports received from report_store exceeds the number requested",
                    ));
                }

                reports.append(&mut reports_drained);

                if reports.len() == agg_rate {
                    break;
                }
            }
        }

        Ok(HashMap::from([(selector.task_id.clone(), reports)]))
    }

    // Called after receiving a CollectReq from Collector.
    async fn init_collect_job(&self, collect_req: &CollectReq) -> Result<Url, DapError> {
        let mut rng = thread_rng();
        let task_config = self
            .get_task_config_for(&collect_req.task_id)
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
            .or_insert_with(LeaderState::new);
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

    // Called after finishing aggregation job to put resuts into LeaderState.
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

    async fn send_http_post(&self, _req: DapRequest<BearerToken>) -> Result<DapResponse, DapError> {
        unreachable!("not implemented");
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
    pub(crate) pending: VecDeque<Report>,
    pub(crate) processed: HashSet<Nonce>,
}

/// Stores the state of the collect job.
pub(crate) enum CollectJobState {
    Pending(CollectReq),
    Processed(CollectResp),
}

/// LeaderState keeps track of the following:
/// * Collect IDs in their order of arrival.
/// * The state of the collect job associated to the Collect ID.
pub(crate) struct LeaderState {
    collect_ids: VecDeque<Id>,
    collect_jobs: HashMap<Id, CollectJobState>,
}

impl LeaderState {
    pub(crate) fn new() -> LeaderState {
        Self {
            collect_ids: VecDeque::default(),
            collect_jobs: HashMap::default(),
        }
    }
}

/// AggStore keeps track of the following:
/// * Aggregate share
/// * Whether this aggregate share has been collected
#[derive(Default)]
pub(crate) struct AggStore {
    pub(crate) agg_share: DapAggregateShare,
    pub(crate) collected: bool,
}
