// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Mock backend functionality to test DAP protocol.

use crate::{
    auth::{BearerToken, BearerTokenProvider},
    hpke::{HpkeDecrypter, HpkeReceiverConfig},
    messages::{
        BatchSelector, CollectReq, CollectResp, HpkeCiphertext, HpkeConfig, Id, Nonce, Report,
        ReportShare, Time, TransitionFailure,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    DapAbort, DapAggregateShare, DapCollectJob, DapError, DapGlobalConfig, DapHelperState,
    DapOutputShare, DapRequest, DapResponse, DapTaskConfig,
};
use async_trait::async_trait;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time::SystemTime,
};
use url::Url;

pub const GLOBAL_CONFIG: &str = r#"{
    "max_batch_duration": 360000,
    "min_batch_interval_start": 259200,
    "max_batch_interval_end": 259200,
    "supported_hpke_kems": ["X25519HkdfSha256"]
}"#;

// Secret key of "collector_hpke_config":
// 60890f1e438bf1f0e9ad2bd839acf1341137eee623bf7906972bf1cc80bb5d7b
//
// NOTE(nakatsuka-y) The leader_url and helper_url must end with a "/".
// When adding paths, they must not start with a "/".
pub const TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "version": "v01",
        "leader_url": "https://leader.biz/v01/",
        "helper_url": "http://helper.com:8788/v01/",
        "collector_hpke_config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key":"ec6427a49c8e9245307cc757dbdcf5d287c7a74075141af9fa566c293a52ee7c"
        },
        "min_batch_duration": 3600,
        "min_batch_size": 1,
        "vdaf": {
            "prio3": "count"
        },
        "vdaf_verify_key": "1fd8d30dc0e0b7ac81f0050fcab0782d"
    }
}"#;

pub const HPKE_RECEIVER_CONFIG_LIST: &str = r#"[
    {
        "config": {
            "id": 23,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key": "5dc71373c6aa7b0af67944a370ab96d8b8216832579c19159ca35d10f25a2765"
        },
        "secret_key": "888e94344585f44530d03e250268be6c6a5caca5314513dcec488cc431486c69"
    },
    {
        "config": {
            "id": 14,
            "kem_id": "X25519HkdfSha256",
            "kdf_id": "HkdfSha256",
            "aead_id": "Aes128Gcm",
            "public_key": "b07126295bcfcdeaec61b310fd7ffbf8c6ca7f6c17e3e0a80a5405a242e5084b"
        },
        "secret_key": "b809a4df399548f56c3a15ebaa4925dd292637f0b7e2f6bc3ba60376b69aa05e"
    }
]"#;

pub const LEADER_BEARER_TOKEN: &str = "ivA1e7LpnySDNn1AulaZggFLQ1n7jZ8GWOUO7GY4hgs=";
pub const COLLECTOR_BEARER_TOKEN: &str = "syfRfvcvNFF5MJk4Y-B7xjRIqD_iNzhaaEB9mYqO9hk=";

pub(crate) struct MockAggregateInfo {
    pub(crate) task_id: Id,
    pub(crate) agg_rate: u64,
}

#[allow(dead_code)]
pub(crate) struct MockAggregator {
    pub(crate) now: u64,
    pub(crate) global_config: DapGlobalConfig,
    pub(crate) tasks: HashMap<Id, DapTaskConfig>,
    hpke_receiver_config_list: Vec<HpkeReceiverConfig>,
    pub(crate) report_store: Arc<Mutex<HashMap<Id, ReportStore>>>,
    leader_state_store: Arc<Mutex<HashMap<Id, LeaderState>>>,
    helper_state_store: Arc<Mutex<HashMap<HelperStateInfo, DapHelperState>>>,
    pub(crate) agg_store: Arc<Mutex<HashMap<BucketInfo, AggStoreState>>>,
}

#[allow(dead_code)]
impl MockAggregator {
    pub(crate) fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let global_config: DapGlobalConfig =
            serde_json::from_str(GLOBAL_CONFIG).expect("failed to parse global config");

        let tasks: HashMap<Id, DapTaskConfig> =
            serde_json::from_str(TASK_LIST).expect("failed to parse task list");

        let hpke_receiver_config_list: Vec<HpkeReceiverConfig> =
            serde_json::from_str(HPKE_RECEIVER_CONFIG_LIST)
                .expect("failed to parse hpke_receiver_config_list");

        let report_store = Arc::new(Mutex::new(HashMap::new()));
        let leader_state_store = Arc::new(Mutex::new(HashMap::new()));
        let helper_state_store = Arc::new(Mutex::new(HashMap::new()));
        let agg_store = Arc::new(Mutex::new(HashMap::new()));

        Self {
            now,
            global_config,
            tasks,
            hpke_receiver_config_list,
            report_store,
            leader_state_store,
            helper_state_store,
            agg_store,
        }
    }

    /// Conducts checks on a received report to see whether:
    /// 1) the report falls into a batch that has been already collected, or
    /// 2) the report has been submitted by the client in the past.
    fn check_report(
        &self,
        bucket_info: &BucketInfo,
        nonce: &Nonce,
        report_store: &ReportStore,
        agg_store: &HashMap<BucketInfo, AggStoreState>,
    ) -> Result<(), TransitionFailure> {
        // Check AggStateStore to see whether the report is part of a batch that has already
        // been collected.
        if matches!(agg_store.get(bucket_info), Some(agg_store_state) if agg_store_state.collected)
        {
            return Err(TransitionFailure::BatchCollected);
        }

        // Check whether the same report has been submitted in the past.
        if report_store.processed.contains(nonce) {
            return Err(TransitionFailure::ReportReplayed);
        }

        Ok(())
    }

    fn get_hpke_receiver_config_for(&self, hpke_config_id: u8) -> Option<&HpkeReceiverConfig> {
        for hpke_receiver_config in self.hpke_receiver_config_list.iter() {
            if hpke_config_id == hpke_receiver_config.config.id {
                return Some(hpke_receiver_config);
            }
        }
        None
    }

    /// Task to use for nominal tests.
    pub(crate) fn nominal_task_id(&self) -> &Id {
        // Just use the first key in the hash map.
        self.tasks.keys().next().as_ref().unwrap()
    }
}

#[async_trait(?Send)]
impl BearerTokenProvider for MockAggregator {
    async fn get_leader_bearer_token_for(
        &self,
        _task_id: &Id,
    ) -> Result<Option<BearerToken>, DapError> {
        Ok(Some(BearerToken::from(LEADER_BEARER_TOKEN.to_string())))
    }

    async fn get_collector_bearer_token_for(
        &self,
        _task_id: &Id,
    ) -> Result<Option<BearerToken>, DapError> {
        Ok(Some(BearerToken::from(COLLECTOR_BEARER_TOKEN.to_string())))
    }
}

#[async_trait(?Send)]
impl<'a> HpkeDecrypter<'a> for MockAggregator {
    type WrappedHpkeConfig = &'a HpkeConfig;

    async fn get_hpke_config_for(
        &'a self,
        _task_id: &Id,
    ) -> Result<Option<&'a HpkeConfig>, DapError> {
        if self.hpke_receiver_config_list.is_empty() {
            return Ok(None);
        }

        // Always advertise the first HPKE config in the list.
        Ok(Some(&self.hpke_receiver_config_list[0].config))
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
        let mut agg_store_mutex_guard = self
            .agg_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let agg_store = agg_store_mutex_guard.deref_mut();
        let batch_interval = batch_selector.unwrap_interval();
        for (inner_bucket_info, agg_store_state) in agg_store.iter() {
            if task_id == &inner_bucket_info.task_id
                && batch_interval.start <= inner_bucket_info.window
                && batch_interval.end() > inner_bucket_info.window
                && agg_store_state.collected
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

        let agg_shares =
            DapAggregateShare::batches_from_out_shares(out_shares, task_config.min_batch_duration)?;

        let mut agg_store_mutex_guard = self
            .agg_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let agg_store = agg_store_mutex_guard.deref_mut();
        let mut bucket_info = BucketInfo {
            task_id: task_id.clone(),
            window: 0,
        };
        for (window, agg_share_delta) in agg_shares.into_iter() {
            bucket_info.window = window;

            if let Some(agg_store_state) = agg_store.get_mut(&bucket_info) {
                agg_store_state.agg_share.merge(agg_share_delta)?;
            } else {
                agg_store.insert(
                    bucket_info.clone(),
                    AggStoreState {
                        agg_share: agg_share_delta,
                        collected: false,
                    },
                );
            }
        }

        Ok(())
    }

    async fn get_agg_share(
        &self,
        task_id: &Id,
        batch_selector: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError> {
        // Lock agg_store.
        let mut agg_store_mutex_guard = self
            .agg_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let agg_store = agg_store_mutex_guard.deref_mut();

        // Fetch aggregate shares.
        let mut agg_share = DapAggregateShare::default();
        let batch_interval = batch_selector.unwrap_interval();
        for (inner_bucket_info, agg_store_state) in agg_store.iter() {
            if task_id == &inner_bucket_info.task_id
                && batch_interval.start <= inner_bucket_info.window
                && batch_interval.end() > inner_bucket_info.window
            {
                if agg_store_state.collected {
                    return Err(DapError::Abort(DapAbort::BatchOverlap));
                } else {
                    agg_share.merge(agg_store_state.agg_share.clone())?;
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
        // Mark aggregate shares as collected.
        let mut agg_store_mutex_guard = self
            .agg_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let agg_store = agg_store_mutex_guard.deref_mut();
        let batch_interval = batch_selector.unwrap_interval();
        for (inner_bucket_info, agg_store_state) in agg_store.iter_mut() {
            if task_id == &inner_bucket_info.task_id
                && batch_interval.start <= inner_bucket_info.window
                && batch_interval.end() > inner_bucket_info.window
            {
                agg_store_state.collected = true;
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
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or_else(|| DapError::fatal("task not found"))?;
        let mut early_fails: HashMap<Nonce, TransitionFailure> = HashMap::new();

        // Lock AggStateStore.
        let agg_store_mutex_guard = self
            .agg_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let agg_store = agg_store_mutex_guard.deref();

        // Lock ReportStore.
        let mut report_store_mutex_guard = self
            .report_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let report_store = report_store_mutex_guard.deref_mut();
        let report_store = report_store
            .entry(task_id.clone())
            .or_insert_with(ReportStore::new);

        for report_share in report_shares.iter() {
            let bucket_info = BucketInfo::new(task_config, task_id, report_share.metadata.time);

            // Check whether Report has been collected or replayed.
            if let Err(transition_failure) = self.check_report(
                &bucket_info,
                &report_share.metadata.nonce,
                report_store,
                agg_store,
            ) {
                early_fails.insert(report_share.metadata.nonce.clone(), transition_failure);
            };

            // Mark Report processed.
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
        let bucket_info = BucketInfo::new(task_config, task_id, report.metadata.time);

        // Lock AggStateStore.
        let agg_store_mutex_guard = self
            .agg_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let agg_store = agg_store_mutex_guard.deref();

        // Lock ReportStore.
        let mut report_store_mutex_guard = self
            .report_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let report_store = report_store_mutex_guard.deref_mut();
        let report_store = report_store
            .entry(task_id.clone())
            .or_insert_with(ReportStore::new);

        // Check whether Report has been collected or replayed.
        if let Err(transition_failure) = self.check_report(
            &bucket_info,
            &report.metadata.nonce,
            report_store,
            agg_store,
        ) {
            return Err(DapError::Transition(transition_failure));
        };

        // Store Report for future processing.
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

/// Information associated to a certain report for a given task and nonce to decide which bucket it would be put into.
#[derive(Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub(crate) struct BucketInfo {
    task_id: Id,
    window: Time,
}

impl BucketInfo {
    pub(crate) fn new(task_config: &DapTaskConfig, task_id: &Id, time: Time) -> Self {
        let window = time - (time % task_config.min_batch_duration);

        Self {
            task_id: task_id.clone(),
            window,
        }
    }
}

/// Stores the reports received from Clients.
pub(crate) struct ReportStore {
    pub(crate) pending: VecDeque<Report>,
    pub(crate) processed: HashSet<Nonce>,
}

impl ReportStore {
    pub(crate) fn new() -> Self {
        let pending: VecDeque<Report> = VecDeque::new();
        let processed: HashSet<Nonce> = HashSet::new();

        Self { pending, processed }
    }
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

/// AggStoreState keeps track of the following:
/// * Aggregate share
/// * Whether this aggregate share has been collected
pub(crate) struct AggStoreState {
    pub(crate) agg_share: DapAggregateShare,
    pub(crate) collected: bool,
}
