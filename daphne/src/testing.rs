// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Mock backend functionality to test DAP protocol.

use crate::{
    auth::{BearerToken, BearerTokenProvider},
    hpke::{HpkeDecrypter, HpkeReceiverConfig},
    messages::{
        CollectReq, CollectResp, HpkeCiphertext, HpkeConfig, Id, Interval, Nonce, Report,
        ReportShare, TransitionFailure,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    DapAggregateShare, DapCollectJob, DapError, DapHelperState, DapOutputShare, DapRequest,
    DapResponse, DapTaskConfig,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    sync::{Arc, Mutex},
};
use url::Url;

pub const TASK_LIST: &str = r#"{
    "f285be3caf948fcfc36b7d32181c14db95c55f04f55a2db2ee439c5879264e1f": {
        "leader_url": "https://leader.biz/leadver/v1/",
        "helper_url": "http://helper.com:8788",
        "collector_hpke_config": "f40020000100010020a761d90c8c76d3d76349a3794a439a1572ab1fb8f13531d69744c92ea7757d7f",
        "min_batch_duration": 3600,
        "min_batch_size": 100,
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

pub(crate) struct MockAggregator {
    tasks: HashMap<Id, DapTaskConfig>,
    hpke_receiver_config_list: Vec<HpkeReceiverConfig>,
    pub(crate) report_store: Arc<Mutex<HashMap<BucketInfo, ReportStore>>>,
    helper_state_store: Arc<Mutex<HashMap<HelperStateInfo, DapHelperState>>>,
}

#[allow(dead_code)]
impl MockAggregator {
    pub(crate) fn new() -> Self {
        let tasks: HashMap<Id, DapTaskConfig> =
            serde_json::from_str(TASK_LIST).expect("failed to parse task list");

        let hpke_receiver_config_list: Vec<HpkeReceiverConfig> =
            serde_json::from_str(HPKE_RECEIVER_CONFIG_LIST)
                .expect("failed to parse hpke_receiver_config_list");

        let report_store = Arc::new(Mutex::new(HashMap::new()));
        let helper_state_store = Arc::new(Mutex::new(HashMap::new()));

        Self {
            tasks,
            hpke_receiver_config_list,
            report_store,
            helper_state_store,
        }
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

impl HpkeDecrypter for MockAggregator {
    fn get_hpke_config_for(&self, _task_id: &Id) -> Option<&HpkeConfig> {
        if self.hpke_receiver_config_list.is_empty() {
            return None;
        }

        // Always advertise the first HPKE config in the list.
        Some(&self.hpke_receiver_config_list[0].config)
    }

    fn can_hpke_decrypt(&self, _task_id: &Id, config_id: u8) -> bool {
        self.get_hpke_receiver_config_for(config_id).is_some()
    }

    fn hpke_decrypt(
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
impl DapAggregator<BearerToken> for MockAggregator {
    async fn authorized(&self, req: &DapRequest<BearerToken>) -> Result<bool, DapError> {
        self.bearer_token_authorized(req).await
    }

    fn get_task_config_for(&self, task_id: &Id) -> Option<&DapTaskConfig> {
        self.tasks.get(task_id)
    }

    async fn put_out_shares(
        &self,
        _task_id: &Id,
        _out_shares: Vec<DapOutputShare>,
    ) -> Result<(), DapError> {
        unreachable!("not implemented");
    }

    async fn get_agg_share(
        &self,
        _task_id: &Id,
        _batch_interval: &Interval,
    ) -> Result<DapAggregateShare, DapError> {
        unreachable!("not implemented");
    }

    async fn mark_collected(
        &self,
        _task_id: &Id,
        _batch_interval: &Interval,
    ) -> Result<(), DapError> {
        unreachable!("not implemented");
    }
}

#[async_trait(?Send)]
impl DapHelper<BearerToken> for MockAggregator {
    async fn mark_aggregated(
        &self,
        task_id: &Id,
        report_shares: &[ReportShare],
    ) -> Result<HashMap<Nonce, TransitionFailure>, DapError> {
        let mut early_fails: HashMap<Nonce, TransitionFailure> = HashMap::new();

        let mut report_store_mutex_guard = self
            .report_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;

        let report_store = report_store_mutex_guard.deref_mut();

        for report_share in report_shares.iter() {
            let bucket_info = BucketInfo::new(
                self.tasks
                    .get(task_id)
                    .ok_or_else(|| DapError::fatal("no task found"))?,
                task_id,
                &report_share.nonce,
            );

            if !report_store.contains_key(&bucket_info) {
                report_store.insert(bucket_info.clone(), ReportStore::new());
            }

            match report_store
                .get_mut(&bucket_info)
                .unwrap()
                .process_put_processed(report_share.nonce.clone())
            {
                Ok(()) => (),
                Err(failure_reason) => {
                    early_fails.insert(report_share.nonce.clone(), failure_reason);
                }
            }
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
impl DapLeader<BearerToken> for MockAggregator {
    type ReportSelector = ();

    async fn put_report(&self, report: &Report) -> Result<(), DapError> {
        let task_id = &report.task_id;
        let bucket_info = BucketInfo::new(
            self.tasks
                .get(task_id)
                .ok_or_else(|| DapError::fatal("no task found"))?,
            task_id,
            &report.nonce,
        );

        let mut report_store_mutex_guard = self
            .report_store
            .lock()
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let report_store = report_store_mutex_guard.deref_mut();

        if !report_store.contains_key(&bucket_info) {
            report_store.insert(bucket_info.clone(), ReportStore::new());
        }

        match report_store
            .get_mut(&bucket_info)
            .unwrap()
            .process_put_pending(report.clone())
        {
            Ok(()) => Ok(()),
            Err(failure_reason) => Err(DapError::Transition(failure_reason)),
        }
    }

    async fn get_reports(
        &self,
        _task_id: &Id,
        _selector: &Self::ReportSelector,
    ) -> Result<Vec<Report>, DapError> {
        unreachable!("not implemented");
    }

    async fn init_collect_job(&self, _collect_req: &CollectReq) -> Result<Url, DapError> {
        unreachable!("not implemented");
    }

    async fn poll_collect_job(
        &self,
        _task_id: &Id,
        _collect_id: &Id,
    ) -> Result<DapCollectJob, DapError> {
        unreachable!("not implemented");
    }

    async fn get_pending_collect_jobs(
        &self,
        _task_id: &Id,
    ) -> Result<Vec<(Id, CollectReq)>, DapError> {
        unreachable!("not implemented");
    }

    async fn finish_collect_job(
        &self,
        _task_id: &Id,
        _collect_id: &Id,
        _collect_resp: &CollectResp,
    ) -> Result<(), DapError> {
        unreachable!("not implemented");
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
    window: u64,
}

impl BucketInfo {
    pub(crate) fn new(task_config: &DapTaskConfig, task_id: &Id, nonce: &Nonce) -> Self {
        let window = nonce.time - (nonce.time % task_config.min_batch_duration);

        Self {
            task_id: task_id.clone(),
            window,
        }
    }
}

// TODO(nakatsuka-y) remove dead_code once all functions are used
#[allow(dead_code)]
pub(crate) struct ReportStore {
    pending: Vec<Report>,
    processed: HashSet<Nonce>,
    collected: bool,
}

// TODO(nakatsuka-y) remove dead_code once all functions are used
#[allow(dead_code)]
impl ReportStore {
    pub(crate) fn new() -> Self {
        let pending: Vec<Report> = Vec::new();
        let processed: HashSet<Nonce> = HashSet::new();
        let collected = false;

        Self {
            pending,
            processed,
            collected,
        }
    }

    fn checked_process(&mut self, nonce: &Nonce) -> Result<(), TransitionFailure> {
        let observed = self.processed.contains(nonce);
        if observed && !self.collected {
            return Err(TransitionFailure::ReportReplayed);
        } else if !observed && self.collected {
            return Err(TransitionFailure::BatchCollected);
        }
        self.processed.insert(nonce.clone());
        Ok(())
    }

    pub(crate) fn process_delete_all(&mut self) {
        self.pending.clear();
        self.processed.clear();
        self.collected = false;
    }

    pub(crate) fn process_get_pending(&mut self, reports_requested: u64) -> Vec<Report> {
        let reports_drained =
            std::cmp::min(reports_requested.try_into().unwrap(), self.pending.len());
        let reports: Vec<Report> = self.pending.drain(..reports_drained).collect();
        reports
    }

    pub(crate) fn process_put_pending(&mut self, report: Report) -> Result<(), TransitionFailure> {
        self.checked_process(&report.nonce)?;
        self.pending.push(report);
        Ok(())
    }

    pub(crate) fn process_put_processed(&mut self, nonce: Nonce) -> Result<(), TransitionFailure> {
        self.checked_process(&nonce)?;
        Ok(())
    }

    pub(crate) fn process_mark_collected(&mut self) {
        self.collected = true;
    }
}
