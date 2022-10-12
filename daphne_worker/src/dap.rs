// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of DAP Aggregator roles for Daphne-Worker.
//!
//! Daphne-Worker uses bearer tokens for DAP request authorization as specified in
//! draft-ietf-ppm-dap-02.

use crate::{
    config::{
        DaphneWorkerConfig, DaphneWorkerDeployment, GuardedBearerToken, GuardedHpkeReceiverConfig,
        KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG,
    },
    dap_err,
    durable::{
        aggregate_store::{
            DURABLE_AGGREGATE_STORE_CHECK_COLLECTED, DURABLE_AGGREGATE_STORE_GET,
            DURABLE_AGGREGATE_STORE_MARK_COLLECTED, DURABLE_AGGREGATE_STORE_MERGE,
        },
        durable_name_agg_store, durable_name_queue, durable_name_task,
        helper_state_store::{
            durable_helper_state_name, DURABLE_HELPER_STATE_GET, DURABLE_HELPER_STATE_PUT,
        },
        leader_agg_job_queue::DURABLE_LEADER_AGG_JOB_QUEUE_GET,
        leader_batch_queue::{
            BatchCount, DURABLE_LEADER_BATCH_QUEUE_ASSIGN, DURABLE_LEADER_BATCH_QUEUE_REMOVE,
        },
        leader_col_job_queue::{
            DURABLE_LEADER_COL_JOB_QUEUE_FINISH, DURABLE_LEADER_COL_JOB_QUEUE_GET,
            DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT, DURABLE_LEADER_COL_JOB_QUEUE_PUT,
        },
        reports_pending::{
            ReportsPendingResult, DURABLE_REPORTS_PENDING_GET, DURABLE_REPORTS_PENDING_PUT,
        },
        reports_processed::DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED,
        BINDING_DAP_AGGREGATE_STORE, BINDING_DAP_HELPER_STATE_STORE,
        BINDING_DAP_LEADER_AGG_JOB_QUEUE, BINDING_DAP_LEADER_BATCH_QUEUE,
        BINDING_DAP_LEADER_COL_JOB_QUEUE, BINDING_DAP_REPORTS_PENDING,
        BINDING_DAP_REPORTS_PROCESSED,
    },
    now, DaphneWorkerReportSelector,
};
use async_trait::async_trait;
use daphne::{
    auth::{BearerToken, BearerTokenProvider},
    constants,
    hpke::HpkeDecrypter,
    messages::{
        BatchSelector, CollectReq, CollectResp, HpkeCiphertext, Id, PartialBatchSelector, Report,
        ReportId, ReportMetadata, TransitionFailure,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    DapAggregateShare, DapBatchBucket, DapCollectJob, DapError, DapGlobalConfig, DapHelperState,
    DapOutputShare, DapQueryConfig, DapRequest, DapResponse, DapTaskConfig,
};
use futures::future::try_join_all;
use prio::codec::{Decode, Encode};
use std::collections::{HashMap, HashSet};
use worker::*;

const INT_ERR_PEER_ABORT: &str = "request aborted by peer";
const INT_ERR_PEER_RESP_MISSING_MEDIA_TYPE: &str = "peer response is missing media type";

pub(crate) fn dap_response_to_worker(resp: DapResponse) -> Result<Response> {
    let mut headers = Headers::new();
    if let Some(media_type) = resp.media_type {
        headers.set("Content-Type", media_type)?;
    }
    let worker_resp = Response::from_bytes(resp.payload)?.with_headers(headers);
    Ok(worker_resp)
}

#[async_trait(?Send)]
impl<'a, D> HpkeDecrypter<'a> for DaphneWorkerConfig<D> {
    type WrappedHpkeConfig = GuardedHpkeReceiverConfig<'a>;

    async fn get_hpke_config_for(
        &'a self,
        _task_id: Option<&Id>,
    ) -> std::result::Result<GuardedHpkeReceiverConfig<'a>, DapError> {
        let kv_store = self.kv().map_err(dap_err)?;
        let keys = kv_store
            .list()
            .limit(1)
            .prefix(KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG.to_string())
            .execute()
            .await
            .map_err(|e| DapError::Fatal(format!("kv_store: {}", e)))?;

        let hpke_config_id = if keys.keys.is_empty() {
            // Generate a new HPKE receiver config and store it in KV.
            //
            // For now, expect that only one KEM algorithm is supported and that only one config
            // will be used at anyone time.
            if self.global_config.supported_hpke_kems.len() != 1 {
                return Err(DapError::Fatal(
                    "The number of supported HPKE KEMs must be 1".to_string(),
                ));
            }

            let mut hpke_config_id = None;
            for hpke_receiver_config in self
                .global_config
                .gen_hpke_receiver_config_list(rand::random())
                .into_iter()
            {
                if hpke_config_id.is_none() {
                    hpke_config_id = Some(hpke_receiver_config.config.id);
                }
                let new_kv_config_key = format!(
                    "{}/{}",
                    KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG, hpke_receiver_config.config.id,
                );

                kv_store
                    .put(&new_kv_config_key, hpke_receiver_config)
                    .map_err(|e| DapError::Fatal(format!("kv_store: {}", e)))?
                    .execute()
                    .await
                    .map_err(|e| DapError::Fatal(format!("kv_store: {}", e)))?;
            }

            hpke_config_id.unwrap()
        } else {
            // Return the first HPKE receiver config in the list.
            parse_hpke_config_id_from_kv_key_name(keys.keys[0].name.as_str())?
        };

        // Fetch the indicated HPKE config from KV.
        //
        // TODO(cjpatton) Figure out how likely this is to fail if we had to generate a new key
        // pair and write it to KV during this call.
        Ok(self
            .get_hpke_receiver_config(hpke_config_id)
            .await
            .map_err(dap_err)?
            .ok_or_else(|| DapError::fatal("empty HPKE receiver config list"))?)
    }

    async fn can_hpke_decrypt(
        &self,
        _task_id: &Id,
        config_id: u8,
    ) -> std::result::Result<bool, DapError> {
        Ok(self
            .get_hpke_receiver_config(config_id)
            .await
            .map_err(dap_err)?
            .is_some())
    }

    async fn hpke_decrypt(
        &self,
        _task_id: &Id,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> std::result::Result<Vec<u8>, DapError> {
        if let Some(hpke_receiver_config) = self
            .get_hpke_receiver_config(ciphertext.config_id)
            .await
            .map_err(dap_err)?
        {
            Ok(hpke_receiver_config.value().decrypt(
                info,
                aad,
                &ciphertext.enc,
                &ciphertext.payload,
            )?)
        } else {
            Err(DapError::Transition(TransitionFailure::HpkeUnknownConfigId))
        }
    }
}

fn parse_hpke_config_id_from_kv_key_name(name: &str) -> std::result::Result<u8, DapError> {
    let mut iter = name.split('/');
    if let Some(prefix) = iter.next() {
        if prefix == KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG {
            if let Some(config_id_str) = iter.next() {
                if iter.next().is_none() {
                    if let Ok(config_id) = config_id_str.parse::<u8>() {
                        return Ok(config_id);
                    }
                }
            }
        }
    }

    Err(DapError::Fatal(format!(
        "malformed kv_store HPKE receiver config key: '{}'",
        name
    )))
}

#[async_trait(?Send)]
impl<'a, D> BearerTokenProvider<'a> for DaphneWorkerConfig<D> {
    type WrappedBearerToken = GuardedBearerToken<'a>;

    async fn get_leader_bearer_token_for(
        &'a self,
        task_id: &'a Id,
    ) -> std::result::Result<Option<GuardedBearerToken>, DapError> {
        self.get_leader_bearer_token(task_id).await.map_err(dap_err)
    }

    async fn get_collector_bearer_token_for(
        &'a self,
        task_id: &'a Id,
    ) -> std::result::Result<Option<GuardedBearerToken>, DapError> {
        self.get_collector_bearer_token(task_id)
            .await
            .map_err(dap_err)
    }
}

#[async_trait(?Send)]
impl<D> DapAuthorizedSender<BearerToken> for DaphneWorkerConfig<D> {
    async fn authorize(
        &self,
        task_id: &Id,
        media_type: &'static str,
        _payload: &[u8],
    ) -> std::result::Result<BearerToken, DapError> {
        Ok(self
            .authorize_with_bearer_token(task_id, media_type)
            .await?
            .value()
            .clone())
    }
}

#[async_trait(?Send)]
impl<'a, D> DapAggregator<'a, BearerToken> for DaphneWorkerConfig<D> {
    type WrappedDapTaskConfig = &'a DapTaskConfig;

    async fn authorized(
        &self,
        req: &DapRequest<BearerToken>,
    ) -> std::result::Result<bool, DapError> {
        self.bearer_token_authorized(req).await
    }

    fn get_global_config(&self) -> &DapGlobalConfig {
        &self.global_config
    }

    async fn get_task_config_for(
        &'a self,
        task_id: &Id,
    ) -> std::result::Result<Option<&'a DapTaskConfig>, DapError> {
        Ok(self.tasks.get(task_id))
    }

    fn get_current_time(&self) -> u64 {
        now()
    }

    async fn is_batch_overlapping(
        &self,
        task_id: &Id,
        batch_sel: &BatchSelector,
    ) -> std::result::Result<bool, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        // Check whether the request overlaps with previous requests. This is done by
        // checking the AggregateStore and seeing whether it requests for aggregate
        // shares that have already been marked collected.
        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            let durable_name =
                durable_name_agg_store(&task_config.version, &task_id.to_hex(), &bucket);
            requests.push(durable.get(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_CHECK_COLLECTED,
                durable_name,
            ));
        }

        let responses: Vec<bool> = try_join_all(requests).await.map_err(dap_err)?;

        for collected in responses {
            if collected {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn batch_exists(
        &self,
        task_id: &Id,
        batch_id: &Id,
    ) -> std::result::Result<bool, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        let agg_share: DapAggregateShare = self
            .durable()
            .get(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_GET,
                durable_name_agg_store(
                    &task_config.version,
                    &task_id.to_hex(),
                    &DapBatchBucket::FixedSize { batch_id },
                ),
            )
            .await
            .map_err(dap_err)?;

        Ok(!agg_share.empty())
    }

    async fn put_out_shares(
        &self,
        task_id: &Id,
        part_batch_sel: &PartialBatchSelector,
        out_shares: Vec<DapOutputShare>,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for (bucket, agg_share) in
            task_config.batch_span_for_out_shares(part_batch_sel, out_shares)?
        {
            let durable_name =
                durable_name_agg_store(&task_config.version, &task_id.to_hex(), &bucket);
            requests.push(durable.post::<_, ()>(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_MERGE,
                durable_name,
                agg_share,
            ));
        }
        try_join_all(requests).await.map_err(dap_err)?;
        Ok(())
    }

    async fn get_agg_share(
        &self,
        task_id: &Id,
        batch_sel: &BatchSelector,
    ) -> std::result::Result<DapAggregateShare, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            let durable_name =
                durable_name_agg_store(&task_config.version, &task_id.to_hex(), &bucket);
            requests.push(durable.get(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_GET,
                durable_name,
            ));
        }
        let responses: Vec<DapAggregateShare> = try_join_all(requests).await.map_err(dap_err)?;
        let mut agg_share = DapAggregateShare::default();
        for agg_share_delta in responses {
            agg_share.merge(agg_share_delta)?;
        }

        Ok(agg_share)
    }

    async fn check_early_reject<'b>(
        &self,
        task_id: &Id,
        part_batch_sel: &'b PartialBatchSelector,
        report_meta: impl Iterator<Item = &'b ReportMetadata>,
    ) -> std::result::Result<HashMap<ReportId, TransitionFailure>, DapError> {
        let durable = self.durable();
        let task_config = self.try_get_task_config_for(task_id)?;
        let task_id_hex = task_id.to_hex();
        let span = task_config.batch_span_for_meta(part_batch_sel, report_meta)?;

        // Coalesce reports pertaining to the same ReportsProcessed or AggregateStore instance.
        let mut reports_processed_request_data: HashMap<String, Vec<String>> = HashMap::new();
        let mut agg_store_request_name = Vec::new();
        let mut agg_store_request_bucket = Vec::new();
        for (bucket, report_meta) in span.iter() {
            agg_store_request_name.push(durable_name_agg_store(
                &task_config.version,
                &task_id_hex,
                bucket,
            ));
            agg_store_request_bucket.push(bucket);
            for metadata in report_meta {
                let durable_name =
                    self.durable_name_report_store(task_config, &task_id_hex, metadata);
                let report_id_hex = hex::encode(metadata.id.get_encoded());
                let report_id_hex_set = reports_processed_request_data
                    .entry(durable_name)
                    .or_default();
                report_id_hex_set.push(report_id_hex);
            }
        }

        // Send ReportsProcessed requests.
        let mut reports_processed_requests = Vec::new();
        for (durable_name, report_id_hex_set) in reports_processed_request_data.into_iter() {
            reports_processed_requests.push(durable.post(
                BINDING_DAP_REPORTS_PROCESSED,
                DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED,
                durable_name,
                report_id_hex_set,
            ));
        }

        // Send AggregateStore requests.
        let mut agg_store_requests = Vec::new();
        for durable_name in agg_store_request_name {
            agg_store_requests.push(durable.get(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_CHECK_COLLECTED,
                durable_name,
            ));
        }

        // Create the set of reports that have been processed.
        let reports_processed_responses: Vec<Vec<String>> =
            try_join_all(reports_processed_requests)
                .await
                .map_err(dap_err)?;
        let mut reports_processed = HashSet::new();
        for response in reports_processed_responses.into_iter() {
            for report_id_hex in response.into_iter() {
                let report_id = ReportId::get_decoded(&hex::decode(&report_id_hex)?)?;
                reports_processed.insert(report_id);
            }
        }

        let agg_store_responses: Vec<bool> =
            try_join_all(agg_store_requests).await.map_err(dap_err)?;

        // Decide which reports to reject early. A report will be rejected if has been processed
        // but not collected or if it has not been proceessed but pertains to a batch that was
        // previously collected.
        let mut early_fails = HashMap::new();
        for (bucket, collected) in agg_store_request_bucket
            .iter()
            .zip(agg_store_responses.into_iter())
        {
            for metadata in span.get(bucket).unwrap() {
                let processed = reports_processed.contains(&metadata.id);
                if processed && !collected {
                    early_fails.insert(metadata.id.clone(), TransitionFailure::ReportReplayed);
                } else if !processed && collected {
                    early_fails.insert(metadata.id.clone(), TransitionFailure::BatchCollected);
                }
            }
        }

        Ok(early_fails)
    }

    async fn mark_collected(
        &self,
        task_id: &Id,
        batch_sel: &BatchSelector,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.batch_span_for_sel(batch_sel)? {
            let durable_name =
                durable_name_agg_store(&task_config.version, &task_id.to_hex(), &bucket);
            requests.push(durable.post::<_, ()>(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_MARK_COLLECTED,
                durable_name,
                &(),
            ));
        }

        try_join_all(requests).await.map_err(dap_err)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a, D> DapLeader<'a, BearerToken> for DaphneWorkerConfig<D> {
    type ReportSelector = DaphneWorkerReportSelector;

    async fn put_report(&self, report: &Report) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(&report.task_id)?;
        let task_id_hex = report.task_id.to_hex();
        let report_hex = hex::encode(report.get_encoded());
        let res: ReportsPendingResult = self
            .durable()
            .post(
                BINDING_DAP_REPORTS_PENDING,
                DURABLE_REPORTS_PENDING_PUT,
                self.durable_name_report_store(task_config, &task_id_hex, &report.metadata),
                &report_hex,
            )
            .await
            .map_err(dap_err)?;

        match res {
            ReportsPendingResult::Ok => Ok(()),
            ReportsPendingResult::ErrReportExists => {
                // NOTE This check for report replay is not definitive. It's possible for two
                // reports with the same ID to appear in two different ReportsPending instances.
                // The definitive check is performed by DapAggregator::check_early_reject(), which
                // tracks all repoort IDs consumed for the task in ReportsProcessed. This check
                // would be too expensive to do during the upload sub-protocol.
                Err(DapError::Transition(TransitionFailure::ReportReplayed))
            }
        }
    }

    async fn get_reports(
        &self,
        report_sel: &DaphneWorkerReportSelector,
    ) -> std::result::Result<HashMap<Id, HashMap<PartialBatchSelector, Vec<Report>>>, DapError>
    {
        let durable = self.durable();
        // Read at most `report_sel.max_buckets` buckets from the agg job queue. The result is ordered
        // from oldest to newest.
        //
        // NOTE There is only one agg job queue for now (`queue_num == 0`). In the future, work
        // will be sharded across multiple queues.
        let res: Vec<String> = durable
            .post(
                BINDING_DAP_LEADER_AGG_JOB_QUEUE,
                DURABLE_LEADER_AGG_JOB_QUEUE_GET,
                durable_name_queue(0),
                &report_sel.max_agg_jobs,
            )
            .await
            .map_err(dap_err)?;

        // Drain at most `report_sel.max_reports` from each ReportsPending instance and group them
        // by task.
        //
        // TODO Figure out if we can safely handle each instance in parallel.
        let mut reports_per_task: HashMap<Id, Vec<Report>> = HashMap::new();
        for reports_pending_id_hex in res.into_iter() {
            let reports_from_durable: Vec<String> = durable
                .post_by_id_hex(
                    BINDING_DAP_REPORTS_PENDING,
                    DURABLE_REPORTS_PENDING_GET,
                    reports_pending_id_hex,
                    &report_sel.max_reports,
                )
                .await
                .map_err(dap_err)?;

            for report_hex in reports_from_durable {
                let report = Report::get_decoded(&hex::decode(&report_hex).map_err(|_| {
                    DapError::fatal("response from ReportsPending is not valid hex")
                })?)?;

                if let Some(reports) = reports_per_task.get_mut(&report.task_id) {
                    reports.push(report);
                } else {
                    reports_per_task.insert(report.task_id.clone(), vec![report]);
                }
            }
        }

        let mut reports_per_task_part: HashMap<Id, HashMap<PartialBatchSelector, Vec<Report>>> =
            HashMap::new();
        for (task_id, mut reports) in reports_per_task.into_iter() {
            let task_config = self.try_get_task_config_for(&task_id)?;
            let task_id_hex = task_id.to_hex();
            let reports_per_part = reports_per_task_part.entry(task_id).or_default();
            match task_config.query {
                DapQueryConfig::TimeInterval { .. } => {
                    reports_per_part.insert(PartialBatchSelector::TimeInterval, reports);
                }
                DapQueryConfig::FixedSize {
                    min_batch_size,
                    max_batch_size: _,
                } => {
                    let num_unassigned = reports.len();
                    let batch_assignments: Vec<BatchCount> = durable
                        .post(
                            BINDING_DAP_LEADER_BATCH_QUEUE,
                            DURABLE_LEADER_BATCH_QUEUE_ASSIGN,
                            durable_name_task(&task_config.version, &task_id_hex),
                            &(min_batch_size, num_unassigned),
                        )
                        .await
                        .map_err(dap_err)?;
                    for batch_count in batch_assignments.into_iter() {
                        let BatchCount {
                            batch_id,
                            report_count,
                        } = batch_count;
                        reports_per_part.insert(
                            PartialBatchSelector::FixedSize { batch_id },
                            reports.drain(..report_count).collect(),
                        );
                    }
                    if !reports.is_empty() {
                        return Err(DapError::Fatal(
                            format!("LeaderBatchQueue returned the wrong number of reports: got {}; want {}",
                                reports.len() + num_unassigned, num_unassigned)
                        ));
                    }
                }
            };
        }

        for (task_id, reports) in reports_per_task_part.iter() {
            let mut report_count = 0;
            for reports in reports.values() {
                report_count += reports.len();
            }
            console_debug!(
                "got {} reports for task {}",
                report_count,
                task_id.to_base64url()
            );
        }
        Ok(reports_per_task_part)
    }

    async fn init_collect_job(
        &self,
        collect_req: &CollectReq,
    ) -> std::result::Result<Url, DapError> {
        let task_config = self.try_get_task_config_for(&collect_req.task_id)?;

        // Try to put the request into collection job queue. If the request is overlapping
        // with past requests, then abort.
        let collect_id: Id = self
            .durable()
            .post(
                BINDING_DAP_LEADER_COL_JOB_QUEUE,
                DURABLE_LEADER_COL_JOB_QUEUE_PUT,
                durable_name_queue(0),
                &collect_req,
            )
            .await
            .map_err(dap_err)?;

        let mut url = task_config.leader_url.clone();
        if matches!(self.deployment, DaphneWorkerDeployment::Dev) {
            // When running in a local development environment, override the hostname of the Leader
            // with localhost.
            url.set_host(Some("127.0.0.1")).map_err(|e| {
                DapError::Fatal(format!(
                    "failed to overwrite hostname for request URL: {}",
                    e
                ))
            })?;
        }

        let collect_uri = url
            .join(&format!(
                "collect/task/{}/req/{}",
                collect_req.task_id.to_base64url(),
                collect_id.to_base64url(),
            ))
            .map_err(|e| DapError::Fatal(e.to_string()))?;

        Ok(collect_uri)
    }

    async fn poll_collect_job(
        &self,
        _task_id: &Id,
        collect_id: &Id,
    ) -> std::result::Result<DapCollectJob, DapError> {
        let res: DapCollectJob = self
            .durable()
            .post(
                BINDING_DAP_LEADER_COL_JOB_QUEUE,
                DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT,
                durable_name_queue(0),
                &collect_id,
            )
            .await
            .map_err(dap_err)?;
        Ok(res)
    }

    async fn get_pending_collect_jobs(
        &self,
    ) -> std::result::Result<Vec<(Id, CollectReq)>, DapError> {
        let res: Vec<(Id, CollectReq)> = self
            .durable()
            .get(
                BINDING_DAP_LEADER_COL_JOB_QUEUE,
                DURABLE_LEADER_COL_JOB_QUEUE_GET,
                durable_name_queue(0),
            )
            .await
            .map_err(dap_err)?;
        Ok(res)
    }

    async fn finish_collect_job(
        &self,
        task_id: &Id,
        collect_id: &Id,
        collect_resp: &CollectResp,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;
        let durable = self.durable();
        if let PartialBatchSelector::FixedSize { ref batch_id } = collect_resp.part_batch_sel {
            durable
                .post(
                    BINDING_DAP_LEADER_BATCH_QUEUE,
                    DURABLE_LEADER_BATCH_QUEUE_REMOVE,
                    durable_name_task(&task_config.version, &task_id.to_hex()),
                    batch_id.to_hex(),
                )
                .await
                .map_err(dap_err)?;
        }

        durable
            .post(
                BINDING_DAP_LEADER_COL_JOB_QUEUE,
                DURABLE_LEADER_COL_JOB_QUEUE_FINISH,
                durable_name_queue(0),
                (collect_id, collect_resp),
            )
            .await
            .map_err(dap_err)?;
        Ok(())
    }

    async fn send_http_post(
        &self,
        req: DapRequest<BearerToken>,
    ) -> std::result::Result<DapResponse, DapError> {
        let (payload, mut url) = (req.payload, req.url);

        // When running in a local development environment, override the hostname of the Helper
        // with localhost.
        if matches!(self.deployment, DaphneWorkerDeployment::Dev) {
            url.set_host(Some("127.0.0.1")).map_err(|e| {
                DapError::Fatal(format!(
                    "failed to overwrite hostname for request URL: {}",
                    e
                ))
            })?;
        }

        let mut headers = reqwest_wasm::header::HeaderMap::new();
        if let Some(content_type) = req.media_type {
            headers.insert(
                reqwest_wasm::header::CONTENT_TYPE,
                reqwest_wasm::header::HeaderValue::from_str(content_type)
                    .map_err(|e| DapError::Fatal(e.to_string()))?,
            );
        }

        if let Some(bearer_token) = req.sender_auth {
            headers.insert(
                reqwest_wasm::header::HeaderName::from_static("dap-auth-token"),
                reqwest_wasm::header::HeaderValue::from_str(bearer_token.as_ref())
                    .map_err(|e| DapError::Fatal(e.to_string()))?,
            );
        }

        let reqwest_req = self
            .client
            .as_ref()
            .ok_or_else(|| DapError::Fatal("helper cannot send HTTP requests".into()))?
            .post(url.as_str())
            .body(payload)
            .headers(headers);

        let start = Date::now().as_millis();
        let reqwest_resp = reqwest_req
            .send()
            .await
            .map_err(|e| DapError::Fatal(e.to_string()))?;
        let end = Date::now().as_millis();
        console_log!("request to {} completed in {}ms", url, end - start);
        let status = reqwest_resp.status();
        if status == 200 {
            // Translate the reqwest response into a Worker response.
            let content_type = reqwest_resp
                .headers()
                .get(reqwest_wasm::header::CONTENT_TYPE)
                .ok_or_else(|| DapError::fatal(INT_ERR_PEER_RESP_MISSING_MEDIA_TYPE))?
                .to_str()
                .map_err(|e| DapError::Fatal(e.to_string()))?;
            let media_type = constants::media_type_for(content_type);

            let payload = reqwest_resp
                .bytes()
                .await
                .map_err(|e| DapError::Fatal(e.to_string()))?
                .to_vec();

            Ok(DapResponse {
                payload,
                media_type,
            })
        } else {
            console_error!("{}: request failed: {:?}", url, reqwest_resp);
            Err(DapError::fatal(INT_ERR_PEER_ABORT))
        }
    }
}

#[async_trait(?Send)]
impl<'a, D> DapHelper<'a, BearerToken> for DaphneWorkerConfig<D> {
    async fn put_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
        helper_state: &DapHelperState,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;
        let helper_state_hex = hex::encode(helper_state.get_encoded(&task_config.vdaf)?);
        self.durable()
            .post(
                BINDING_DAP_HELPER_STATE_STORE,
                DURABLE_HELPER_STATE_PUT,
                durable_helper_state_name(&task_config.version, task_id, agg_job_id),
                helper_state_hex,
            )
            .await
            .map_err(dap_err)?;
        Ok(())
    }

    async fn get_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
    ) -> std::result::Result<Option<DapHelperState>, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;
        let res: Option<String> = self
            .durable()
            .post(
                BINDING_DAP_HELPER_STATE_STORE,
                DURABLE_HELPER_STATE_GET,
                durable_helper_state_name(&task_config.version, task_id, agg_job_id),
                (),
            )
            .await
            .map_err(dap_err)?;

        match res {
            Some(helper_state_hex) => {
                let data =
                    hex::decode(&helper_state_hex).map_err(|e| DapError::Fatal(e.to_string()))?;
                let helper_state = DapHelperState::get_decoded(&task_config.vdaf, &data)?;
                Ok(Some(helper_state))
            }
            None => Ok(None),
        }
    }
}
