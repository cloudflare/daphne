// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of DAP Aggregator roles for Daphne-Worker.
//!
//! Daphne-Worker uses bearer tokens for DAP request authorization as specified in
//! draft-ietf-ppm-dap-01.

use crate::{
    config::{DaphneWorkerConfig, DaphneWorkerDeployment},
    durable::{
        aggregate_store::{
            durable_agg_store_name, AggregateStoreResult, DURABLE_AGGREGATE_STORE_GET,
            DURABLE_AGGREGATE_STORE_MARK_COLLECTED, DURABLE_AGGREGATE_STORE_MERGE,
        },
        durable_queue_name,
        helper_state_store::{
            durable_helper_state_name, DURABLE_HELPER_STATE_GET, DURABLE_HELPER_STATE_PUT,
        },
        leader_agg_job_queue::DURABLE_LEADER_AGG_JOB_QUEUE_GET,
        leader_col_job_queue::{
            DURABLE_LEADER_COL_JOB_QUEUE_FINISH, DURABLE_LEADER_COL_JOB_QUEUE_GET,
            DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT, DURABLE_LEADER_COL_JOB_QUEUE_PUT,
        },
        report_store::{
            ReportStoreResult, DURABLE_REPORT_STORE_GET_PENDING,
            DURABLE_REPORT_STORE_MARK_COLLECTED, DURABLE_REPORT_STORE_PUT_PENDING,
            DURABLE_REPORT_STORE_PUT_PROCESSED,
        },
        BINDING_DAP_AGGREGATE_STORE, BINDING_DAP_HELPER_STATE_STORE,
        BINDING_DAP_LEADER_AGG_JOB_QUEUE, BINDING_DAP_LEADER_COL_JOB_QUEUE,
        BINDING_DAP_REPORT_STORE,
    },
    now, InternalAggregateInfo,
};
use async_trait::async_trait;
use daphne::{
    auth::{BearerToken, BearerTokenProvider},
    constants,
    hpke::HpkeDecrypter,
    messages::{
        CollectReq, CollectResp, HpkeCiphertext, HpkeConfig, Id, Interval, Nonce, Report,
        ReportShare, TransitionFailure,
    },
    roles::{DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    DapAggregateShare, DapCollectJob, DapError, DapGlobalConfig, DapHelperState, DapOutputShare,
    DapRequest, DapResponse, DapTaskConfig,
};
use futures::future::try_join_all;
use prio::codec::{Decode, Encode};
use std::collections::HashMap;
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

impl<D> HpkeDecrypter for DaphneWorkerConfig<D> {
    fn get_hpke_config_for(&self, _task_id: &Id) -> Option<&HpkeConfig> {
        if self.hpke_receiver_config_list.is_empty() {
            return None;
        }

        // Always advertise the first HPKE config in the list.
        Some(&(self.hpke_receiver_config_list[0]).config)
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
    ) -> std::result::Result<Vec<u8>, DapError> {
        if let Some(hpke_receiver_config) = self.get_hpke_receiver_config_for(ciphertext.config_id)
        {
            Ok(hpke_receiver_config.decrypt(info, aad, &ciphertext.enc, &ciphertext.payload)?)
        } else {
            Err(DapError::Transition(TransitionFailure::HpkeUnknownConfigId))
        }
    }
}

#[async_trait(?Send)]
impl<D> BearerTokenProvider for DaphneWorkerConfig<D> {
    async fn get_leader_bearer_token_for(
        &self,
        task_id: &Id,
    ) -> std::result::Result<Option<BearerToken>, DapError> {
        Ok(self.leader_bearer_tokens.get(task_id).cloned())
    }

    async fn get_collector_bearer_token_for(
        &self,
        task_id: &Id,
    ) -> std::result::Result<Option<BearerToken>, DapError> {
        let tokens = self.collector_bearer_tokens.as_ref().ok_or_else(|| {
            DapError::Fatal("helper cannot authorize requests from collector".into())
        })?;
        Ok(tokens.get(task_id).cloned())
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
        self.authorize_with_bearer_token(task_id, media_type).await
    }
}

#[async_trait(?Send)]
impl<D> DapAggregator<BearerToken> for DaphneWorkerConfig<D> {
    async fn authorized(
        &self,
        req: &DapRequest<BearerToken>,
    ) -> std::result::Result<bool, DapError> {
        self.bearer_token_authorized(req).await
    }

    fn get_global_config(&self) -> &DapGlobalConfig {
        &self.global_config
    }

    fn get_task_config_for(&self, task_id: &Id) -> Option<&DapTaskConfig> {
        self.tasks.get(task_id)
    }

    fn get_current_time(&self) -> u64 {
        now()
    }

    async fn is_batch_overlapping(
        &self,
        task_id: &Id,
        batch_interval: &Interval,
    ) -> std::result::Result<bool, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        // Check whether the request overlaps with previous requests. This is done by
        // checking the AggregateStore and seeing whether it requests for aggregate
        // shares that have already been marked collected.
        let mut requests = Vec::new();
        for window in (batch_interval.start..batch_interval.end())
            .step_by(task_config.min_batch_duration.try_into().unwrap())
        {
            let durable_name =
                durable_agg_store_name(&task_config.version, &task_id.to_hex(), window);
            requests.push(self.durable_post(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_GET,
                durable_name,
                &(),
            ));
        }

        let responses: Vec<AggregateStoreResult> = try_join_all(requests).await?;

        for resp in responses {
            // If this agg share has been collected before, return BatchCollected error.
            match resp {
                AggregateStoreResult::Ok(_) => {
                    continue;
                }
                AggregateStoreResult::ErrBatchOverlap => {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn put_out_shares(
        &self,
        task_id: &Id,
        out_shares: Vec<DapOutputShare>,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        let agg_shares =
            DapAggregateShare::batches_from_out_shares(out_shares, task_config.min_batch_duration)?;

        let mut requests = Vec::new();
        for (window, agg_share) in agg_shares.into_iter() {
            let durable_name =
                durable_agg_store_name(&task_config.version, &task_id.to_hex(), window);
            requests.push(self.durable_post(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_MERGE,
                durable_name,
                agg_share,
            ));
        }
        let responses: Vec<String> = try_join_all(requests).await?;
        for result in responses {
            if !result.is_empty() {
                return Err(DapError::fatal("unexpected response"));
            }
        }

        Ok(())
    }

    async fn get_agg_share(
        &self,
        task_id: &Id,
        batch_interval: &Interval,
    ) -> std::result::Result<DapAggregateShare, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        let mut requests = Vec::new();
        for window in (batch_interval.start..batch_interval.end())
            .step_by(task_config.min_batch_duration.try_into().unwrap())
        {
            let durable_name =
                durable_agg_store_name(&task_config.version, &task_id.to_hex(), window);
            requests.push(self.durable_post(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_GET,
                durable_name,
                &(),
            ));
        }
        let responses: Vec<AggregateStoreResult> = try_join_all(requests).await?;

        let mut agg_share = DapAggregateShare::default();
        for resp in responses {
            match resp {
                AggregateStoreResult::Ok(agg_share_delta) => agg_share.merge(agg_share_delta)?,
                AggregateStoreResult::ErrBatchOverlap => {
                    return Err(DapError::fatal("batch collected"))
                }
            }
        }

        Ok(agg_share)
    }

    async fn mark_collected(
        &self,
        task_id: &Id,
        batch_interval: &Interval,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        // Mark reports collected.
        let mut requests = Vec::new();
        for durable_name in
            self.iter_report_store_names(&task_config.version, task_id, batch_interval)?
        {
            requests.push(self.durable_post(
                BINDING_DAP_REPORT_STORE,
                DURABLE_REPORT_STORE_MARK_COLLECTED,
                durable_name,
                &(),
            ));
        }
        let responses: Vec<ReportStoreResult> = try_join_all(requests).await?;
        for result in responses {
            if let ReportStoreResult::Err(_) = result {
                return Err(DapError::fatal("unexpected response"));
            }
        }

        // Mark aggregate shares collected.
        let mut requests = Vec::new();
        for window in (batch_interval.start..batch_interval.end())
            .step_by(task_config.min_batch_duration.try_into().unwrap())
        {
            let durable_name =
                durable_agg_store_name(&task_config.version, &task_id.to_hex(), window);
            requests.push(self.durable_post(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_MARK_COLLECTED,
                durable_name,
                &(),
            ));
        }
        let responses: Vec<String> = try_join_all(requests).await?;
        for result in responses {
            if !result.is_empty() {
                return Err(DapError::fatal("unexpected response"));
            }
        }

        Ok(())
    }
}

#[async_trait(?Send)]
impl<D> DapLeader<BearerToken> for DaphneWorkerConfig<D> {
    type ReportSelector = InternalAggregateInfo;

    async fn put_report(&self, report: &Report) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(&report.task_id)?;
        let durable_namespace = self.durable_object(BINDING_DAP_REPORT_STORE)?;
        let durable_name =
            self.durable_report_store_name(task_config, &report.task_id, &report.nonce);
        let stub = durable_namespace.id_from_name(&durable_name)?.get_stub()?;
        let report_hex = hex::encode(report.get_encoded());
        let mut resp = durable_post!(stub, DURABLE_REPORT_STORE_PUT_PENDING, &report_hex).await?;
        match resp.json().await? {
            ReportStoreResult::Ok => Ok(()),
            ReportStoreResult::Err(t) => return Err(DapError::Transition(t)),
        }
    }

    async fn get_reports(
        &self,
        selector: &InternalAggregateInfo,
    ) -> std::result::Result<HashMap<Id, Vec<Report>>, DapError> {
        // Read at most `selector.max_buckets` buckets from the agg job queue. The result is ordered
        // from oldest to newest.
        //
        // NOTE There is only one agg job queue for now (`queue_num == 0`). In the future, work
        // will be sharded across multiple queues.
        let namespace = self.durable_object(BINDING_DAP_LEADER_AGG_JOB_QUEUE)?;
        let stub = namespace.id_from_name(&durable_queue_name(0))?.get_stub()?;
        let mut resp = durable_post!(
            stub,
            DURABLE_LEADER_AGG_JOB_QUEUE_GET,
            &selector.max_buckets
        )
        .await?;
        let res: Vec<String> = resp.json().await?;

        // Drain at most `selector.max_reports` from each bucket.
        //
        // TODO Figure out if we can safely handle each bucket in parallel.
        let namespace = self.durable_object(BINDING_DAP_REPORT_STORE)?;
        let mut reports_per_task: HashMap<Id, Vec<Report>> = HashMap::new();
        for report_store_id_hex in res.into_iter() {
            let stub = namespace.id_from_string(&report_store_id_hex)?.get_stub()?;
            let reports_from_durable: Vec<String> = durable_post!(
                stub,
                DURABLE_REPORT_STORE_GET_PENDING,
                &selector.max_reports
            )
            .await?
            .json()
            .await?;

            for report_hex in reports_from_durable {
                let report =
                    Report::get_decoded(&hex::decode(&report_hex).map_err(|_| {
                        DapError::fatal("response from ReportStore is not valid hex")
                    })?)?;

                if let Some(reports) = reports_per_task.get_mut(&report.task_id) {
                    reports.push(report);
                } else {
                    reports_per_task.insert(report.task_id.clone(), vec![report]);
                }
            }
        }

        for (task_id, reports) in reports_per_task.iter() {
            console_debug!(
                "got {} reports for task {}",
                reports.len(),
                task_id.to_base64url()
            );
        }
        Ok(reports_per_task)
    }

    async fn init_collect_job(
        &self,
        collect_req: &CollectReq,
    ) -> std::result::Result<Url, DapError> {
        let task_config = self.try_get_task_config_for(&collect_req.task_id)?;

        // Try to put the request into collection job queue. If the request is overlapping
        // with past requests, then abort.
        let namespace = self.durable_object(BINDING_DAP_LEADER_COL_JOB_QUEUE)?;
        let stub = namespace.id_from_name(&durable_queue_name(0))?.get_stub()?;
        let collect_id: Id = durable_post!(stub, DURABLE_LEADER_COL_JOB_QUEUE_PUT, &collect_req)
            .await?
            .json()
            .await?;

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
        let namespace = self.durable_object(BINDING_DAP_LEADER_COL_JOB_QUEUE)?;
        let stub = namespace.id_from_name(&durable_queue_name(0))?.get_stub()?;
        let res: DapCollectJob =
            durable_post!(stub, DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT, &collect_id)
                .await?
                .json()
                .await?;
        Ok(res)
    }

    async fn get_pending_collect_jobs(
        &self,
    ) -> std::result::Result<Vec<(Id, CollectReq)>, DapError> {
        let leader_state_namespace = self.durable_object(BINDING_DAP_LEADER_COL_JOB_QUEUE)?;
        let leader_state_stub = leader_state_namespace
            .id_from_name(&durable_queue_name(0))?
            .get_stub()?;
        let res: Vec<(Id, CollectReq)> =
            durable_get!(leader_state_stub, DURABLE_LEADER_COL_JOB_QUEUE_GET)
                .await?
                .json()
                .await?;
        Ok(res)
    }

    async fn finish_collect_job(
        &self,
        _task_id: &Id,
        collect_id: &Id,
        collect_resp: &CollectResp,
    ) -> std::result::Result<(), DapError> {
        let leader_state_namespace = self.durable_object(BINDING_DAP_LEADER_COL_JOB_QUEUE)?;
        let leader_state_stub = leader_state_namespace
            .id_from_name(&durable_queue_name(0))?
            .get_stub()?;
        durable_post!(
            leader_state_stub,
            DURABLE_LEADER_COL_JOB_QUEUE_FINISH,
            &(collect_id.clone(), collect_resp.clone(),)
        )
        .await?;
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
impl<D> DapHelper<BearerToken> for DaphneWorkerConfig<D> {
    async fn mark_aggregated(
        &self,
        task_id: &Id,
        report_shares: &[ReportShare],
    ) -> std::result::Result<HashMap<Nonce, TransitionFailure>, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;

        let mut durable_requests: HashMap<String, Vec<String>> = HashMap::new();
        for report_share in report_shares.iter() {
            let durable_name =
                self.durable_report_store_name(task_config, task_id, &report_share.nonce);
            let nonce_hex = hex::encode(report_share.nonce.get_encoded());
            if let Some(nonce_hex_set) = durable_requests.get_mut(&durable_name) {
                nonce_hex_set.push(nonce_hex);
            } else {
                durable_requests.insert(durable_name, vec![nonce_hex]);
            }
        }

        let mut requests = Vec::new();
        for (durable_name, nonce_hex_set) in durable_requests.into_iter() {
            requests.push(self.durable_post(
                BINDING_DAP_REPORT_STORE,
                DURABLE_REPORT_STORE_PUT_PROCESSED,
                durable_name,
                nonce_hex_set,
            ));
        }
        let responses: Vec<Vec<(String, TransitionFailure)>> = try_join_all(requests).await?;

        let mut early_fails = HashMap::new();
        for response in responses.into_iter() {
            for (nonce_hex, failure_reason) in response.into_iter() {
                let nonce_hex: String = nonce_hex;
                let nonce = Nonce::get_decoded(&hex::decode(&nonce_hex)?)?;
                early_fails.insert(nonce, failure_reason);
            }
        }
        Ok(early_fails)
    }

    async fn put_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
        helper_state: &DapHelperState,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;
        let namespace = self.durable_object(BINDING_DAP_HELPER_STATE_STORE)?;
        let stub = namespace
            .id_from_name(&durable_helper_state_name(
                &task_config.version,
                task_id,
                agg_job_id,
            ))?
            .get_stub()?;

        let helper_state_hex = hex::encode(helper_state.get_encoded(&task_config.vdaf)?);
        durable_post!(stub, DURABLE_HELPER_STATE_PUT, &helper_state_hex).await?;
        Ok(())
    }

    async fn get_helper_state(
        &self,
        task_id: &Id,
        agg_job_id: &Id,
    ) -> std::result::Result<Option<DapHelperState>, DapError> {
        let task_config = self.try_get_task_config_for(task_id)?;
        let namespace = self.durable_object(BINDING_DAP_HELPER_STATE_STORE)?;
        let stub = namespace
            .id_from_name(&durable_helper_state_name(
                &task_config.version,
                task_id,
                agg_job_id,
            ))?
            .get_stub()?;

        let res: Option<String> = durable_post!(stub, DURABLE_HELPER_STATE_GET, &())
            .await?
            .json()
            .await?;

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
