// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of DAP Aggregator roles for Daphne-Worker.
//!
//! Daphne-Worker uses bearer tokens for DAP request authorization as specified in
//! draft-ietf-ppm-dap-03.

use crate::{
    auth::DaphneWorkerAuth,
    config::{
        BearerTokenKvPair, DapTaskConfigKvPair, DaphneWorker, HpkeReceiverConfigKvPair,
        HpkeReceiverKvKey, KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG,
    },
    dap_err,
    durable::{
        aggregate_store::{
            DURABLE_AGGREGATE_STORE_CHECK_COLLECTED, DURABLE_AGGREGATE_STORE_GET,
            DURABLE_AGGREGATE_STORE_MARK_COLLECTED, DURABLE_AGGREGATE_STORE_MERGE,
        },
        durable_name_agg_store, durable_name_queue, durable_name_task,
        helper_state_store::{
            durable_helper_state_name, DURABLE_HELPER_STATE_GET,
            DURABLE_HELPER_STATE_PUT_IF_NOT_EXISTS,
        },
        leader_agg_job_queue::DURABLE_LEADER_AGG_JOB_QUEUE_GET,
        leader_batch_queue::{
            BatchCount, DURABLE_LEADER_BATCH_QUEUE_ASSIGN, DURABLE_LEADER_BATCH_QUEUE_REMOVE,
        },
        leader_col_job_queue::{
            CollectQueueRequest, DURABLE_LEADER_COL_JOB_QUEUE_FINISH,
            DURABLE_LEADER_COL_JOB_QUEUE_GET, DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT,
            DURABLE_LEADER_COL_JOB_QUEUE_PUT,
        },
        reports_pending::{
            PendingReport, ReportsPendingResult, DURABLE_REPORTS_PENDING_GET,
            DURABLE_REPORTS_PENDING_PUT,
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
    constants::DapMediaType,
    hpke::HpkeDecrypter,
    messages::{
        BatchId, BatchSelector, Collection, CollectionJobId, CollectionReq, HpkeCiphertext,
        HpkeConfig, PartialBatchSelector, Report, ReportId, ReportMetadata, TaskId,
        TransitionFailure,
    },
    metrics::DaphneMetrics,
    roles::{early_metadata_check, DapAggregator, DapAuthorizedSender, DapHelper, DapLeader},
    DapAggregateShare, DapBatchBucket, DapCollectJob, DapError, DapGlobalConfig, DapHelperState,
    DapOutputShare, DapQueryConfig, DapRequest, DapResponse, DapSender, DapTaskConfig, DapVersion,
    MetaAggregationJobId,
};
use futures::future::try_join_all;
use prio::codec::{Decode, Encode, ParameterizedDecode, ParameterizedEncode};
use std::{borrow::Cow, collections::HashMap};
use tracing::debug;
use worker::*;

pub(crate) fn dap_response_to_worker(resp: DapResponse) -> Result<Response> {
    let mut headers = Headers::new();
    headers.set(
        "Content-Type",
        resp.media_type
            .as_str_for_version(resp.version)
            .ok_or_else(|| {
                Error::RustError(format!(
                    "failed to construct content-type for media type {:?} and version {:?}",
                    resp.media_type, resp.version
                ))
            })?,
    )?;
    let worker_resp = Response::from_bytes(resp.payload)?.with_headers(headers);
    Ok(worker_resp)
}

#[async_trait(?Send)]
impl<'srv> HpkeDecrypter for DaphneWorker<'srv> {
    type WrappedHpkeConfig<'a> = HpkeReceiverConfigKvPair<'a>
        where Self: 'a;

    async fn get_hpke_config_for<'s>(
        &'s self,
        version: DapVersion,
        _task_id: Option<&TaskId>,
    ) -> std::result::Result<HpkeReceiverConfigKvPair<'s>, DapError> {
        let kv_store = self.kv().map_err(dap_err)?;
        let keys = kv_store
            .list()
            .limit(1)
            .prefix(KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG.to_string())
            .execute()
            .await
            .map_err(|e| DapError::Fatal(format!("kv_store: {e}")))?;

        let hpke_receiver_kv_key = if keys.keys.is_empty() {
            // Generate a new HPKE receiver config and store it in KV.
            //
            // For now, expect that only one KEM algorithm is supported and that only one config
            // will be used at anyone time.
            if self.config().global.supported_hpke_kems.len() != 1 {
                return Err(DapError::Fatal(
                    "The number of supported HPKE KEMs must be 1".to_string(),
                ));
            }

            let mut hpke_config_id = None;
            for it in self
                .config()
                .global
                .gen_hpke_receiver_config_list(rand::random())
            {
                let hpke_receiver_config = it.expect("failed to generate HPKE receiver config");
                if hpke_config_id.is_none() {
                    hpke_config_id = Some(hpke_receiver_config.config.id);
                }
                let new_kv_config_key = format!(
                    "{}/{}",
                    KV_KEY_PREFIX_HPKE_RECEIVER_CONFIG,
                    HpkeReceiverKvKey {
                        version,
                        hpke_config_id: hpke_receiver_config.config.id
                    },
                );

                kv_store
                    .put(&new_kv_config_key, hpke_receiver_config)
                    .map_err(|e| DapError::Fatal(format!("kv_store: {e}")))?
                    .execute()
                    .await
                    .map_err(|e| DapError::Fatal(format!("kv_store: {e}")))?;
            }

            HpkeReceiverKvKey {
                version,
                hpke_config_id: hpke_config_id.unwrap(),
            }
        } else {
            // Return the first HPKE receiver config in the list.
            HpkeReceiverKvKey::try_from_name(keys.keys[0].name.as_str())?
        };

        // Fetch the indicated HPKE config from KV.
        //
        // TODO(cjpatton) Figure out how likely this is to fail if we had to generate a new key
        // pair and write it to KV during this call.
        Ok(self
            .get_hpke_receiver_config(hpke_receiver_kv_key)
            .await
            .map_err(dap_err)?
            .ok_or_else(|| DapError::fatal("empty HPKE receiver config list"))?)
    }

    async fn can_hpke_decrypt(
        &self,
        task_id: &TaskId,
        config_id: u8,
    ) -> std::result::Result<bool, DapError> {
        let version = self.try_get_task_config(task_id).await?.as_ref().version;
        Ok(self
            .get_hpke_receiver_config(HpkeReceiverKvKey {
                version,
                hpke_config_id: config_id,
            })
            .await
            .map_err(dap_err)?
            .is_some())
    }

    async fn hpke_decrypt(
        &self,
        task_id: &TaskId,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> std::result::Result<Vec<u8>, DapError> {
        let version = self.try_get_task_config(task_id).await?.as_ref().version;
        if let Some(hpke_receiver_config) = self
            .get_hpke_receiver_config(HpkeReceiverKvKey {
                version,
                hpke_config_id: ciphertext.config_id,
            })
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

#[async_trait(?Send)]
impl<'srv> BearerTokenProvider for DaphneWorker<'srv> {
    type WrappedBearerToken<'a> = BearerTokenKvPair<'a>
        where Self: 'a;

    async fn get_leader_bearer_token_for<'s>(
        &'s self,
        task_id: &'s TaskId,
    ) -> std::result::Result<Option<Self::WrappedBearerToken<'s>>, DapError> {
        self.get_leader_bearer_token(task_id).await.map_err(dap_err)
    }

    async fn get_collector_bearer_token_for<'s>(
        &'s self,
        task_id: &'s TaskId,
    ) -> std::result::Result<Option<Self::WrappedBearerToken<'s>>, DapError> {
        self.get_collector_bearer_token(task_id)
            .await
            .map_err(dap_err)
    }

    fn is_taskprov_leader_bearer_token(&self, token: &BearerToken) -> bool {
        self.get_global_config().allow_taskprov
            && match &self.config().taskprov {
                Some(config) => config.leader_auth.as_ref() == token,
                None => false,
            }
    }

    fn is_taskprov_collector_bearer_token(&self, token: &BearerToken) -> bool {
        self.get_global_config().allow_taskprov
            && match &self.config().taskprov {
                Some(config) => {
                    config
                        .collector_auth
                        .as_ref()
                        .expect("collector authorization method not set")
                        .as_ref()
                        == token
                }
                None => false,
            }
    }
}

#[async_trait(?Send)]
impl DapAuthorizedSender<DaphneWorkerAuth> for DaphneWorker<'_> {
    async fn authorize(
        &self,
        task_id: &TaskId,
        media_type: &DapMediaType,
        _payload: &[u8],
    ) -> std::result::Result<DaphneWorkerAuth, DapError> {
        Ok(DaphneWorkerAuth {
            bearer_token: Some(
                self.authorize_with_bearer_token(task_id, media_type)
                    .await?
                    .value()
                    .clone(),
            ),
            // TODO Consider adding support for authorizing the request with TLS client
            // certificates: https://developers.cloudflare.com/workers/runtime-apis/mtls/
            cf_tls_client_auth: None,
        })
    }
}

#[async_trait(?Send)]
impl<'srv> DapAggregator<DaphneWorkerAuth> for DaphneWorker<'srv> {
    type WrappedDapTaskConfig<'a> = DapTaskConfigKvPair<'a>;

    async fn unauthorized_reason(
        &self,
        req: &DapRequest<DaphneWorkerAuth>,
    ) -> std::result::Result<Option<String>, DapError> {
        let mut authorized = false;

        let Some(ref sender_auth) = req.sender_auth else {
            return Ok(Some("Missing authorization.".into()));
        };

        // If a bearer token is present, verify that it can be used to authorize the request.
        if sender_auth.bearer_token.is_some() {
            if let Some(unauthorized_reason) = self.bearer_token_authorized(req).await? {
                return Ok(Some(unauthorized_reason));
            }
            authorized = true;
        }

        // If a TLS client certificate is present, verify that it is valid and that the issuer and
        // subject are trusted.
        if let Some(ref cf_tls_client_auth) = sender_auth.cf_tls_client_auth {
            // TODO(cjpatton) Add support for TLS client authentication for non-Taskprov tasks.
            let Some(ref taskprov_config) = self.config().taskprov else {
                return Ok(Some(
                    "TLS client authentication is currently only supported with Taskprov.".into(),
                ));
            };

            // Check that that the certificate is valid. This is indicated bylLiteral "SUCCESS".
            let cert_verified = cf_tls_client_auth.cert_verified();
            if cert_verified != "SUCCESS" {
                return Ok(Some(format!("Invalid TLS certificate ({cert_verified}).")));
            }

            // Resolve the trusted certificate issuers and subjects for this request.
            let sender = req.media_type.sender();
            let trusted_certs = if let (Some(DapSender::Leader), Some(ref trusted_certs)) =
                (sender, &taskprov_config.leader_auth.cf_tls_client_auth)
            {
                trusted_certs
            } else if let (Some(DapSender::Collector), Some(ref trusted_certs)) = (
                sender,
                taskprov_config
                    .collector_auth
                    .as_ref()
                    .and_then(|auth| auth.cf_tls_client_auth.as_ref()),
            ) {
                trusted_certs
            } else {
                let unauthorized_reason =
                    format!("TLS client authentication is not configured for sender ({sender:?}.");
                return Ok(Some(unauthorized_reason));
            };

            let cert_issuer = cf_tls_client_auth.cert_issuer_dn_rfc2253();
            let cert_subject = cf_tls_client_auth.cert_subject_dn_rfc2253();
            if !trusted_certs.iter().any(|trusted_cert| {
                trusted_cert.issuer == cert_issuer && trusted_cert.subject == cert_subject
            }) {
                return Ok(Some(format!(
                    r#"Unexpected issuer "{cert_issuer}" and subject "{cert_subject}"."#
                )));
            }
            authorized = true;
        }

        if authorized {
            Ok(None)
        } else {
            Ok(Some("No suitable authorization method was found.".into()))
        }
    }

    fn get_global_config(&self) -> &DapGlobalConfig {
        &self.config().global
    }

    fn taskprov_vdaf_verify_key_init(&self) -> Option<&[u8; 32]> {
        self.config()
            .taskprov
            .as_ref()
            .map(|config| &config.vdaf_verify_key_init)
    }

    fn taskprov_collector_hpke_config(&self) -> Option<&HpkeConfig> {
        self.config()
            .taskprov
            .as_ref()
            .map(|config| &config.hpke_collector_config)
    }

    fn taskprov_opt_out_reason(
        &self,
        _task_config: &DapTaskConfig,
    ) -> std::result::Result<Option<String>, DapError> {
        // For now we always opt-in.
        Ok(None)
    }

    async fn taskprov_put(
        &self,
        req: &DapRequest<DaphneWorkerAuth>,
        task_config: DapTaskConfig,
    ) -> std::result::Result<(), DapError> {
        let task_id = req.task_id().map_err(DapError::Abort)?;
        let taskprov = self
            .config()
            .taskprov
            .as_ref()
            .ok_or_else(|| DapError::fatal("taskprov configuration not found"))?;

        // If `resolve_advertised_task_config()` returned a `TaskConfig` and `req.taskprov` is set,
        // then the task was advertised in the HTTP "dap-taskprov" header. In this case we expect
        // the peer to send the header in every request for this task.
        //
        // NOTE(cjpatton) This behavior is not specified in taskprov-02, but we expect it to be
        // mandatory in a future draft.
        if !self.config().is_leader && req.taskprov.is_some() {
            // Store the task config in Worker memory, but don't write it through to KV.
            let mut guarded_tasks =
                self.isolate_state().tasks.write().map_err(|e| {
                    DapError::Fatal(format!("failed to lock tasks for writing: {e}"))
                })?;
            guarded_tasks.insert(task_id.clone(), task_config);

            if let Some(ref leader_bearer_token) = taskprov.leader_auth.bearer_token {
                let mut guarded_leader_bearer_tokens = self
                    .isolate_state()
                    .leader_bearer_tokens
                    .write()
                    .map_err(|e| {
                        DapError::Fatal(format!(
                            "failed to lock leader_bearer_tokens for writing: {e}"
                        ))
                    })?;
                guarded_leader_bearer_tokens.insert(task_id.clone(), leader_bearer_token.clone());
            }
        } else {
            // Write the task config through to KV.
            self.set_task_config(task_id, &task_config)
                .await
                .map_err(dap_err)?;

            if let Some(ref leader_bearer_token) = taskprov.leader_auth.bearer_token {
                self.set_leader_bearer_token(task_id, leader_bearer_token)
                    .await
                    .map_err(dap_err)?;
            }
        }

        Ok(())
    }

    async fn get_task_config_for<'req>(
        &self,
        task_id: Cow<'req, TaskId>,
    ) -> std::result::Result<Option<Self::WrappedDapTaskConfig<'req>>, DapError> {
        self.get_task_config(task_id).await.map_err(dap_err)
    }

    fn get_current_time(&self) -> u64 {
        now()
    }

    async fn is_batch_overlapping(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> std::result::Result<bool, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;

        // Check whether the request overlaps with previous requests. This is done by
        // checking the AggregateStore and seeing whether it requests for aggregate
        // shares that have already been marked collected.
        let durable = self.durable().with_retry();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            let durable_name =
                durable_name_agg_store(&task_config.as_ref().version, &task_id.to_hex(), &bucket);
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
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> std::result::Result<bool, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;

        let agg_share: DapAggregateShare = self
            .durable()
            .with_retry()
            .get(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_GET,
                durable_name_agg_store(
                    &task_config.as_ref().version,
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
        task_id: &TaskId,
        part_batch_sel: &PartialBatchSelector,
        out_shares: Vec<DapOutputShare>,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config(task_id).await?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for (bucket, agg_share) in task_config
            .as_ref()
            .batch_span_for_out_shares(part_batch_sel, out_shares)?
        {
            let durable_name =
                durable_name_agg_store(&task_config.as_ref().version, &task_id.to_hex(), &bucket);
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
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> std::result::Result<DapAggregateShare, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;

        let durable = self.durable().with_retry();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            let durable_name =
                durable_name_agg_store(&task_config.as_ref().version, &task_id.to_hex(), &bucket);
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

    async fn check_early_reject(
        &self,
        task_id: &TaskId,
        part_batch_sel: &PartialBatchSelector,
        report_meta: impl Iterator<Item = &ReportMetadata>,
    ) -> std::result::Result<HashMap<ReportId, TransitionFailure>, DapError> {
        let durable = self.durable().with_retry();
        let task_config = self.try_get_task_config(task_id).await?;
        let task_id_hex = task_id.to_hex();
        let span = task_config
            .as_ref()
            .batch_span_for_meta(part_batch_sel, report_meta)?;

        // Coalesce reports pertaining to the same ReportsProcessed or AggregateStore instance.
        let mut reports_processed_request_data: HashMap<String, Vec<String>> = HashMap::new();
        let mut agg_store_request_name = Vec::new();
        let mut agg_store_request_bucket = Vec::new();
        for (bucket, report_meta) in span.iter() {
            agg_store_request_name.push(durable_name_agg_store(
                &task_config.as_ref().version,
                &task_id_hex,
                bucket,
            ));
            agg_store_request_bucket.push(bucket);
            for metadata in report_meta {
                let durable_name = self.config().durable_name_report_store(
                    task_config.as_ref(),
                    &task_id_hex,
                    metadata,
                );
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
            reports_processed_requests.push(durable.post_with_handler(
                BINDING_DAP_REPORTS_PROCESSED,
                DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED,
                durable_name,
                report_id_hex_set,
                |output: Vec<String>, retried| (output, retried),
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
        let reports_processed_responses: Vec<(Vec<String>, bool)> =
            try_join_all(reports_processed_requests)
                .await
                .map_err(dap_err)?;
        let mut early_fails = HashMap::new();
        for (reports_processed, retried) in reports_processed_responses.into_iter() {
            // The request to ReportsProcessed is not idempotent. If it was retried, then it's
            // possible that one or more of the reports were erroneously as replayed. This would
            // happen if, for example, a fresh report was marked as aggregated in the failed
            // request, then marked as replayed by a retried request. In this case we cannot
            // determine definitively if the report was replayed, so we drop it to be safe.
            let failure = if retried {
                TransitionFailure::ReportDropped
            } else {
                TransitionFailure::ReportReplayed
            };
            for report_id_hex in reports_processed.into_iter() {
                let report_id = ReportId::get_decoded(&hex::decode(report_id_hex)?)?;
                early_fails.insert(report_id, failure);
            }
        }

        let agg_store_responses: Vec<bool> =
            try_join_all(agg_store_requests).await.map_err(dap_err)?;

        // Decide which reports to reject early. A report will be rejected here if, for example,
        // it has been processed but not collected, or if it has not been proceessed but pertains
        // to a batch that was previously collected, or if it is not within time bounds specified
        // by the configuration.
        let current_time = self.get_current_time();
        let min_time = self.least_valid_report_time(current_time);
        let max_time = self.greatest_valid_report_time(current_time);
        for (bucket, collected) in agg_store_request_bucket
            .iter()
            .zip(agg_store_responses.into_iter())
        {
            for metadata in span.get(bucket).unwrap() {
                let result = early_fails.get(&metadata.id);
                if matches!(result, Some(TransitionFailure::ReportDropped)) {
                    continue;
                }

                let processed = matches!(result, Some(TransitionFailure::ReportReplayed));
                if let Some(failure) =
                    early_metadata_check(metadata, processed, collected, min_time, max_time)
                {
                    early_fails.insert(metadata.id.clone(), failure);
                }
            }
        }

        Ok(early_fails)
    }

    async fn mark_collected(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config(task_id).await?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            let durable_name =
                durable_name_agg_store(&task_config.as_ref().version, &task_id.to_hex(), &bucket);
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

    async fn current_batch(&self, task_id: &TaskId) -> std::result::Result<BatchId, DapError> {
        self.internal_current_batch(task_id).await
    }

    fn metrics(&self) -> &DaphneMetrics {
        &self.state.metrics.daphne
    }
}

#[async_trait(?Send)]
impl<'srv> DapLeader<DaphneWorkerAuth> for DaphneWorker<'srv> {
    type ReportSelector = DaphneWorkerReportSelector;

    async fn put_report(
        &self,
        report: &Report,
        task_id: &TaskId,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        let task_id_hex = task_id.to_hex();
        let version = task_config.as_ref().version;
        let pending_report = PendingReport {
            version,
            task_id: task_id.clone(),
            report_hex: hex::encode(report.get_encoded_with_param(&version)),
        };
        let res: ReportsPendingResult = self
            .durable()
            .post(
                BINDING_DAP_REPORTS_PENDING,
                DURABLE_REPORTS_PENDING_PUT,
                self.config().durable_name_report_store(
                    task_config.as_ref(),
                    &task_id_hex,
                    &report.report_metadata,
                ),
                &pending_report,
            )
            .await
            .map_err(dap_err)?;

        match res {
            ReportsPendingResult::Ok => Ok(()),
            ReportsPendingResult::ErrReportExists => {
                // NOTE This check for report replay is not definitive. It's possible for two
                // reports with the same ID to appear in two different ReportsPending instances.
                // The definitive check is performed by DapAggregator::check_early_reject(), which
                // tracks all report IDs consumed for the task in ReportsProcessed. This check
                // would be too expensive to do during the upload sub-protocol.
                Err(DapError::Transition(TransitionFailure::ReportReplayed))
            }
        }
    }

    async fn get_reports(
        &self,
        report_sel: &DaphneWorkerReportSelector,
    ) -> std::result::Result<HashMap<TaskId, HashMap<PartialBatchSelector, Vec<Report>>>, DapError>
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
        let mut reports_per_task: HashMap<TaskId, Vec<Report>> = HashMap::new();
        for reports_pending_id_hex in res.into_iter() {
            let reports_from_durable: Vec<PendingReport> = durable
                .post_by_id_hex(
                    BINDING_DAP_REPORTS_PENDING,
                    DURABLE_REPORTS_PENDING_GET,
                    reports_pending_id_hex,
                    &report_sel.max_reports,
                )
                .await
                .map_err(dap_err)?;

            for pending_report in reports_from_durable {
                let report_bytes = hex::decode(&pending_report.report_hex).map_err(|_| {
                    DapError::fatal("response from ReportsPending is not valid hex")
                })?;

                let version = self
                    .try_get_task_config(&pending_report.task_id)
                    .await?
                    .as_ref()
                    .version;
                let report = Report::get_decoded_with_param(&version, &report_bytes)?;
                if let Some(reports) = reports_per_task.get_mut(&pending_report.task_id) {
                    reports.push(report);
                } else {
                    reports_per_task.insert(pending_report.task_id.clone(), vec![report]);
                }
            }
        }

        let mut reports_per_task_part: HashMap<TaskId, HashMap<PartialBatchSelector, Vec<Report>>> =
            HashMap::new();
        for (task_id, mut reports) in reports_per_task.into_iter() {
            let task_config = self
                .get_task_config(Cow::Owned(task_id))
                .await
                .map_err(dap_err)?
                .ok_or_else(|| DapError::fatal("unrecognized task"))?;
            let task_id_hex = task_config.key().to_hex();
            let reports_per_part = reports_per_task_part
                .entry(task_config.key().clone())
                .or_default();
            match task_config.as_ref().query {
                DapQueryConfig::TimeInterval => {
                    reports_per_part.insert(PartialBatchSelector::TimeInterval, reports);
                }
                DapQueryConfig::FixedSize { .. } => {
                    let num_unassigned = reports.len();
                    let batch_assignments: Vec<BatchCount> = durable
                        .post(
                            BINDING_DAP_LEADER_BATCH_QUEUE,
                            DURABLE_LEADER_BATCH_QUEUE_ASSIGN,
                            durable_name_task(&task_config.as_ref().version, &task_id_hex),
                            &(task_config.as_ref().min_batch_size, num_unassigned),
                        )
                        .await
                        .map_err(dap_err)?;
                    for batch_count in batch_assignments.into_iter() {
                        let BatchCount {
                            batch_id,
                            report_count,
                        } = batch_count;
                        reports_per_part.insert(
                            PartialBatchSelector::FixedSizeByBatchId { batch_id },
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
            debug!(
                "got {} reports for task {}",
                report_count,
                task_id.to_base64url()
            );
        }
        Ok(reports_per_task_part)
    }

    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        collect_job_id: &Option<CollectionJobId>,
        collect_req: &CollectionReq,
    ) -> std::result::Result<Url, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        // Try to put the request into collection job queue. If the request is overlapping
        // with past requests, then abort.
        let collect_queue_req = CollectQueueRequest {
            collect_req: collect_req.clone(),
            task_id: task_id.clone(),
            collect_job_id: collect_job_id.clone(),
        };
        let collect_id: CollectionJobId = self
            .durable()
            .post(
                BINDING_DAP_LEADER_COL_JOB_QUEUE,
                DURABLE_LEADER_COL_JOB_QUEUE_PUT,
                durable_name_queue(0),
                &collect_queue_req,
            )
            .await
            .map_err(dap_err)?;
        debug!("assigned collect_id {collect_id}");

        let url = task_config.as_ref().leader_url.clone();

        // Note that we always return the draft02 URI, but draft04 and later ignore it.
        let collect_uri = url
            .join(&format!(
                "collect/task/{}/req/{}",
                task_id.to_base64url(),
                collect_id.to_base64url(),
            ))
            .map_err(|e| DapError::Fatal(e.to_string()))?;

        Ok(collect_uri)
    }

    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        collect_id: &CollectionJobId,
    ) -> std::result::Result<DapCollectJob, DapError> {
        let res: DapCollectJob = self
            .durable()
            .post(
                BINDING_DAP_LEADER_COL_JOB_QUEUE,
                DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT,
                durable_name_queue(0),
                (&task_id, &collect_id),
            )
            .await
            .map_err(dap_err)?;
        Ok(res)
    }

    async fn get_pending_collect_jobs(
        &self,
    ) -> std::result::Result<Vec<(TaskId, CollectionJobId, CollectionReq)>, DapError> {
        let res: Vec<(TaskId, CollectionJobId, CollectionReq)> = self
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
        task_id: &TaskId,
        collect_id: &CollectionJobId,
        collect_resp: &Collection,
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        let durable = self.durable();
        if let PartialBatchSelector::FixedSizeByBatchId { ref batch_id } =
            collect_resp.part_batch_sel
        {
            durable
                .post(
                    BINDING_DAP_LEADER_BATCH_QUEUE,
                    DURABLE_LEADER_BATCH_QUEUE_REMOVE,
                    durable_name_task(&task_config.as_ref().version, &task_id.to_hex()),
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
                (task_id, collect_id, collect_resp),
            )
            .await
            .map_err(dap_err)?;
        Ok(())
    }

    async fn send_http_post(
        &self,
        req: DapRequest<DaphneWorkerAuth>,
    ) -> std::result::Result<DapResponse, DapError> {
        self.send_http(req, false).await
    }

    async fn send_http_put(
        &self,
        req: DapRequest<DaphneWorkerAuth>,
    ) -> std::result::Result<DapResponse, DapError> {
        self.send_http(req, true).await
    }
}

#[async_trait(?Send)]
impl<'srv> DapHelper<DaphneWorkerAuth> for DaphneWorker<'srv> {
    async fn put_helper_state_if_not_exists(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        helper_state: &DapHelperState,
    ) -> std::result::Result<bool, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        let helper_state_hex = hex::encode(helper_state.get_encoded(&task_config.as_ref().vdaf)?);
        Ok(self
            .durable()
            .with_retry()
            .post(
                BINDING_DAP_HELPER_STATE_STORE,
                DURABLE_HELPER_STATE_PUT_IF_NOT_EXISTS,
                durable_helper_state_name(&task_config.as_ref().version, task_id, agg_job_id),
                helper_state_hex,
            )
            .await
            .map_err(dap_err)?)
    }

    async fn get_helper_state(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
    ) -> std::result::Result<Option<DapHelperState>, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        // TODO(cjpatton) Figure out if retry is safe, since the request is not actually
        // idempotent. (It removes the helper's state from storage if it exists.)
        let res: Option<String> = self
            .durable()
            .with_retry()
            .get(
                BINDING_DAP_HELPER_STATE_STORE,
                DURABLE_HELPER_STATE_GET,
                durable_helper_state_name(&task_config.as_ref().version, task_id, agg_job_id),
            )
            .await
            .map_err(dap_err)?;

        match res {
            Some(helper_state_hex) => {
                let data =
                    hex::decode(helper_state_hex).map_err(|e| DapError::Fatal(e.to_string()))?;
                let helper_state = DapHelperState::get_decoded(&task_config.as_ref().vdaf, &data)?;
                Ok(Some(helper_state))
            }
            None => Ok(None),
        }
    }
}
