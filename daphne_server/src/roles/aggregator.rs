// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{borrow::Cow, time::SystemTime};

use axum::async_trait;
use daphne::{
    audit_log::{AuditLog, NoopAuditLog},
    auth::{BearerToken, BearerTokenProvider},
    error::DapAbort,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter},
    messages::{
        BatchId, BatchSelector, HpkeCiphertext, PartialBatchSelector, TaskId, Time,
        TransitionFailure,
    },
    metrics::DaphneMetrics,
    roles::{aggregator::MergeAggShareError, DapAggregator, DapReportInitializer},
    vdaf::{EarlyReportStateConsumed, EarlyReportStateInitialized},
    DapAggregateShare, DapAggregateSpan, DapBatchBucket, DapError, DapGlobalConfig, DapQueryConfig,
    DapRequest, DapSender, DapTaskConfig, DapVersion,
};
use daphne_service_utils::{
    auth::DaphneAuth,
    durable_requests::bindings::{
        self, AggregateStoreMergeReq, AggregateStoreMergeResp, LeaderBatchQueueResult,
    },
};
use futures::{future::try_join_all, StreamExt};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use crate::storage_proxy_connection::kv;

#[async_trait]
impl DapAggregator<DaphneAuth> for crate::App {
    async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_share_span: DapAggregateSpan<DapAggregateShare>,
    ) -> DapAggregateSpan<Result<(), MergeAggShareError>> {
        let task_id_hex = task_id.to_hex();
        let durable = self.durable();

        futures::stream::iter(agg_share_span)
            .map(|(bucket, (agg_share, report_metadatas))| async {
                let result = durable
                    .request(
                        bindings::AggregateStore::Merge,
                        (task_config.version, &task_id_hex, &bucket),
                    )
                    .encode_bincode(AggregateStoreMergeReq {
                        contained_reports: report_metadatas.iter().map(|(id, _)| *id).collect(),
                        agg_share_delta: agg_share,
                    })
                    .send::<AggregateStoreMergeResp>()
                    .await
                    .map_err(|e| fatal_error!(err = ?e));
                let result = match result {
                    Ok(AggregateStoreMergeResp::Ok) => Ok(()),
                    Ok(AggregateStoreMergeResp::AlreadyCollected) => {
                        Err(MergeAggShareError::AlreadyCollected)
                    }
                    Ok(AggregateStoreMergeResp::ReplaysDetected(replays)) => {
                        Err(MergeAggShareError::ReplaysDetected(replays))
                    }
                    Err(e) => Err(MergeAggShareError::Other(e)),
                };
                (bucket, (result, report_metadatas))
            })
            .buffer_unordered(usize::MAX)
            .collect()
            .await
    }

    async fn get_agg_share(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            requests.push(
                durable
                    .request(
                        bindings::AggregateStore::Get,
                        (task_config.as_ref().version, &task_id.to_hex(), &bucket),
                    )
                    .send(),
            );
        }
        let responses: Vec<DapAggregateShare> = try_join_all(requests)
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        let mut agg_share = DapAggregateShare::default();
        for agg_share_delta in responses {
            agg_share.merge(agg_share_delta)?;
        }

        Ok(agg_share)
    }

    async fn mark_collected(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            requests.push(
                durable
                    .request(
                        bindings::AggregateStore::MarkCollected,
                        (task_config.as_ref().version, &task_id.to_hex(), &bucket),
                    )
                    .send::<()>(),
            );
        }

        try_join_all(requests)
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        Ok(())
    }

    type WrappedDapTaskConfig<'a> = DapTaskConfig
    where
        Self: 'a;

    async fn unauthorized_reason(
        &self,
        task_config: &DapTaskConfig,
        req: &DapRequest<DaphneAuth>,
    ) -> Result<Option<String>, DapError> {
        let mut authorized = false;

        let Some(ref sender_auth) = req.sender_auth else {
            return Ok(Some("Missing authorization.".into()));
        };

        // If a bearer token is present, verify that it can be used to authorize the request.
        if sender_auth.bearer_token.is_some() {
            if let Some(unauthorized_reason) =
                self.bearer_token_authorized(task_config, req).await?
            {
                return Ok(Some(unauthorized_reason));
            }
            authorized = true;
        }

        // If a TLS client certificate is present, verify that it is valid and that the issuer and
        // subject are trusted.
        if let Some(ref cf_tls_client_auth) = sender_auth.cf_tls_client_auth {
            // TODO(cjpatton) Add support for TLS client authentication for non-Taskprov tasks.
            let Some(ref taskprov_config) = self.service_config.taskprov else {
                return Ok(Some(
                    "TLS client authentication is currently only supported with Taskprov.".into(),
                ));
            };

            // Check that that the certificate is valid. This is indicated by literal "SUCCESS".
            if cf_tls_client_auth.verified != "SUCCESS" {
                return Ok(Some(format!(
                    "Invalid TLS certificate ({}).",
                    cf_tls_client_auth.verified
                )));
            }

            // Resolve the trusted certificate issuers and subjects for this request.
            let sender = req.media_type.sender();
            let trusted_certs = if let (Some(DapSender::Leader), Some(ref trusted_certs)) =
                (sender, &taskprov_config.leader_auth.cf_tls_client_auth)
            {
                trusted_certs
            } else if let (Some(DapSender::Collector), Some(trusted_certs)) = (
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

            if !trusted_certs.iter().any(|trusted_cert| {
                trusted_cert.issuer == cf_tls_client_auth.issuer
                    && trusted_cert.subject == cf_tls_client_auth.subject
            }) {
                return Ok(Some(format!(
                    r#"Unexpected issuer "{}" and subject "{}"."#,
                    cf_tls_client_auth.issuer, cf_tls_client_auth.subject,
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
        &self.service_config.global
    }

    fn taskprov_vdaf_verify_key_init(&self) -> Option<&[u8; 32]> {
        self.service_config
            .taskprov
            .as_ref()
            .map(|c| &c.vdaf_verify_key_init)
    }

    fn taskprov_collector_hpke_config(&self) -> Option<&HpkeConfig> {
        self.service_config
            .taskprov
            .as_ref()
            .map(|c| &c.hpke_collector_config)
    }

    fn taskprov_opt_out_reason(
        &self,
        _task_config: &DapTaskConfig,
    ) -> Result<Option<String>, DapError> {
        // For now we always opt-in.
        Ok(None)
    }

    async fn taskprov_put(
        &self,
        req: &DapRequest<DaphneAuth>,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError> {
        let task_id = req.task_id().map_err(DapError::Abort)?;

        if self.service_config.role.is_leader() || req.taskprov.is_none() {
            self.kv()
                .put::<kv::prefix::TaskConfig>(task_id, task_config)
                .await
                .map_err(|e| fatal_error!(err = ?e))?;
        } else {
            self.kv()
                .only_cache_put::<kv::prefix::TaskConfig>(task_id, task_config)
                .await;
        }
        Ok(())
    }

    async fn get_task_config_for<'req>(
        &'req self,
        task_id: &'req TaskId,
    ) -> Result<Option<Self::WrappedDapTaskConfig<'req>>, DapError> {
        self.kv()
            .get::<kv::prefix::TaskConfig>(task_id)
            .await
            .map_err(|e| fatal_error!(err = ?e))
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

        // Check whether the request overlaps with previous requests. This is done by
        // checking the AggregateStore and seeing whether it requests for aggregate
        // shares that have already been marked collected.
        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            requests.push(
                durable
                    .request(
                        bindings::AggregateStore::CheckCollected,
                        (task_config.as_ref().version, &task_id.to_hex(), &bucket),
                    )
                    .send(),
            );
        }

        let responses: Vec<bool> = try_join_all(requests)
            .await
            .map_err(|e| fatal_error!(err = ?e))?;

        for collected in responses {
            if collected {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn batch_exists(&self, task_id: &TaskId, batch_id: &BatchId) -> Result<bool, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;

        let agg_share: DapAggregateShare = self
            .durable()
            .request(
                bindings::AggregateStore::Get,
                (
                    task_config.as_ref().version,
                    &task_id.to_hex(),
                    &DapBatchBucket::FixedSize {
                        batch_id: *batch_id,
                    },
                ),
            )
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))?;

        Ok(!agg_share.empty())
    }

    async fn current_batch(&self, task_id: &TaskId) -> Result<BatchId, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;

        if !matches!(task_config.query, DapQueryConfig::FixedSize { .. }) {
            return Err(fatal_error!(err = "query type mismatch"));
        }

        let res: LeaderBatchQueueResult = self
            .durable()
            .request(
                bindings::LeaderBatchQueue::Current,
                (task_config.as_ref().version, &task_id.to_hex()),
            )
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))?;

        match res {
            LeaderBatchQueueResult::Ok(batch_id) => Ok(batch_id),

            // TODO Return 400 Bad Request (with problem detail "empty batch queue") here instead
            // 500 Internal Error
            LeaderBatchQueueResult::EmptyQueue => Err(fatal_error!(err = "empty batch queue")),
        }
    }

    fn metrics(&self) -> &DaphneMetrics {
        &self.metrics.daphne
    }

    fn audit_log(&self) -> &dyn AuditLog {
        &NoopAuditLog
    }

    fn host(&self) -> &str {
        &self.service_config.env
    }
}

#[async_trait]
impl DapReportInitializer for crate::App {
    async fn initialize_reports<'req>(
        &self,
        is_leader: bool,
        _task_id: &TaskId,
        task_config: &DapTaskConfig,
        _part_batch_sel: &PartialBatchSelector,
        consumed_reports: Vec<EarlyReportStateConsumed>,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        tokio::task::spawn_blocking({
            let vdaf_config = task_config.vdaf.clone();
            let vdaf_verify_key = task_config.vdaf_verify_key.clone();
            move || {
                consumed_reports
                    .into_par_iter()
                    .map(|consumed_report| {
                        EarlyReportStateInitialized::initialize(
                            is_leader,
                            &vdaf_verify_key,
                            &vdaf_config,
                            consumed_report,
                        )
                    })
                    .collect::<Result<Vec<EarlyReportStateInitialized>, _>>()
            }
        })
        .await
        .map_err(|e| fatal_error!(err = ?e, "initialzing reports panicked"))?
    }
}

#[async_trait]
impl HpkeDecrypter for crate::App {
    type WrappedHpkeConfig<'a> = HpkeConfig
    where
        Self: 'a;

    async fn get_hpke_config_for<'s>(
        &'s self,
        version: DapVersion,
        _task_id: Option<&TaskId>,
    ) -> Result<Self::WrappedHpkeConfig<'s>, DapError> {
        self.kv()
            .get_mapped::<kv::prefix::HpkeReceiverConfigSet, _, _>(&version, |config_list| {
                // Assume the first HPKE config in the receiver list has the highest preference.
                //
                // NOTE draft02 compatibility: The spec allows us to return multiple configs, but
                // draft02 does not. In order to keep things imple we preserve the semantics of the old
                // version for now.
                config_list
                    .iter()
                    .next()
                    .map(|receiver| receiver.config.clone())
            })
            .await
            .map_err(|e| fatal_error!(err = ?e))?
            .ok_or_else(|| fatal_error!(err = "there ar eno hpke configs in kv!!", %version))
    }

    async fn can_hpke_decrypt(&self, task_id: &TaskId, config_id: u8) -> Result<bool, DapError> {
        let version = self
            .get_task_config_for(task_id)
            .await
            .map_err(|e| fatal_error!(err = ?e))?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?
            .version;

        Ok(self
            .kv()
            .get_mapped::<kv::prefix::HpkeReceiverConfigSet, _, _>(&version, |config_list| {
                config_list
                    .iter()
                    .find(|r| r.config.id == config_id)
                    .map(|_| ())
            })
            .await
            .map_err(|e| fatal_error!(err = ?e))?
            .is_some())
    }

    async fn hpke_decrypt(
        &self,
        task_id: &TaskId,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        let version = self
            .get_task_config_for(task_id)
            .await?
            .as_ref()
            .ok_or(DapAbort::UnrecognizedTask)?
            .version;
        self.kv()
            .get_mapped::<kv::prefix::HpkeReceiverConfigSet, _, _>(&version, |config_list| {
                config_list
                    .iter()
                    .find(|receiver| receiver.config.id == ciphertext.config_id)
                    .map(|receiver| {
                        receiver.decrypt(info, aad, &ciphertext.enc, &ciphertext.payload)
                    })
            })
            .await
            .map_err(|e| fatal_error!(err = ?e))?
            .ok_or(DapError::Transition(TransitionFailure::HpkeUnknownConfigId))?
    }
}

#[async_trait]
impl BearerTokenProvider for crate::App {
    type WrappedBearerToken<'a> = Cow<'a,  BearerToken>
        where Self: 'a;

    async fn get_leader_bearer_token_for<'s>(
        &'s self,
        task_id: &'s TaskId,
        task_config: &DapTaskConfig,
    ) -> std::result::Result<Option<Self::WrappedBearerToken<'s>>, DapError> {
        if self.service_config.global.allow_taskprov && task_config.method_is_taskprov() {
            if let Some(bearer_token) = self
                .service_config
                .taskprov
                .as_ref()
                .and_then(|c| c.leader_auth.bearer_token.as_ref())
            {
                return Ok(Some(Cow::Borrowed(bearer_token)));
            }
        }

        self.kv()
            .get_mapped::<kv::prefix::LeaderBearerToken, _, _>(task_id, |t| {
                Some(Cow::Owned(t.to_owned()))
            })
            .await
            .map_err(|e| fatal_error!(err = ?e))
    }

    async fn get_collector_bearer_token_for<'s>(
        &'s self,
        task_id: &'s TaskId,
        task_config: &DapTaskConfig,
    ) -> std::result::Result<Option<Self::WrappedBearerToken<'s>>, DapError> {
        if self.service_config.global.allow_taskprov && task_config.method_is_taskprov() {
            if let Some(bearer_token) = self.service_config.taskprov.as_ref().and_then(|c| {
                c.collector_auth
                    .as_ref()
                    .expect("collector auth method not set")
                    .bearer_token
                    .as_ref()
            }) {
                return Ok(Some(Cow::Borrowed(bearer_token)));
            }
        }

        self.kv()
            .get_mapped::<kv::prefix::CollectorBearerToken, _, _>(task_id, |t| {
                Some(Cow::Owned(t.to_owned()))
            })
            .await
            .map_err(|e| fatal_error!(err = ?e))
    }
}
