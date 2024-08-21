// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{borrow::Cow, future::ready, num::NonZeroUsize, ops::Range, time::SystemTime};

use axum::async_trait;
use daphne::{
    audit_log::AuditLog,
    auth::{BearerToken, BearerTokenProvider},
    error::DapAbort,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter, HpkeProvider},
    messages::{self, BatchId, BatchSelector, HpkeCiphertext, TaskId, Time, TransitionFailure},
    metrics::DaphneMetrics,
    roles::{aggregator::MergeAggShareError, DapAggregator, DapReportInitializer},
    taskprov, DapAggregateShare, DapAggregateSpan, DapAggregationParam, DapError, DapGlobalConfig,
    DapRequest, DapTaskConfig, DapVersion, EarlyReportStateConsumed, EarlyReportStateInitialized,
};
use daphne_service_utils::{
    auth::DaphneAuth,
    durable_requests::bindings::{
        self, AggregateStoreMergeOptions, AggregateStoreMergeReq, AggregateStoreMergeResp,
    },
};
use futures::{future::try_join_all, StreamExt, TryStreamExt};
use mappable_rc::Marc;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use crate::{
    roles::fetch_replay_protection_override,
    storage_proxy_connection::kv::{self, KvGetOptions},
};

#[async_trait]
impl DapAggregator<DaphneAuth> for crate::App {
    #[tracing::instrument(skip(self, task_config, agg_share_span))]
    async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_share_span: DapAggregateSpan<DapAggregateShare>,
    ) -> DapAggregateSpan<Result<(), MergeAggShareError>> {
        let task_id_hex = task_id.to_hex();
        let durable = self.durable();

        let replay_protection = fetch_replay_protection_override(self.kv()).await;

        futures::stream::iter(agg_share_span)
            .map(|(bucket, (agg_share, report_metadatas))| async {
                let result = durable
                    .request(
                        bindings::AggregateStore::Merge,
                        (task_config.version, &task_id_hex, &bucket),
                    )
                    .encode(&AggregateStoreMergeReq {
                        contained_reports: report_metadatas.iter().map(|(id, _)| *id).collect(),
                        agg_share_delta: agg_share,
                        options: AggregateStoreMergeOptions {
                            skip_replay_protection: replay_protection.disabled(),
                        },
                    })
                    .send::<AggregateStoreMergeResp>()
                    .await
                    .map_err(|e| fatal_error!(err = ?e, "failed to merge aggregate share"));
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

    #[tracing::instrument(skip(self))]
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
            .map_err(|e| fatal_error!(err = ?e, "failed to get agg shares from durable objects"))?;
        let mut agg_share = DapAggregateShare::default();
        for agg_share_delta in responses {
            agg_share.merge(agg_share_delta)?;
        }

        Ok(agg_share)
    }

    #[tracing::instrument(skip(self))]
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
            .map_err(|e| fatal_error!(err = ?e, "failed to mark agg shares as collected"))?;
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

        // If a TLS client certificate is present verify that it is valid.
        if let Some(ref cf_tls_client_auth) = sender_auth.cf_tls_client_auth {
            // TODO(cjpatton) Add support for TLS client authentication for non-Taskprov tasks.
            let Some(ref _taskprov_config) = self.service_config.taskprov else {
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

            authorized = true;
        }

        if authorized {
            Ok(None)
        } else {
            Ok(Some("No suitable authorization method was found.".into()))
        }
    }

    async fn get_global_config(&self) -> Result<DapGlobalConfig, DapError> {
        let mut global_config = self.service_config.global.clone();

        // Check KV for overrides to the global configuration.
        let opt = KvGetOptions {
            // If an override is not found, then don't try again until the cache line expires.
            cache_not_found: true,
        };

        // "global_config/override/default_num_agg_span_shards"
        if let Some(default_num_agg_span_shards) = self
            .kv()
            .get_cloned::<kv::prefix::GlobalConfigOverride<NonZeroUsize>>(
                &kv::prefix::GlobalOverrides::DefaultNumAggSpanShards,
                &opt,
            )
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get global override for the default_num_agg_span_shards"))?
        {
            global_config.default_num_agg_span_shards = default_num_agg_span_shards;
        }

        Ok(global_config)
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

    async fn taskprov_opt_in(
        &self,
        task_id: &TaskId,
        task_config: taskprov::DapTaskConfigNeedsOptIn,
        global_config: &DapGlobalConfig,
    ) -> Result<DapTaskConfig, DapError> {
        if let Some(param) = self
            .kv()
            .get_cloned::<kv::prefix::TaskprovOptInParam>(task_id, &KvGetOptions::default())
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get TaskprovOptInParam from kv"))?
        {
            Ok(task_config.into_opted_in(&param))
        } else {
            let param = taskprov::OptInParam {
                not_before: self.get_current_time(),
                num_agg_span_shards: global_config.default_num_agg_span_shards,
            };

            let task_config = task_config.into_opted_in(&param);
            let expiration_time = task_config.not_after;

            if let Err(e) = self
                .kv()
                .put_with_expiration::<kv::prefix::TaskprovOptInParam>(
                    task_id,
                    param,
                    expiration_time,
                )
                .await
            {
                tracing::warn!(error = ?e, "failed to store taskprov opt in param");
            }

            Ok(task_config)
        }
    }

    async fn taskprov_put(
        &self,
        req: &DapRequest<DaphneAuth>,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError> {
        let task_id = req.task_id().map_err(DapError::Abort)?;
        let expiration_time = task_config.not_after;

        if self.service_config.role.is_leader() || req.taskprov.is_none() {
            self.kv()
                .put_with_expiration::<kv::prefix::TaskConfig>(
                    task_id,
                    task_config,
                    expiration_time,
                )
                .await
                .map_err(|e| fatal_error!(err = ?e, "failed to put the a task config in kv"))?;
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
            .get_cloned::<kv::prefix::TaskConfig>(task_id, &KvGetOptions::default())
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get a task config from kv: {task_id}"))
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
        Ok(
            futures::stream::iter(task_config.batch_span_for_sel(batch_sel)?)
                .map(|bucket| {
                    durable
                        .request(
                            bindings::AggregateStore::CheckCollected,
                            (task_config.as_ref().version, &task_id.to_hex(), &bucket),
                        )
                        .send()
                })
                .buffer_unordered(usize::MAX)
                .try_any(ready)
                .await
                .map_err(
                    |e| fatal_error!(err = ?e, "failed to check if agg shares are collected"),
                )?,
        )
    }

    async fn batch_exists(&self, task_id: &TaskId, batch_id: &BatchId) -> Result<bool, DapError> {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;
        let version = task_config.as_ref().version;

        let agg_span = task_config.batch_span_for_sel(&BatchSelector::FixedSizeByBatchId {
            batch_id: *batch_id,
        })?;

        futures::stream::iter(agg_span)
            .map(|bucket| async move {
                Ok::<bool, DapError>(
                    !self
                        .durable()
                        .request(
                            bindings::AggregateStore::Get,
                            (version, &task_id.to_hex(), &bucket),
                        )
                        .send::<DapAggregateShare>()
                        .await
                        .map_err(|e| fatal_error!(err = ?e, "failed to get an agg share"))?
                        .empty(),
                )
            })
            .buffer_unordered(usize::MAX)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .reduce(|a, b| Ok(a? || b?))
            .unwrap_or(Ok(false))
    }

    fn metrics(&self) -> &dyn DaphneMetrics {
        self.metrics.daphne()
    }

    fn audit_log(&self) -> &dyn AuditLog {
        &*self.audit_log
    }
}

#[async_trait]
impl DapReportInitializer for crate::App {
    fn valid_report_time_range(&self) -> Range<messages::Time> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("now should always be after unix epoch")
            .as_secs();

        let start = now.saturating_sub(self.service_config.report_storage_epoch_duration);
        let end = now.saturating_add(self.service_config.report_storage_max_future_time_skew);

        start..end
    }

    #[tracing::instrument(skip(self, task_config, agg_param, consumed_reports))]
    async fn initialize_reports(
        &self,
        is_leader: bool,
        task_config: &DapTaskConfig,
        agg_param: &DapAggregationParam,
        consumed_reports: Vec<EarlyReportStateConsumed>,
    ) -> Result<Vec<EarlyReportStateInitialized>, DapError> {
        tokio::task::spawn_blocking({
            let vdaf_config = task_config.vdaf;
            let vdaf_verify_key = task_config.vdaf_verify_key.clone();
            let agg_param = agg_param.clone();
            move || {
                consumed_reports
                    .into_par_iter()
                    .map(|consumed_report| {
                        EarlyReportStateInitialized::initialize(
                            is_leader,
                            &vdaf_verify_key,
                            &vdaf_config,
                            &agg_param,
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
impl HpkeProvider for crate::App {
    type WrappedHpkeConfig<'s> = Marc<HpkeConfig>;

    async fn get_hpke_config_for<'s>(
        &'s self,
        version: DapVersion,
        _task_id: Option<&TaskId>,
    ) -> Result<Self::WrappedHpkeConfig<'static>, DapError> {
        self.kv()
            .get_mapped::<kv::prefix::HpkeReceiverConfigSet, _, _>(
                &version,
                &KvGetOptions::default(),
                |config_list| {
                    // Assume the first HPKE config in the receiver list has the highest preference.
                    //
                    // TODO draft02 cleanup: Return the entire list and not just a single HPKE config.
                    // Note that we previously returned one because this was required in draft02.
                    config_list.iter().next().map(|hpke| &hpke.config)
                },
            )
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get the hpke config"))?
            .ok_or_else(|| fatal_error!(err = "there are no hpke configs in kv!!", %version))
    }

    async fn can_hpke_decrypt(&self, task_id: &TaskId, config_id: u8) -> Result<bool, DapError> {
        let version = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?
            .version;

        Ok(self
            .kv()
            .peek::<kv::prefix::HpkeReceiverConfigSet, _, _>(
                &version,
                &KvGetOptions::default(),
                |config_list| config_list.iter().any(|r| r.config.id == config_id),
            )
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get at the hpke config"))?
            .unwrap_or(false))
    }
}

#[async_trait]
impl HpkeDecrypter for crate::App {
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
            .peek::<kv::prefix::HpkeReceiverConfigSet, _, _>(
                &version,
                &KvGetOptions::default(),
                |config_list| {
                    config_list
                        .iter()
                        .find(|receiver| receiver.config.id == ciphertext.config_id)
                        .map(|receiver| receiver.decrypt(info, aad, ciphertext))
                },
            )
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get the hpke config"))?
            .flatten()
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
            .get_cloned::<kv::prefix::LeaderBearerToken>(task_id, &KvGetOptions::default())
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get the leader bearer token"))
            .map(|r| r.map(Cow::Owned))
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
            .get_cloned::<kv::prefix::CollectorBearerToken>(task_id, &KvGetOptions::default())
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get the collector bearer token"))
            .map(|r| r.map(Cow::Owned))
    }
}
