// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{future::ready, num::NonZeroUsize, ops::Range, time::SystemTime};

use axum::async_trait;
use daphne::{
    audit_log::AuditLog,
    error::DapAbort,
    fatal_error,
    hpke::{self, HpkeConfig, HpkeProvider, HpkeReceiverConfig},
    messages::{self, BatchId, BatchSelector, HpkeCiphertext, TaskId, Time},
    metrics::DaphneMetrics,
    roles::{
        aggregator::{MergeAggShareError, TaskprovConfig},
        DapAggregator, DapReportInitializer,
    },
    taskprov, DapAggregateShare, DapAggregateSpan, DapAggregationParam, DapError, DapGlobalConfig,
    DapRequestMeta, DapTaskConfig, DapVersion, EarlyReportStateConsumed,
    EarlyReportStateInitialized,
};
use daphne_service_utils::durable_requests::bindings::{
    self, AggregateStoreMergeOptions, AggregateStoreMergeReq, AggregateStoreMergeResp,
};
use futures::{future::try_join_all, StreamExt, TryFutureExt, TryStreamExt};
use mappable_rc::Marc;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use crate::{
    roles::fetch_replay_protection_override,
    storage_proxy_connection::kv::{self, KvGetOptions},
};

#[async_trait]
impl DapAggregator for crate::App {
    #[tracing::instrument(skip(self, task_config, agg_share_span))]
    async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_share_span: DapAggregateSpan<DapAggregateShare>,
    ) -> DapAggregateSpan<Result<(), MergeAggShareError>> {
        let durable = self.durable();

        let replay_protection = fetch_replay_protection_override(self.kv()).await;

        futures::stream::iter(agg_share_span)
            .map(|(bucket, (agg_share, report_metadatas))| async {
                let result = durable
                    .request(
                        bindings::AggregateStore::Merge,
                        (task_config.version, task_id, &bucket),
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
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: *task_id,
            }))?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            requests.push(
                durable
                    .request(
                        bindings::AggregateStore::Get,
                        (task_config.as_ref().version, task_id, &bucket),
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
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: *task_id,
            }))?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            requests.push(
                durable
                    .request(
                        bindings::AggregateStore::MarkCollected,
                        (task_config.as_ref().version, task_id, &bucket),
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

    fn get_taskprov_config(&self) -> Option<TaskprovConfig<'_>> {
        self.service_config
            .taskprov
            .as_ref()
            .map(|t| TaskprovConfig {
                hpke_collector_config: &t.hpke_collector_config,
                vdaf_verify_key_init: &t.vdaf_verify_key_init,
            })
    }

    async fn taskprov_opt_in(
        &self,
        task_id: &TaskId,
        task_config: taskprov::DapTaskConfigNeedsOptIn,
    ) -> Result<DapTaskConfig, DapError> {
        if let Some(param) = self
            .kv()
            .get_cloned::<kv::prefix::TaskprovOptInParam>(task_id, &KvGetOptions::default())
            .await
            .map_err(|e| fatal_error!(err = ?e, "failed to get TaskprovOptInParam from kv"))?
        {
            Ok(task_config.into_opted_in(&param))
        } else {
            let global_config = self.get_global_config().await?;
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
        req: &DapRequestMeta,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError> {
        let task_id = &req.task_id;
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
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: *task_id,
            }))?;

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
                            (task_config.as_ref().version, task_id, &bucket),
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
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: *task_id,
            }))?;
        let version = task_config.as_ref().version;

        let agg_span = task_config.batch_span_for_sel(&BatchSelector::FixedSizeByBatchId {
            batch_id: *batch_id,
        })?;

        futures::stream::iter(agg_span)
            .map(|bucket| async move {
                let durable = self.durable();
                let params = (version, task_id, &bucket);

                let get_report_count = || {
                    durable
                        .request(bindings::AggregateStore::ReportCount, params)
                        .send::<u64>()
                };

                // TODO: remove this after the worker has this feature deployed.
                let backwards_compat_get_report_count = || {
                    durable
                        .request(bindings::AggregateStore::Get, params)
                        .send::<DapAggregateShare>()
                        .map_ok(|r| r.report_count)
                };

                let count = get_report_count()
                    .or_else(|_| backwards_compat_get_report_count())
                    .await
                    .map_err(|e| {
                        fatal_error!(
                            err = ?e,
                            params = ?params,
                            "failed fetching report count of an agg share"
                        )
                    })?;
                Ok(count > 0)
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

pub struct HpkeDecrypter(Marc<Vec<HpkeReceiverConfig>>);

impl hpke::HpkeDecrypter for HpkeDecrypter {
    fn hpke_decrypt(
        &self,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        self.0.hpke_decrypt(info, aad, ciphertext)
    }
}

#[async_trait]
impl HpkeProvider for crate::App {
    type WrappedHpkeConfig<'s> = Marc<HpkeConfig>;
    type ReceiverConfigs<'s> = HpkeDecrypter;

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
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask {
                task_id: *task_id,
            }))?
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

    async fn get_receiver_configs<'s>(
        &'s self,
        version: DapVersion,
    ) -> Result<Self::ReceiverConfigs<'s>, DapError> {
        Ok(HpkeDecrypter(
            self.kv()
                .get::<kv::prefix::HpkeReceiverConfigSet>(&version, &KvGetOptions::default())
                .await
                .map_err(|e| fatal_error!(err= ?e,"failed to get the hpke config"))?
                .ok_or_else(|| fatal_error!(err="there are no hpke configs in kv!!", %version))?,
        ))
    }
}
