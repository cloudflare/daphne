// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of common requirments for both helpers and leaders

use crate::{
    auth::DaphneWorkerAuth,
    config::{DapTaskConfigKvPair, DaphneWorker},
    durable::{
        aggregate_store::{
            AggregateStoreMergeReq, DURABLE_AGGREGATE_STORE_CHECK_COLLECTED,
            DURABLE_AGGREGATE_STORE_GET, DURABLE_AGGREGATE_STORE_MARK_COLLECTED,
            DURABLE_AGGREGATE_STORE_MERGE,
        },
        durable_name_agg_store,
        reports_processed::DURABLE_REPORTS_PROCESSED_INITIALIZED,
        BINDING_DAP_AGGREGATE_STORE, BINDING_DAP_REPORTS_PROCESSED,
    },
    now,
};
use async_trait::async_trait;
use daphne::{
    audit_log::AuditLog,
    auth::BearerTokenProvider,
    fatal_error,
    hpke::HpkeConfig,
    messages::{BatchId, BatchSelector, PartialBatchSelector, ReportId, TaskId, TransitionFailure},
    metrics::DaphneMetrics,
    roles::{DapAggregator, DapReportInitializer},
    vdaf::{EarlyReportState, EarlyReportStateConsumed, EarlyReportStateInitialized},
    DapAggregateShare, DapAggregateSpan, DapBatchBucket, DapError, DapGlobalConfig, DapRequest,
    DapSender, DapTaskConfig,
};
use futures::{future::try_join_all, StreamExt, TryFutureExt, TryStreamExt};
use std::collections::{HashMap, HashSet};

#[async_trait(?Send)]
impl DapReportInitializer for DaphneWorker<'_> {
    async fn initialize_reports<'req>(
        &self,
        is_leader: bool,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        consumed_reports: Vec<EarlyReportStateConsumed<'req>>,
    ) -> Result<Vec<EarlyReportStateInitialized<'req>>, DapError> {
        let durable = self.durable();
        let span = task_config
            .as_ref()
            .batch_span_for_meta(part_batch_sel, consumed_reports.iter())?;
        let mut reports_processed_request_data = HashMap::new();
        let collected_reports = {
            let task_id_hex = task_id.to_hex();

            let mut agg_store_request_names = Vec::new();
            for (bucket, ((), report_ids_and_time)) in span.iter() {
                for (id, time) in report_ids_and_time {
                    let durable_name = self.config().durable_name_report_store(
                        task_config.as_ref(),
                        &task_id_hex,
                        id,
                        *time,
                    );

                    reports_processed_request_data
                        .entry(durable_name)
                        .or_insert_with(Vec::new)
                        .push(id);
                }
                agg_store_request_names.push((
                    bucket,
                    durable_name_agg_store(task_config.version, &task_id_hex, bucket),
                ));
            }

            // Send AggregateStore requests.
            futures::stream::iter(agg_store_request_names)
                .map(|(bucket, durable_name)| {
                    durable
                        .get(
                            BINDING_DAP_AGGREGATE_STORE,
                            DURABLE_AGGREGATE_STORE_CHECK_COLLECTED,
                            durable_name,
                        )
                        .map_ok(move |collected| (bucket, collected))
                })
                .buffer_unordered(usize::MAX)
                .try_collect::<HashMap<&DapBatchBucket, bool>>()
                .map_err(|e| fatal_error!(err = ?e, "failed to check collected"))
                .await?
        };

        let min_time = self.least_valid_report_time(self.get_current_time());
        let max_time = self.greatest_valid_report_time(self.get_current_time());

        let mut initialized_reports = consumed_reports
            .into_iter()
            .map(|consumed_report| {
                let metadata = consumed_report.metadata();

                let initialized = if metadata.time < min_time {
                    consumed_report
                        .into_initialized_rejected_due_to(TransitionFailure::ReportDropped)
                } else if metadata.time > max_time {
                    consumed_report
                        .into_initialized_rejected_due_to(TransitionFailure::ReportTooEarly)
                } else if collected_reports
                    [&task_config.bucket_for(part_batch_sel, &consumed_report)]
                {
                    consumed_report
                        .into_initialized_rejected_due_to(TransitionFailure::BatchCollected)
                } else {
                    EarlyReportStateInitialized::initialize(
                        is_leader,
                        &task_config.vdaf_verify_key,
                        &task_config.vdaf,
                        consumed_report,
                    )?
                };

                Ok(initialized)
            })
            .collect::<Result<Vec<_>, DapError>>()
            .map_err(|e| fatal_error!(err = ?e, "failed to initialize a report"))?;

        let replayed_reports_check = futures::stream::iter(reports_processed_request_data)
            .map(|(durable_name, reports)| async {
                durable
                    .post::<_, HashSet<ReportId>>(
                        BINDING_DAP_REPORTS_PROCESSED,
                        DURABLE_REPORTS_PROCESSED_INITIALIZED,
                        durable_name,
                        reports,
                    )
                    .await
            })
            .buffer_unordered(usize::MAX)
            .try_fold(HashSet::new(), |mut acc, replays| async {
                acc.extend(replays);
                Ok(acc)
            })
            .await
            .map_err(|e| fatal_error!(err = ?e, "checking for replayed reports"))?;

        for rep in &mut initialized_reports {
            if replayed_reports_check.contains(&rep.metadata().id) {
                rep.reject_due_to(TransitionFailure::ReportReplayed);
            }
        }

        Ok(initialized_reports)
    }
}

#[async_trait(?Send)]
impl<'srv> DapAggregator<DaphneWorkerAuth> for DaphneWorker<'srv> {
    type WrappedDapTaskConfig<'a> = DapTaskConfigKvPair<'a>
        where Self: 'a;

    async fn unauthorized_reason(
        &self,
        task_config: &DapTaskConfig,
        req: &DapRequest<DaphneWorkerAuth>,
    ) -> std::result::Result<Option<String>, DapError> {
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
            .ok_or_else(|| fatal_error!(err = "taskprov configuration not found"))?;

        // If `resolve_advertised_task_config()` returned a `TaskConfig` and `req.taskprov` is set,
        // then the task was advertised in the HTTP "dap-taskprov" header. In this case we expect
        // the peer to send the header in every request for this task.
        //
        // NOTE(cjpatton) This behavior is not specified in taskprov-02, but we expect it to be
        // mandatory in a future draft.
        if !self.config().is_leader && req.taskprov.is_some() {
            // Store the task config in Worker memory, but don't write it through to KV.
            let mut guarded_tasks = self
                .isolate_state()
                .tasks
                .write()
                .map_err(|e| fatal_error!(err = ?e, "failed to lock tasks for writing"))?;
            guarded_tasks.insert(*task_id, task_config);

            if let Some(ref leader_bearer_token) = taskprov.leader_auth.bearer_token {
                let mut guarded_leader_bearer_tokens = self
                    .isolate_state()
                    .leader_bearer_tokens
                    .write()
                    .map_err(|e| {
                        fatal_error!(err = ?e, "failed to lock leader_bearer_tokens for writing")
                    })?;
                guarded_leader_bearer_tokens.insert(*task_id, leader_bearer_token.clone());
            }
        } else {
            // Write the task config through to KV.
            self.set_task_config(task_id, &task_config)
                .await
                .map_err(|e| fatal_error!(err = ?e))?;

            if let Some(ref leader_bearer_token) = taskprov.leader_auth.bearer_token {
                self.set_leader_bearer_token(task_id, leader_bearer_token)
                    .await
                    .map_err(|e| fatal_error!(err = ?e))?;
            }
        }

        Ok(())
    }

    async fn get_task_config_for<'req>(
        &'req self,
        task_id: &'req TaskId,
    ) -> std::result::Result<Option<Self::WrappedDapTaskConfig<'req>>, DapError> {
        self.get_task_config(task_id)
            .await
            .map_err(|e| fatal_error!(err = ?e))
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
                durable_name_agg_store(task_config.as_ref().version, &task_id.to_hex(), &bucket);
            requests.push(durable.get(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_CHECK_COLLECTED,
                durable_name,
            ));
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
                    task_config.as_ref().version,
                    &task_id.to_hex(),
                    &DapBatchBucket::FixedSize {
                        batch_id: *batch_id,
                    },
                ),
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?;

        Ok(!agg_share.empty())
    }

    async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_share_span: DapAggregateSpan<DapAggregateShare>,
    ) -> DapAggregateSpan<Result<HashSet<ReportId>, DapError>> {
        let task_id_hex = task_id.to_hex();
        let durable = self.durable().with_retry();

        futures::stream::iter(agg_share_span)
            .map(|(bucket, (agg_share, report_metadatas))| async {
                let agg_store_name =
                    durable_name_agg_store(task_config.version, &task_id_hex, &bucket);
                let result = durable
                    .post::<_, HashSet<ReportId>>(
                        BINDING_DAP_AGGREGATE_STORE,
                        DURABLE_AGGREGATE_STORE_MERGE,
                        agg_store_name,
                        AggregateStoreMergeReq {
                            contained_reports: report_metadatas.iter().map(|(id, _)| *id).collect(),
                            agg_share_delta: agg_share,
                        },
                    )
                    .await
                    .map_err(|e| fatal_error!(err = ?e));
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
    ) -> std::result::Result<DapAggregateShare, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;

        let durable = self.durable().with_retry();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            let durable_name =
                durable_name_agg_store(task_config.as_ref().version, &task_id.to_hex(), &bucket);
            requests.push(durable.get(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_GET,
                durable_name,
            ));
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
    ) -> std::result::Result<(), DapError> {
        let task_config = self.try_get_task_config(task_id).await?;

        let durable = self.durable();
        let mut requests = Vec::new();
        for bucket in task_config.as_ref().batch_span_for_sel(batch_sel)? {
            let durable_name =
                durable_name_agg_store(task_config.as_ref().version, &task_id.to_hex(), &bucket);
            requests.push(durable.post::<_, ()>(
                BINDING_DAP_AGGREGATE_STORE,
                DURABLE_AGGREGATE_STORE_MARK_COLLECTED,
                durable_name,
                &(),
            ));
        }

        try_join_all(requests)
            .await
            .map_err(|e| fatal_error!(err = ?e))?;
        Ok(())
    }

    async fn current_batch(&self, task_id: &TaskId) -> std::result::Result<BatchId, DapError> {
        self.internal_current_batch(task_id).await
    }

    fn metrics(&self) -> &DaphneMetrics {
        &self.state.metrics.daphne
    }

    fn audit_log(&self) -> &dyn AuditLog {
        self.state.audit_log
    }
}
