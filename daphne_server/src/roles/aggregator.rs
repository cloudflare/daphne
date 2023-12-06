// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(unused_variables)]

use std::time::SystemTime;

use axum::async_trait;
use daphne::{
    audit_log::{AuditLog, NoopAuditLog},
    hpke::{HpkeConfig, HpkeDecrypter},
    messages::{BatchId, BatchSelector, HpkeCiphertext, PartialBatchSelector, TaskId, Time},
    metrics::DaphneMetrics,
    roles::{aggregator::MergeAggShareError, DapAggregator, DapReportInitializer},
    vdaf::{EarlyReportStateConsumed, EarlyReportStateInitialized},
    DapAggregateShare, DapAggregateSpan, DapError, DapGlobalConfig, DapRequest, DapTaskConfig,
    DapVersion,
};

#[async_trait]
impl<S: Sync> DapAggregator<S> for crate::App {
    async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_share_span: DapAggregateSpan<DapAggregateShare>,
    ) -> DapAggregateSpan<Result<(), MergeAggShareError>> {
        let r = self
            .worker
            .durable_objects()
            .try_put_agg_share_span(task_id, task_config, &agg_share_span)
            .await;

        match r {
            Ok(span) => span,
            Err(e) => todo!(),
        }
    }

    async fn get_agg_share(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError> {
        self.worker
            .durable_objects()
            .get_agg_share(task_id, batch_sel)
            .await
    }

    async fn mark_collected(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError> {
        self.worker
            .durable_objects()
            .mark_collected(task_id, batch_sel)
            .await
    }

    type WrappedDapTaskConfig<'a> = DapTaskConfig
    where
        Self: 'a;

    async fn unauthorized_reason(
        &self,
        task_config: &DapTaskConfig,
        req: &DapRequest<S>,
    ) -> Result<Option<String>, DapError> {
        todo!()
    }

    fn get_global_config(&self) -> &DapGlobalConfig {
        &self.global_config
    }

    fn taskprov_vdaf_verify_key_init(&self) -> Option<&[u8; 32]> {
        todo!()
    }

    fn taskprov_collector_hpke_config(&self) -> Option<&HpkeConfig> {
        todo!()
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
        req: &DapRequest<S>,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError> {
        todo!()
    }

    async fn get_task_config_for<'req>(
        &'req self,
        task_id: &'req TaskId,
    ) -> Result<Option<Self::WrappedDapTaskConfig<'req>>, DapError> {
        todo!()
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
        self.worker
            .durable_objects()
            .is_batch_overlapping(task_id, batch_sel)
            .await
    }

    async fn batch_exists(&self, task_id: &TaskId, batch_id: &BatchId) -> Result<bool, DapError> {
        todo!()
    }

    async fn current_batch(&self, task_id: &TaskId) -> Result<BatchId, DapError> {
        todo!()
    }

    fn metrics(&self) -> &DaphneMetrics {
        &self.metrics.daphne
    }

    fn audit_log(&self) -> &dyn AuditLog {
        &NoopAuditLog
    }

    fn host(&self) -> &str {
        todo!()
    }
}

#[async_trait]
impl DapReportInitializer for crate::App {
    async fn initialize_reports<'req>(
        &self,
        is_leader: bool,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        consumed_reports: Vec<EarlyReportStateConsumed<'req>>,
    ) -> Result<Vec<EarlyReportStateInitialized<'req>>, DapError> {
        todo!()
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
        task_id: Option<&TaskId>,
    ) -> Result<Self::WrappedHpkeConfig<'s>, DapError> {
        todo!()
    }

    async fn can_hpke_decrypt(&self, task_id: &TaskId, config_id: u8) -> Result<bool, DapError> {
        todo!()
    }

    async fn hpke_decrypt(
        &self,
        task_id: &TaskId,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, DapError> {
        todo!()
    }
}
