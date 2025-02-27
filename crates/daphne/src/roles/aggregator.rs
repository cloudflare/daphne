// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashSet, ops::Range};

use async_trait::async_trait;
use prio::codec::Encode;

use crate::{
    audit_log::AuditLog,
    constants::DapMediaType,
    error::DapAbort,
    hpke::{HpkeConfig, HpkeProvider},
    messages::{BatchId, BatchSelector, HpkeConfigList, ReportId, TaskId, Time},
    metrics::{DaphneMetrics, DaphneRequestType},
    taskprov, DapAggregateShare, DapAggregateSpan, DapError, DapGlobalConfig, DapResponse,
    DapTaskConfig, DapVersion,
};

#[derive(Debug)]
pub enum MergeAggShareError {
    AlreadyCollected,
    ReplaysDetected(HashSet<ReportId>),
    Other(DapError),
}

pub struct TaskprovConfig<'s> {
    /// HPKE collector configuration for all taskprov tasks.
    pub hpke_collector_config: &'s HpkeConfig,

    /// VDAF verify key init secret, used to generate the VDAF verification key for a taskprov task.
    pub vdaf_verify_key_init: &'s [u8; 32],
}

/// DAP Aggregator functionality.
#[async_trait]
pub trait DapAggregator: HpkeProvider + Sized {
    /// Look up the DAP global configuration.
    async fn get_global_config(&self) -> Result<DapGlobalConfig, DapError>;

    /// Get the taskprov configuration. This method also controls whether taskprov is enabled.
    /// Returning [`None`] disables taskprov.
    fn get_taskprov_config(&self) -> Option<TaskprovConfig<'_>>;

    /// taskprov: Complete the opt-in process.
    ///
    /// # Notes
    ///
    /// - Changing the number of aggregate spans for a task is not safe; see [`DapGlobalConfig`]
    /// for details. Implementers should ensure this parameter doesn't change over the lifetime of
    /// the task.
    ///
    /// - If you'd like your implementation to opt-out, then return
    /// `Err(DapError::Abort(DapAbort::InvalidTask{..}))`.
    async fn taskprov_opt_in(
        &self,
        task_id: &TaskId,
        task_config: taskprov::DapTaskConfigNeedsOptIn,
    ) -> Result<DapTaskConfig, DapError>;

    /// taskprov: Configure a task. This is called after opting in. If successful, the next call to
    /// `get_task_config_for()` will return the configure task. Otherwise this call will return
    /// nothing.
    async fn taskprov_put(
        &self,
        task_id: &TaskId,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError>;

    /// Look up the DAP task configuration for the given task ID.
    async fn get_task_config_for<'req>(
        &'req self,
        task_id: &'req TaskId,
    ) -> Result<Option<DapTaskConfig>, DapError>;

    /// Get the current time (number of seconds since the beginning of UNIX time).
    fn get_current_time(&self) -> Time;

    /// Check whether the batch determined by the collect request would overlap with a previously
    /// collected batch.
    async fn is_batch_overlapping(
        &self,
        version: DapVersion,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<bool, DapError>;

    /// Check whether the given batch ID has been observed before. This is called by the Leader
    /// (resp. Helper) in response to a CollectReq (resp. AggregateShareReq) for leader-selected tasks.
    async fn batch_exists(
        &self,
        version: DapVersion,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<bool, DapError>;

    /// Store a set of output shares and mark the corresponding reports as aggregated.
    ///
    /// If any report within a bucket has already been aggregated (is a replay) then that entire
    /// bucket must be skipped without changing any state, such that this operation is idempotent.
    ///
    /// # Returns
    ///
    /// A span with the same buckets as the input `agg_share_span` where the value is one of 3
    /// possible sets of values:
    /// - `Ok(())` if all went well and no reports were replays.
    /// - `Err(MergeAggShareError::ReplaysDetected)` if at least one report was a replay. This also
    ///                                              means no aggregate shares where merged.
    /// - `Err(MergeAggShareError::AlreadyCollected)` This span belong to an aggregate share that
    ///                                               has been collected.
    /// - `Err(MergeAggShareError::Other)` if another unrecoverable error occurred.
    async fn try_put_agg_share_span(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        agg_share_span: DapAggregateSpan<DapAggregateShare>,
    ) -> DapAggregateSpan<Result<(), MergeAggShareError>>;

    /// Fetch the aggregate share for the given batch.
    async fn get_agg_share(
        &self,
        version: DapVersion,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError>;

    /// Mark a batch as collected.
    async fn mark_collected(
        &self,
        version: DapVersion,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError>;

    /// Access the Prometheus metrics.
    fn metrics(&self) -> &dyn DaphneMetrics;

    /// Access the audit log.
    fn audit_log(&self) -> &dyn AuditLog;

    /// Return the time range in which a report must appear in order to be considered valid.
    fn valid_report_time_range(&self) -> Range<Time>;
}

/// Handle request for the Aggregator's HPKE configuration.
pub async fn handle_hpke_config_req<A>(
    aggregator: &A,
    version: DapVersion,
    task_id: Option<TaskId>,
) -> Result<DapResponse, DapError>
where
    A: DapAggregator,
{
    let metrics = aggregator.metrics();

    if version == DapVersion::Latest && task_id.is_some() {
        return Err(DapAbort::BadRequest(
            "Task ID may not be specified in draft 12 or later".to_string(),
        )
        .into());
    }

    let hpke_config = aggregator
        .get_hpke_config_for(version, task_id.as_ref())
        .await?;

    if let Some(task_id) = task_id {
        let task_config = aggregator
            .get_task_config_for(&task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask { task_id })?;

        // Check whether the DAP version in the request matches the task config.
        if task_config.as_ref().version != version {
            return Err(DapAbort::version_mismatch(version, task_config.as_ref().version).into());
        }
    }

    let payload = {
        let hpke_config_list = HpkeConfigList {
            hpke_configs: vec![hpke_config.clone()],
        };
        hpke_config_list.get_encoded().map_err(DapError::encoding)?
    };

    metrics.inbound_req_inc(DaphneRequestType::HpkeConfig);
    Ok(DapResponse {
        version,
        media_type: DapMediaType::HpkeConfigList,
        payload,
    })
}
