// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{borrow::Cow, collections::HashSet};

use async_trait::async_trait;
use prio::codec::Encode;

use crate::{
    audit_log::AuditLog,
    constants::DapMediaType,
    error::DapAbort,
    hpke::{HpkeConfig, HpkeDecrypter},
    messages::{
        decode_base64url, BatchId, BatchSelector, HpkeConfigList, PartialBatchSelector, ReportId,
        TaskId, Time,
    },
    metrics::{DaphneMetrics, DaphneRequestType},
    vdaf::{EarlyReportStateConsumed, EarlyReportStateInitialized},
    DapAggregateShare, DapError, DapGlobalConfig, DapOutputShare, DapRequest, DapResponse,
    DapTaskConfig, DapVersion,
};

/// Report initializer. Used by a DAP Aggregator [`DapAggregator`] when initializing an aggregation
/// job.
#[async_trait(?Send)]
pub trait DapReportInitializer {
    /// Initialize a sequence of reports that are in the "consumed" state by performing the early
    /// validation steps (check if the report was replayed, belongs to a batch that has been
    /// collected) and initializing VDAF preparation.
    async fn initialize_reports<'req>(
        &self,
        is_leader: bool,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        consumed_reports: Vec<EarlyReportStateConsumed<'req>>,
    ) -> Result<Vec<EarlyReportStateInitialized<'req>>, DapError>;
}

/// DAP Aggregator functionality.
#[async_trait(?Send)]
pub trait DapAggregator<S>: HpkeDecrypter + DapReportInitializer + Sized {
    /// A refernce to a task configuration stored by the Aggregator.
    type WrappedDapTaskConfig<'a>: AsRef<DapTaskConfig>;

    /// Decide whether the given DAP request is authorized.
    ///
    /// If the return value is `None`, then the request is authorized. If the return value is
    /// `Some(reason)`, then the request is denied and `reason` conveys details about how the
    /// decision was reached.
    async fn unauthorized_reason(
        &self,
        task_config: &DapTaskConfig,
        req: &DapRequest<S>,
    ) -> Result<Option<String>, DapError>;

    /// Look up the DAP global configuration.
    fn get_global_config(&self) -> &DapGlobalConfig;

    /// taskprov: The VDAF verification key initializer. Used to derive the VDAF verify key for all
    /// tasks configured by this extension.
    fn taskprov_vdaf_verify_key_init(&self) -> Option<&[u8; 32]>;

    /// taskprov: The Collector's HPKE configuration used for all tasks configured by this
    /// extension.
    fn taskprov_collector_hpke_config(&self) -> Option<&HpkeConfig>;

    /// taskprov: Decide whether to opt-in or out-out of a task provisioned via taskprov.
    ///
    /// If the return value is `None`, then the decision is to opt-in. If the return value is
    /// `Some(reason)`, then the decision is to opt-out; `reason` conveys details about how the
    /// decision was reached (e.g.., the minimum batch size is too smal).
    fn taskprov_opt_out_reason(
        &self,
        task_config: &DapTaskConfig,
    ) -> Result<Option<String>, DapError>;

    /// taskprov: Configure a task. This is called after opting in. If successful, the next call to
    /// `get_task_config_for()` will return the configure task. Otherwise this call will return
    /// nothing.
    async fn taskprov_put(
        &self,
        req: &DapRequest<S>,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError>;

    /// Look up the DAP task configuration for the given task ID.
    async fn get_task_config_for<'req>(
        &self,
        task_id: Cow<'req, TaskId>,
    ) -> Result<Option<Self::WrappedDapTaskConfig<'req>>, DapError>;

    /// Get the current time (number of seconds since the beginning of UNIX time).
    fn get_current_time(&self) -> Time;

    /// Check whether the batch determined by the collect request would overlap with a previous
    /// batch.
    async fn is_batch_overlapping(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<bool, DapError>;

    /// Check whether the given batch ID has been observed before. This is called by the Leader
    /// (resp. Helper) in response to a CollectReq (resp. AggregateShareReq) for fixed-size tasks.
    async fn batch_exists(&self, task_id: &TaskId, batch_id: &BatchId) -> Result<bool, DapError>;

    /// Store a set of output shares and mark the corresponding reports as aggregated. Any reports
    /// that were already aggregated are not committed.
    ///
    /// TODO spec: Ensure the spec allows rejecting due to replay at this stage.
    async fn put_out_shares(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        part_batch_sel: &PartialBatchSelector,
        out_shares: Vec<DapOutputShare>,
    ) -> Result<HashSet<ReportId>, DapError>;

    /// Fetch the aggregate share for the given batch.
    async fn get_agg_share(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<DapAggregateShare, DapError>;

    /// Mark a batch as collected.
    async fn mark_collected(
        &self,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
    ) -> Result<(), DapError>;

    /// Handle request for the Aggregator's HPKE configuration.
    async fn handle_hpke_config_req(&self, req: &DapRequest<S>) -> Result<DapResponse, DapAbort> {
        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::version_unknown());
        }

        let metrics = self.metrics().with_host(req.host());

        // Parse the task ID from the query string, ensuring that it is the only query parameter.
        let mut id = None;
        for (k, v) in req.url.query_pairs() {
            if k != "task_id" {
                return Err(DapAbort::BadRequest("unexpected query parameter".into()));
            }

            let bytes = decode_base64url(v.as_bytes()).ok_or(DapAbort::BadRequest(
                "failed to parse query parameter as URL-safe Base64".into(),
            ))?;

            id = Some(TaskId(bytes))
        }

        let hpke_config = self.get_hpke_config_for(req.version, id.as_ref()).await?;

        if let Some(task_id) = id {
            let task_config = self
                .get_task_config_for(Cow::Owned(task_id))
                .await?
                .ok_or(DapAbort::UnrecognizedTask)?;

            // Check whether the DAP version in the request matches the task config.
            if task_config.as_ref().version != req.version {
                return Err(DapAbort::version_mismatch(
                    req.version,
                    task_config.as_ref().version,
                ));
            }
        }

        let payload = match req.version {
            DapVersion::Draft02 => hpke_config.as_ref().get_encoded(),
            DapVersion::Draft05 => {
                let hpke_config_list = HpkeConfigList {
                    hpke_configs: vec![hpke_config.as_ref().clone()],
                };
                hpke_config_list.get_encoded()
            }
            // This is just to keep the compiler happy as we excluded DapVersion::Unknown by
            // aborting at the top of the function.
            _ => unreachable!("unhandled version {:?}", req.version),
        };

        metrics.inbound_req_inc(DaphneRequestType::HpkeConfig);
        Ok(DapResponse {
            version: req.version,
            media_type: DapMediaType::HpkeConfigList,
            payload,
        })
    }

    async fn current_batch(&self, task_id: &TaskId) -> Result<BatchId, DapError>;

    /// Access the Prometheus metrics.
    fn metrics(&self) -> &DaphneMetrics;

    /// Access the audit log.
    fn audit_log(&self) -> &dyn AuditLog;
}
