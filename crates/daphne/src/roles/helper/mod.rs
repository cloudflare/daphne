// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod handle_agg_job;

use async_trait::async_trait;
use prio::codec::{Encode, ParameterizedDecode, ParameterizedEncode};

use super::{check_batch, resolve_task_config, DapAggregator};
use crate::{
    constants::DapMediaType,
    error::DapAbort,
    messages::{
        constant_time_eq, AggregateShare, AggregateShareReq, AggregationJobId,
        AggregationJobInitReq, PartialBatchSelector, TaskId,
    },
    metrics::{DaphneRequestType, ReportStatus},
    protocol::aggregator::ReplayProtection,
    DapAggregationParam, DapError, DapRequest, DapResponse, DapTaskConfig, DapVersion,
};

/// DAP Helper functionality.
#[async_trait]
pub trait DapHelper: DapAggregator {
    /// Asserts that either:
    /// - this the first time we see this aggregation job
    /// - this aggregation job has been seen before and it hasn't changed since the last time we
    ///     saw it.
    async fn assert_agg_job_is_immutable(
        &self,
        id: AggregationJobId,
        version: DapVersion,
        task_id: &TaskId,
        req: &AggregationJobInitReq,
    ) -> Result<(), DapError>;
}

pub async fn handle_agg_job_init_req<A: DapHelper + Sync>(
    aggregator: &A,
    req: DapRequest<AggregationJobInitReq>,
    replay_protection: ReplayProtection,
) -> Result<DapResponse, DapError> {
    let metrics = aggregator.metrics();
    metrics.inbound_req_inc(DaphneRequestType::Aggregate);

    let version = req.version;

    let agg_job_resp = handle_agg_job::start(req)
        .check_aggregation_job_legality(aggregator)
        .await?
        .resolve_task_config(aggregator)
        .await?
        .initialize_reports(aggregator, replay_protection)
        .await?
        .finish_and_aggregate(aggregator)
        .await?;

    Ok(DapResponse {
        version,
        media_type: DapMediaType::AggregationJobResp,
        payload: agg_job_resp
            .get_encoded_with_param(&version)
            .map_err(DapError::encoding)?,
    })
}

/// Handle a request for an aggregate share. This is called by the Leader to complete a
/// collection job.
pub async fn handle_agg_share_req<'req, A: DapHelper>(
    aggregator: &A,
    req: DapRequest<AggregateShareReq>,
) -> Result<DapResponse, DapError> {
    let global_config = aggregator.get_global_config().await?;
    let now = aggregator.get_current_time();
    let metrics = aggregator.metrics();
    let task_id = req.task_id;

    let task_config = resolve_task_config(aggregator, &req.meta).await?;

    let agg_param =
        DapAggregationParam::get_decoded_with_param(&task_config.vdaf, &req.payload.agg_param)
            .map_err(|e| DapAbort::from_codec_error(e, task_id))?;

    // Ensure the batch boundaries are valid and that the batch doesn't overlap with previosuly
    // collected batches.
    check_batch(
        aggregator,
        &task_config,
        &task_id,
        &req.payload.batch_sel.clone().into(),
        &req.payload.agg_param,
        now,
        &global_config,
    )
    .await?;

    let agg_share = aggregator
        .get_agg_share(&task_id, &req.payload.batch_sel)
        .await?;

    // Check that we have aggreagted the same set of reports as the Leader.
    if req.payload.report_count != agg_share.report_count
        || !constant_time_eq(&req.payload.checksum, &agg_share.checksum)
    {
        return Err(DapAbort::BatchMismatch{
                detail: format!("Either the report count or checksum does not match: the Leader computed {} and {}; the Helper computed {} and {}.",
                    req.payload.report_count,
                    hex::encode(req.payload.checksum),
                    agg_share.report_count,
                    hex::encode(agg_share.checksum)),
                task_id,
            }.into());
    }

    // Check the batch size.
    if !task_config
        .is_report_count_compatible(&task_id, agg_share.report_count)
        .unwrap_or(false)
    {
        return Err(DapAbort::InvalidBatchSize {
            detail: format!(
                "Report count ({}) is less than minimum ({})",
                agg_share.report_count, task_config.min_batch_size
            ),
            task_id,
        }
        .into());
    }

    // Mark each aggregated report as collected.
    aggregator
        .mark_collected(&task_id, &req.payload.batch_sel)
        .await?;

    let encrypted_agg_share = task_config.produce_helper_encrypted_agg_share(
        &task_config.collector_hpke_config,
        &task_id,
        &req.payload.batch_sel,
        &agg_param,
        &agg_share,
        task_config.version,
    )?;

    let agg_share_resp = AggregateShare {
        encrypted_agg_share,
    };

    metrics.report_inc_by(ReportStatus::Collected, req.payload.report_count);
    metrics.inbound_req_inc(DaphneRequestType::Collect);
    Ok(DapResponse {
        version: req.version,
        media_type: DapMediaType::AggregateShare,
        payload: agg_share_resp.get_encoded().map_err(DapError::encoding)?,
    })
}

fn check_part_batch(
    task_id: &TaskId,
    task_config: &DapTaskConfig,
    part_batch_sel: &PartialBatchSelector,
    agg_param: &[u8],
) -> Result<(), DapAbort> {
    if !task_config.query.is_valid_part_batch_sel(part_batch_sel) {
        return Err(DapAbort::batch_mode_mismatch(
            task_id,
            &task_config.query,
            part_batch_sel,
        ));
    }

    // Check that the aggregation parameter is suitable for the given VDAF.
    if !task_config.vdaf.is_valid_agg_param(agg_param) {
        // TODO spec: Define this behavior.
        return Err(DapAbort::InvalidMessage {
            detail: "invalid aggregation parameter".into(),
            task_id: *task_id,
        });
    }

    Ok(())
}
