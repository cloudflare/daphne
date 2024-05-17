// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashMap, sync::Once};

use async_trait::async_trait;
use prio::codec::{Encode, ParameterizedDecode};
use tracing::error;

use super::{check_batch, check_request_content_type, resolve_taskprov, DapAggregator};
use crate::{
    audit_log::AggregationJobAuditAction,
    constants::DapMediaType,
    error::DapAbort,
    messages::{
        constant_time_eq, AggregateShare, AggregateShareReq, AggregationJobInitReq,
        AggregationJobResp, PartialBatchSelector, TaskId, TransitionFailure, TransitionVar,
    },
    metrics::{DaphneMetrics, DaphneRequestType, ReportStatus},
    protocol::aggregator::ReportProcessedStatus,
    roles::aggregator::MergeAggShareError,
    DapAggregationParam, DapError, DapRequest, DapResource, DapResponse, DapTaskConfig,
    EarlyReportStateInitialized,
};

/// DAP Helper functionality.
#[async_trait]
pub trait DapHelper<S: Sync>: DapAggregator<S> {}

pub async fn handle_agg_job_init_req<'req, S: Sync, A: DapHelper<S>>(
    aggregator: &A,
    req: &'req DapRequest<S>,
) -> Result<DapResponse, DapError> {
    let global_config = aggregator.get_global_config().await?;
    let task_id = req.task_id()?;
    let metrics = aggregator.metrics();
    let agg_job_init_req =
        AggregationJobInitReq::get_decoded_with_param(&req.version, &req.payload)
            .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

    metrics.agg_job_observe_batch_size(agg_job_init_req.prep_inits.len());

    // taskprov: Resolve the task config to use for the request.
    if global_config.allow_taskprov {
        resolve_taskprov(aggregator, task_id, req, &global_config).await?;
    }

    let wrapped_task_config = aggregator
        .get_task_config_for(task_id)
        .await?
        .ok_or(DapAbort::UnrecognizedTask)?;
    let task_config = wrapped_task_config.as_ref();

    if let Some(reason) = aggregator.unauthorized_reason(task_config, req).await? {
        error!("aborted unauthorized collect request: {reason}");
        return Err(DapAbort::UnauthorizedRequest {
            detail: reason,
            task_id: *task_id,
        }
        .into());
    }

    let DapResource::AggregationJob(_agg_job_id) = req.resource else {
        return Err(DapAbort::BadRequest("missing aggregation job ID".to_string()).into());
    };

    // Check whether the DAP version in the request matches the task config.
    if task_config.version != req.version {
        return Err(DapAbort::version_mismatch(req.version, task_config.version).into());
    }

    // Ensure we know which batch the request pertains to.
    check_part_batch(
        task_id,
        task_config,
        &agg_job_init_req.part_batch_sel,
        &agg_job_init_req.agg_param,
    )?;

    let prep_init_count = agg_job_init_req.prep_inits.len();
    let part_batch_sel = agg_job_init_req.part_batch_sel.clone();
    let initialized_reports = task_config
        .consume_agg_job_req(aggregator, aggregator, task_id, agg_job_init_req)
        .await?;

    let agg_job_resp = {
        let agg_job_resp = finish_agg_job_and_aggregate(
            aggregator,
            task_id,
            task_config,
            &part_batch_sel,
            &initialized_reports,
            metrics,
        )
        .await?;

        metrics.agg_job_started_inc();
        metrics.agg_job_completed_inc();
        agg_job_resp
    };

    aggregator.audit_log().on_aggregation_job(
        aggregator.host(),
        task_id,
        task_config,
        prep_init_count as u64,
        AggregationJobAuditAction::Init,
    );

    metrics.inbound_req_inc(DaphneRequestType::Aggregate);
    Ok(DapResponse {
        version: req.version,
        media_type: DapMediaType::AggregationJobResp,
        payload: agg_job_resp.get_encoded().map_err(DapError::encoding)?,
    })
}

/// Handle a request pertaining to an aggregation job.
pub async fn handle_agg_job_req<'req, S: Sync, A: DapHelper<S>>(
    aggregator: &A,
    req: &DapRequest<S>,
) -> Result<DapResponse, DapError> {
    match req.media_type {
        Some(DapMediaType::AggregationJobInitReq) => handle_agg_job_init_req(aggregator, req).await,
        _ => Err(DapAbort::BadRequest("unexpected media type".into()).into()),
    }
}

/// Handle a request for an aggregate share. This is called by the Leader to complete a
/// collection job.
pub async fn handle_agg_share_req<'req, S: Sync, A: DapHelper<S>>(
    aggregator: &A,
    req: &DapRequest<S>,
) -> Result<DapResponse, DapError> {
    let global_config = aggregator.get_global_config().await?;
    let now = aggregator.get_current_time();
    let metrics = aggregator.metrics();
    let task_id = req.task_id()?;

    check_request_content_type(req, DapMediaType::AggregateShareReq)?;

    if global_config.allow_taskprov {
        resolve_taskprov(aggregator, task_id, req, &global_config).await?;
    }

    let wrapped_task_config = aggregator
        .get_task_config_for(req.task_id()?)
        .await?
        .ok_or(DapAbort::UnrecognizedTask)?;
    let task_config = wrapped_task_config.as_ref();

    if let Some(reason) = aggregator.unauthorized_reason(task_config, req).await? {
        error!("aborted unauthorized collect request: {reason}");
        return Err(DapAbort::UnauthorizedRequest {
            detail: reason,
            task_id: *task_id,
        }
        .into());
    }

    // Check whether the DAP version in the request matches the task config.
    if task_config.version != req.version {
        return Err(DapAbort::version_mismatch(req.version, task_config.version).into());
    }

    let agg_share_req = AggregateShareReq::get_decoded_with_param(&req.version, &req.payload)
        .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

    let agg_param =
        DapAggregationParam::get_decoded_with_param(&task_config.vdaf, &agg_share_req.agg_param)
            .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

    // Ensure the batch boundaries are valid and that the batch doesn't overlap with previosuly
    // collected batches.
    check_batch(
        aggregator,
        task_config,
        task_id,
        &agg_share_req.batch_sel.clone().into(),
        &agg_share_req.agg_param,
        now,
        &global_config,
    )
    .await?;

    let agg_share = aggregator
        .get_agg_share(task_id, &agg_share_req.batch_sel)
        .await?;

    // Check that we have aggreagted the same set of reports as the Leader.
    if agg_share_req.report_count != agg_share.report_count
        || !constant_time_eq(&agg_share_req.checksum, &agg_share.checksum)
    {
        return Err(DapAbort::BatchMismatch{
                detail: format!("Either the report count or checksum does not match: the Leader computed {} and {}; the Helper computed {} and {}.",
                    agg_share_req.report_count,
                    hex::encode(agg_share_req.checksum),
                    agg_share.report_count,
                    hex::encode(agg_share.checksum)),
                task_id: *task_id,
            }.into());
    }

    // Check the batch size.
    if !task_config
        .is_report_count_compatible(task_id, agg_share.report_count)
        .unwrap_or(false)
    {
        return Err(DapAbort::InvalidBatchSize {
            detail: format!(
                "Report count ({}) is less than minimum ({})",
                agg_share.report_count, task_config.min_batch_size
            ),
            task_id: *task_id,
        }
        .into());
    }

    // Mark each aggregated report as collected.
    aggregator
        .mark_collected(task_id, &agg_share_req.batch_sel)
        .await?;

    let encrypted_agg_share = task_config.produce_helper_encrypted_agg_share(
        &task_config.collector_hpke_config,
        task_id,
        &agg_share_req.batch_sel,
        &agg_param,
        &agg_share,
        task_config.version,
    )?;

    let agg_share_resp = AggregateShare {
        encrypted_agg_share,
    };

    metrics.report_inc_by(ReportStatus::Collected, agg_share_req.report_count);
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
        return Err(DapAbort::query_mismatch(
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
            task_id: Some(*task_id),
        });
    }

    Ok(())
}

async fn finish_agg_job_and_aggregate<S: Sync>(
    helper: &impl DapHelper<S>,
    task_id: &TaskId,
    task_config: &DapTaskConfig,
    part_batch_sel: &PartialBatchSelector,
    initialized_reports: &[EarlyReportStateInitialized],
    metrics: &dyn DaphneMetrics,
) -> Result<AggregationJobResp, DapError> {
    // This loop is intended to run at most once on the "happy path". The intent is as follows:
    //
    // - try to aggregate the output shares into an `DapAggregateShareSpan`
    // - pass it to `try_put_agg_share_span`
    //   - if replays are found, then try again, rejecting the reports that were replayed
    //   - else break with the finished (of failed) transitions
    //
    // The reason we do this is because we don't expect replays to happen but we have to guard
    // against them, as such, even though retrying is possibly very expensive, it probably
    // won't happen often enough that it matters.
    const RETRY_COUNT: u32 = 3;
    let mut report_status = HashMap::new();
    for _ in 0..RETRY_COUNT {
        let (agg_span, agg_job_resp) = task_config.produce_agg_job_resp(
            &report_status,
            part_batch_sel,
            initialized_reports,
        )?;

        let put_shares_result = helper
            .try_put_agg_share_span(task_id, task_config, agg_span)
            .await;

        let inc_restart_metric = Once::new();
        for (_bucket, result) in put_shares_result {
            match result {
                // This bucket had no replays.
                (Ok(()), reports) => {
                    // Every report in the bucket has been committed to aggregate storage.
                    report_status.extend(
                        reports.into_iter().map(|(report_id, _time)| {
                            (report_id, ReportProcessedStatus::Aggregated)
                        }),
                    );
                }
                // This bucket had replays.
                (Err(MergeAggShareError::ReplaysDetected(replays)), _reports) => {
                    // At least one report was replayed (no change to aggregate storage).
                    report_status.extend(replays.into_iter().map(|report_id| {
                        (
                            report_id,
                            ReportProcessedStatus::Rejected(TransitionFailure::ReportReplayed),
                        )
                    }));
                    inc_restart_metric.call_once(|| metrics.agg_job_put_span_retry_inc());
                }
                // This bucket is contained by an aggregate share span that has been collected.
                (Err(MergeAggShareError::AlreadyCollected), reports) => {
                    report_status.extend(reports.into_iter().map(|(report_id, _)| {
                        (
                            report_id,
                            ReportProcessedStatus::Rejected(TransitionFailure::BatchCollected),
                        )
                    }));
                    inc_restart_metric.call_once(|| metrics.agg_job_put_span_retry_inc());
                }
                // If this happens, the leader and helper can possibly have inconsistent state.
                // The leader will still think all of the reports in this job have yet to be
                // aggregated. But we could have aggregated some and not others due to the
                // batched nature of storage requests.
                //
                // This is considered an okay compromise because the leader can retry the job
                // and if this error doesn't manifest itself all reports will be successfully
                // aggregated. Which means that no reports will be lost in a such a state that
                // they can never be aggregated.
                (Err(MergeAggShareError::Other(other)), _) => return Err(other),
            }
        }
        if !inc_restart_metric.is_completed() {
            let out_shares_count = agg_job_resp
                .transitions
                .iter()
                .filter(|t| !matches!(t.var, TransitionVar::Failed(..)))
                .count()
                .try_into()
                .expect("usize to fit in u64");
            metrics.report_inc_by(ReportStatus::Aggregated, out_shares_count);

            for transition in &agg_job_resp.transitions {
                if let TransitionVar::Failed(failure) = &transition.var {
                    metrics.report_inc_by(ReportStatus::Rejected(*failure), 1);
                }
            }

            return Ok(agg_job_resp);
        }
    }

    // We need to prevent an attacker from keeping this loop running for too long, potentially
    // enabling an DOS attack.
    Err(DapAbort::BadRequest("aggregation job contained too many replays".into()).into())
}
