// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashMap, sync::Once};

use async_trait::async_trait;
use prio::codec::{Encode, ParameterizedDecode, ParameterizedEncode};

use super::{check_batch, resolve_task_config, DapAggregator};
use crate::{
    constants::DapMediaType,
    error::DapAbort,
    messages::{
        constant_time_eq, AggregateShare, AggregateShareReq, AggregationJobInitReq,
        AggregationJobResp, PartialBatchSelector, ReportError, TaskId, TransitionVar,
    },
    metrics::{DaphneMetrics, DaphneRequestType, ReportStatus},
    protocol::{
        aggregator::{ReplayProtection, ReportProcessedStatus},
        report_init::{InitializedReport, WithPeerPrepShare},
    },
    roles::aggregator::MergeAggShareError,
    DapAggregationParam, DapError, DapRequest, DapResponse, DapTaskConfig,
};

/// DAP Helper functionality.
#[async_trait]
pub trait DapHelper: DapAggregator {}

pub async fn handle_agg_job_init_req<A: DapHelper + Sync>(
    aggregator: &A,
    req: DapRequest<AggregationJobInitReq>,
    replay_protection: ReplayProtection,
) -> Result<DapResponse, DapError> {
    let task_id = req.task_id;
    let metrics = aggregator.metrics();

    metrics.agg_job_observe_batch_size(req.payload.prep_inits.len());

    let task_config = resolve_task_config(aggregator, &req.meta).await?;

    // Ensure we know which batch the request pertains to.
    check_part_batch(
        &task_id,
        &task_config,
        &req.payload.part_batch_sel,
        &req.payload.agg_param,
    )?;

    let part_batch_sel = req.payload.part_batch_sel.clone();
    let version = req.version;
    let initialized_reports = task_config.consume_agg_job_req(
        &aggregator.get_receiver_configs(task_config.version).await?,
        aggregator.valid_report_time_range(),
        &task_id,
        req.payload,
        replay_protection,
    )?;

    let agg_job_resp = {
        let agg_job_resp = finish_agg_job_and_aggregate(
            aggregator,
            &task_id,
            &task_config,
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
        &task_id,
        &task_config,
        agg_job_resp.transitions.len() as u64,
        0, /* vdaf step */
    );

    metrics.inbound_req_inc(DaphneRequestType::Aggregate);
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

async fn finish_agg_job_and_aggregate(
    helper: &impl DapHelper,
    task_id: &TaskId,
    task_config: &DapTaskConfig,
    part_batch_sel: &PartialBatchSelector,
    initialized_reports: &[InitializedReport<WithPeerPrepShare>],
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
            *task_id,
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
                            ReportProcessedStatus::Rejected(ReportError::ReportReplayed),
                        )
                    }));
                    inc_restart_metric.call_once(|| metrics.agg_job_put_span_retry_inc());
                }
                // This bucket is contained by an aggregate share span that has been collected.
                (Err(MergeAggShareError::AlreadyCollected), reports) => {
                    report_status.extend(reports.into_iter().map(|(report_id, _)| {
                        (
                            report_id,
                            ReportProcessedStatus::Rejected(ReportError::BatchCollected),
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
                if let TransitionVar::Failed(err) = &transition.var {
                    metrics.report_inc_by(ReportStatus::Rejected(*err), 1);
                }
            }

            return Ok(agg_job_resp);
        }
    }

    // We need to prevent an attacker from keeping this loop running for too long, potentially
    // enabling an DOS attack.
    Err(DapAbort::BadRequest("aggregation job contained too many replays".into()).into())
}
