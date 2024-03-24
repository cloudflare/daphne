// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod in_memory_leader;

use std::collections::HashMap;

use async_trait::async_trait;
use futures::future::try_join_all;
use prio::codec::{Decode, Encode, ParameterizedDecode, ParameterizedEncode};
use rand::{thread_rng, Rng};
use tracing::{debug, error};
use url::Url;

use super::{
    aggregator::MergeAggShareError, check_batch, check_request_content_type, resolve_taskprov,
    DapAggregator,
};
use crate::{
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{
        AggregateShare, AggregateShareReq, AggregationJobId, AggregationJobResp, Base64Encode,
        BatchId, BatchSelector, Collection, CollectionJobId, CollectionReq, Interval,
        PartialBatchSelector, Query, Report, TaskId,
    },
    metrics::DaphneRequestType,
    DapAggregationParam, DapCollectionJob, DapError, DapLeaderProcessTelemetry, DapRequest,
    DapResource, DapResponse, DapTaskConfig,
};

struct LeaderHttpRequestOptions<'p> {
    path: &'p str,
    req_media_type: DapMediaType,
    resp_media_type: DapMediaType,
    resource: DapResource,
    req_data: Vec<u8>,
    method: LeaderHttpRequestMethod,
    taskprov: Option<String>,
}

enum LeaderHttpRequestMethod {
    Post,
    Put,
}

async fn leader_send_http_request<S: Sync>(
    role: &impl DapLeader<S>,
    task_id: &TaskId,
    task_config: &DapTaskConfig,
    opts: LeaderHttpRequestOptions<'_>,
) -> Result<DapResponse, DapError> {
    let LeaderHttpRequestOptions {
        path,
        req_media_type,
        resp_media_type,
        resource,
        req_data,
        method,
        taskprov,
    } = opts;

    let url = task_config
        .helper_url
        .join(path)
        .map_err(|e| fatal_error!(err = ?e))?;

    let req = DapRequest {
        version: task_config.version,
        media_type: Some(req_media_type),
        task_id: Some(*task_id),
        resource,
        sender_auth: Some(
            role.authorize(task_id, task_config, &req_media_type, &req_data)
                .await?,
        ),
        payload: req_data,
        taskprov,
    };

    let resp = match method {
        LeaderHttpRequestMethod::Put => role.send_http_put(req, url).await?,
        LeaderHttpRequestMethod::Post => role.send_http_post(req, url).await?,
    };

    check_response_content_type(&resp, resp_media_type)?;
    Ok(resp)
}

/// A party in the DAP protocol who is authorized to send requests to another party.
#[async_trait]
pub trait DapAuthorizedSender<S> {
    /// Add authorization to an outbound DAP request with the given task ID, media type, and payload.
    async fn authorize(
        &self,
        task_id: &TaskId,
        task_config: &DapTaskConfig,
        media_type: &DapMediaType,
        payload: &[u8],
    ) -> Result<S, DapError>;
}

/// A work item, either an aggregation job or collection job.
#[derive(Debug)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum WorkItem {
    AggregationJob {
        task_id: TaskId,
        part_batch_sel: PartialBatchSelector,
        agg_param: DapAggregationParam,
        reports: Vec<Report>,
    },
    CollectionJob {
        task_id: TaskId,
        coll_job_id: CollectionJobId,
        batch_sel: BatchSelector,
        agg_param: DapAggregationParam,
    },
}

impl WorkItem {
    /// Get the ID for the task to which the work item is associated.
    pub fn task_id(&self) -> &TaskId {
        match self {
            Self::AggregationJob { task_id, .. } | Self::CollectionJob { task_id, .. } => task_id,
        }
    }
}

/// DAP Leader functionality.
#[async_trait]
pub trait DapLeader<S: Sync>: DapAuthorizedSender<S> + DapAggregator<S> {
    /// Store a report for use later on.
    async fn put_report(&self, report: &Report, task_id: &TaskId) -> Result<(), DapError>;

    /// Fixed-size tasks: Return the ID of the batch currently being filled.
    //
    // TODO draft02 cleanup: Consider removing this.
    async fn current_batch(&self, task_id: &TaskId) -> Result<BatchId, DapError>;

    /// Initialize a collection job.
    async fn init_collect_job(
        &self,
        task_id: &TaskId,
        collect_job_id: &CollectionJobId,
        batch_sel: BatchSelector,
        agg_param: DapAggregationParam,
    ) -> Result<Url, DapError>;

    /// Check the status of a collect job.
    async fn poll_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
    ) -> Result<DapCollectionJob, DapError>;

    /// Drain at most `num_items` items from the work queue.
    async fn dequeue_work(&self, num_items: usize) -> Result<Vec<WorkItem>, DapError>;

    /// Append `items` to the work queue.
    async fn enqueue_work(&self, items: Vec<WorkItem>) -> Result<(), DapError>;

    /// Complete a collect job by assigning it the completed
    /// [`Collection`](crate::messages::Collection).
    async fn finish_collect_job(
        &self,
        task_id: &TaskId,
        coll_job_id: &CollectionJobId,
        collect_resp: &Collection,
    ) -> Result<(), DapError>;

    /// Send an HTTP POST request.
    async fn send_http_post(&self, req: DapRequest<S>, url: Url) -> Result<DapResponse, DapError>;

    /// Send an HTTP PUT request.
    async fn send_http_put(&self, req: DapRequest<S>, url: Url) -> Result<DapResponse, DapError>;
}

/// Handle a report from a Client.
pub async fn handle_upload_req<S: Sync, A: DapLeader<S>>(
    aggregator: &A,
    req: &DapRequest<S>,
) -> Result<(), DapError> {
    let metrics = aggregator.metrics();
    let task_id = req.task_id()?;
    debug!("upload for task {task_id}");

    check_request_content_type(req, DapMediaType::Report)?;

    let report = Report::get_decoded_with_param(&req.version, req.payload.as_ref())
        .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;
    debug!("report id is {}", report.report_metadata.id);

    if aggregator.get_global_config().allow_taskprov {
        resolve_taskprov(aggregator, task_id, req).await?;
    }
    let task_config = aggregator
        .get_task_config_for(task_id)
        .await?
        .ok_or(DapAbort::UnrecognizedTask)?;

    // Check whether the DAP version in the request matches the task config.
    if task_config.as_ref().version != req.version {
        return Err(DapAbort::version_mismatch(req.version, task_config.as_ref().version).into());
    }

    if report.encrypted_input_shares.len() != 2 {
        return Err(DapAbort::InvalidMessage {
            detail: format!(
                "expected exactly two encrypted input shares; got {}",
                report.encrypted_input_shares.len()
            ),
            task_id: Some(*task_id),
        }
        .into());
    }

    // Check that the indicated HpkeConfig is present.
    if !aggregator
        .can_hpke_decrypt(req.task_id()?, report.encrypted_input_shares[0].config_id)
        .await?
    {
        return Err(DapAbort::ReportRejected {
            detail: "No current HPKE configuration matches the indicated ID.".into(),
        }
        .into());
    }

    // Check that the task has not expired.
    if report.report_metadata.time >= task_config.as_ref().expiration {
        return Err(DapAbort::ReportTooLate.into());
    }

    // Store the report for future processing. At this point, the report may be rejected if
    // the Leader detects that the report was replayed or pertains to a batch that has already
    // been collected.
    aggregator.put_report(&report, req.task_id()?).await?;

    metrics.inbound_req_inc(DaphneRequestType::Upload);
    Ok(())
}

/// Handle a collect job from the Collector. The response is the URI that the Collector will
/// poll later on to get the collection.
pub async fn handle_coll_job_req<S: Sync, A: DapLeader<S>>(
    aggregator: &A,
    req: &DapRequest<S>,
) -> Result<Url, DapError> {
    let now = aggregator.get_current_time();
    let metrics = aggregator.metrics();
    let task_id = req.task_id()?;
    debug!("collect for task {task_id}");

    check_request_content_type(req, DapMediaType::CollectReq)?;

    if aggregator.get_global_config().allow_taskprov {
        resolve_taskprov(aggregator, task_id, req).await?;
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

    let coll_job_req = CollectionReq::get_decoded_with_param(&req.version, req.payload.as_ref())
        .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

    let agg_param =
        DapAggregationParam::get_decoded_with_param(&task_config.vdaf, &coll_job_req.agg_param)
            .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

    // Check whether the DAP version in the request matches the task config.
    if task_config.version != req.version {
        return Err(DapAbort::version_mismatch(req.version, task_config.version).into());
    }

    // Ensure the batch boundaries are valid and that the batch doesn't overlap with previosuly
    // collected batches.
    check_batch(
        aggregator,
        task_config,
        task_id,
        &coll_job_req.query,
        &coll_job_req.agg_param,
        now,
    )
    .await?;

    let DapResource::CollectionJob(coll_job_id) = &req.resource else {
        return Err(DapAbort::BadRequest("missing collection ID".into()).into());
    };

    let batch_sel = match coll_job_req.query {
        Query::TimeInterval { batch_interval } => BatchSelector::TimeInterval { batch_interval },
        Query::FixedSizeByBatchId { batch_id } => BatchSelector::FixedSizeByBatchId { batch_id },
        Query::FixedSizeCurrentBatch => BatchSelector::FixedSizeByBatchId {
            batch_id: aggregator.current_batch(task_id).await?,
        },
    };

    let collect_job_uri = aggregator
        .init_collect_job(task_id, coll_job_id, batch_sel, agg_param)
        .await?;

    metrics.inbound_req_inc(DaphneRequestType::Collect);
    Ok(collect_job_uri)
}

/// Run an aggregation job for a set of reports. Return the number of reports that were
/// aggregated successfully.
async fn run_agg_job<S: Sync, A: DapLeader<S>>(
    aggregator: &A,
    task_id: &TaskId,
    task_config: &DapTaskConfig,
    part_batch_sel: &PartialBatchSelector,
    agg_param: &DapAggregationParam,
    reports: Vec<Report>,
) -> Result<u64, DapError> {
    let metrics = aggregator.metrics();

    let taskprov = task_config.resolve_taskprove_advertisement()?;

    // Prepare AggregationJobInitReq.
    let agg_job_id = AggregationJobId(thread_rng().gen());
    let (agg_job_state, agg_job_init_req) = task_config
        .produce_agg_job_req(
            aggregator,
            aggregator,
            task_id,
            part_batch_sel,
            agg_param,
            futures::stream::iter(reports),
            metrics,
        )
        .await?;

    if agg_job_state.report_count() == 0 {
        return Ok(0);
    }

    let url_path = format!(
        "tasks/{}/aggregation_jobs/{}",
        task_id.to_base64url(),
        agg_job_id.to_base64url()
    );

    // Send AggregationJobInitReq and receive AggregationJobResp.
    let resp = leader_send_http_request(
        aggregator,
        task_id,
        task_config,
        LeaderHttpRequestOptions {
            path: &url_path,
            req_media_type: DapMediaType::AggregationJobInitReq,
            resp_media_type: DapMediaType::AggregationJobResp,
            resource: DapResource::AggregationJob(agg_job_id),
            req_data: agg_job_init_req
                .get_encoded_with_param(&(task_config.version, false))
                .map_err(DapError::encoding)?,
            method: LeaderHttpRequestMethod::Put,
            taskprov: taskprov.clone(),
        },
    )
    .await?;
    let agg_job_resp = AggregationJobResp::get_decoded(&resp.payload)
        .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

    // Handle AggregationJobResp.
    let agg_span =
        task_config.consume_agg_job_resp(task_id, agg_job_state, agg_job_resp, metrics)?;

    let out_shares_count = agg_span.report_count() as u64;
    if out_shares_count == 0 {
        return Ok(0);
    }

    // At this point we're committed to aggregating the reports: if we do detect an error (a
    // report was replayed at this stage or the span overlaps with a collected batch), then we
    // may end up with a batch mismatch. However, this should only happen if there are multiple
    // aggregation jobs in-flight that include the same report.
    let (replayed, collected) = aggregator
        .try_put_agg_share_span(task_id, task_config, agg_span)
        .await
        .into_iter()
        .map(|(_bucket, (result, _report_metadata))| match result {
            Ok(()) => Ok((0, 0)),
            Err(MergeAggShareError::AlreadyCollected) => Ok((0, 1)),
            Err(MergeAggShareError::ReplaysDetected(replays)) => Ok((replays.len(), 0)),
            Err(MergeAggShareError::Other(e)) => Err(e),
        })
        .try_fold((0, 0), |(replayed, collected), rc| {
            let (r, c) = rc?;
            Ok::<_, DapError>((replayed + r, collected + c))
        })?;

    if replayed > 0 {
        tracing::error!(
            replay_count = replayed,
            "tried to aggregate replayed reports"
        );
    }

    if collected > 0 {
        tracing::error!(
            collected_count = collected,
            "tried to aggregate reports belonging to collected spans"
        );
    }

    metrics.report_inc_by("aggregated", out_shares_count);
    Ok(out_shares_count)
}

/// Handle a pending collection job. If the results are ready, then compute the aggregate
/// results and store them to be retrieved by the Collector later. Returns the number of
/// reports in the batch.
async fn run_coll_job<S: Sync, A: DapLeader<S>>(
    aggregator: &A,
    task_id: &TaskId,
    task_config: &DapTaskConfig,
    coll_job_id: &CollectionJobId,
    batch_sel: &BatchSelector,
    agg_param: &DapAggregationParam,
) -> Result<u64, DapError> {
    let metrics = aggregator.metrics();

    debug!("collecting id {coll_job_id}");
    let leader_agg_share = aggregator.get_agg_share(task_id, batch_sel).await?;

    let taskprov = task_config.resolve_taskprove_advertisement()?;

    // Check the batch size. If not not ready, then return early.
    //
    // TODO Consider logging this error, as it should never happen.
    if !task_config.is_report_count_compatible(task_id, leader_agg_share.report_count)? {
        return Ok(0);
    }

    // Prepare the Leader's aggregate share.
    let leader_enc_agg_share = task_config.produce_leader_encrypted_agg_share(
        &task_config.collector_hpke_config,
        task_id,
        batch_sel,
        agg_param,
        &leader_agg_share,
        task_config.version,
    )?;

    // Prepare AggregateShareReq.
    let agg_share_req = AggregateShareReq {
        batch_sel: batch_sel.clone(),
        agg_param: agg_param
            .get_encoded()
            .map_err(|e| fatal_error!(err = ?e))?,
        report_count: leader_agg_share.report_count,
        checksum: leader_agg_share.checksum,
    };

    let url_path = format!("tasks/{}/aggregate_shares", task_id.to_base64url());

    // Send AggregateShareReq and receive AggregateShareResp.
    let resp = leader_send_http_request(
        aggregator,
        task_id,
        task_config,
        LeaderHttpRequestOptions {
            path: &url_path,
            req_media_type: DapMediaType::AggregateShareReq,
            resp_media_type: DapMediaType::AggregateShare,
            resource: DapResource::Undefined,
            req_data: agg_share_req
                .get_encoded_with_param(&task_config.version)
                .map_err(DapError::encoding)?,
            method: LeaderHttpRequestMethod::Post,
            taskprov,
        },
    )
    .await?;
    let agg_share_resp = AggregateShare::get_decoded(&resp.payload)
        .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;
    // The Collection message includes the smallest quantized time interval containing all reports
    // in the batch.
    let interval = {
        let low = task_config.quantized_time_lower_bound(leader_agg_share.min_time);
        let high = task_config.quantized_time_upper_bound(leader_agg_share.max_time);
        Interval {
            start: low,
            duration: if high > low {
                high - low
            } else {
                // This should never happen!
                task_config.time_precision
            },
        }
    };

    // Complete the collect job.
    let collection = Collection {
        part_batch_sel: batch_sel.clone().into(),
        report_count: leader_agg_share.report_count,
        interval,
        encrypted_agg_shares: [leader_enc_agg_share, agg_share_resp.encrypted_agg_share],
    };
    aggregator
        .finish_collect_job(task_id, coll_job_id, &collection)
        .await?;

    // Mark reports as collected.
    aggregator
        .mark_collected(task_id, &agg_share_req.batch_sel)
        .await?;

    metrics.report_inc_by("collected", agg_share_req.report_count);
    Ok(agg_share_req.report_count)
}

/// Drain a number of items from the work queue and process them.
///
/// Aggregation jobs are handled in parallel, subject to the restriction that all aggregation jobs
/// pertaining to a task are completed before processing any collection job for the same task.
///
/// Collection jobs are processed in order. If a collection job is still pending once processed, it
/// is pushed to the back of the work queue.
pub async fn process<S: Sync, A: DapLeader<S>>(
    aggregator: &A,
    host: &str,
    num_items: usize,
) -> Result<DapLeaderProcessTelemetry, DapError> {
    let mut telem = DapLeaderProcessTelemetry::default();

    tracing::debug!("RUNNING read_work_stream");

    let mut agg_jobs = HashMap::new();
    let mut pending_coll_jobs = Vec::new();
    for work_item in aggregator.dequeue_work(num_items).await? {
        match work_item {
            WorkItem::AggregationJob {
                task_id,
                part_batch_sel,
                agg_param,
                reports,
            } => {
                telem.reports_processed += u64::try_from(reports.len()).unwrap();
                let agg_jobs_per_task: &mut Vec<_> = agg_jobs.entry(task_id).or_default();
                agg_jobs_per_task.push(async move {
                    let task_config = aggregator
                        .get_task_config_for(&task_id)
                        .await?
                        .ok_or(DapAbort::UnrecognizedTask)?;

                    if reports.is_empty() {
                        return Ok(0);
                    }

                    tracing::debug!(
                        "RUNNING run_agg_job FOR TID {task_id} AND {part_batch_sel:?} AND {host}"
                    );
                    run_agg_job(
                        aggregator,
                        &task_id,
                        task_config.as_ref(),
                        &part_batch_sel,
                        &agg_param,
                        reports,
                    )
                    .await
                });
            }
            WorkItem::CollectionJob {
                task_id,
                coll_job_id,
                batch_sel,
                agg_param,
            } => {
                // Wait for all pending aggregation jobs for this task to complete before
                // processing the next collection job. This is to prevent a race condition
                // involving an aggregate share computed during a collection job and any output
                // shares computed during an aggregation job.
                if let Some(agg_jobs_per_task) = agg_jobs.get_mut(&task_id) {
                    telem.reports_aggregated +=
                        try_join_all(agg_jobs_per_task.drain(0..agg_jobs_per_task.len()))
                            .await?
                            .into_iter()
                            .sum::<u64>();
                }

                let task_config = aggregator
                    .get_task_config_for(&task_id)
                    .await?
                    .ok_or(DapAbort::UnrecognizedTask)?;

                tracing::debug!("RUNNING run_collect_job FOR TID {task_id} AND {coll_job_id} AND {batch_sel:?} AND {agg_param:?} AND {host}");
                let collected = run_coll_job(
                    aggregator,
                    &task_id,
                    task_config.as_ref(),
                    &coll_job_id,
                    &batch_sel,
                    &agg_param,
                )
                .await?;

                if collected > 0 {
                    telem.reports_collected += collected;
                } else {
                    pending_coll_jobs.push(WorkItem::CollectionJob {
                        task_id,
                        coll_job_id,
                        batch_sel,
                        agg_param,
                    });
                }
            }
        }
    }

    for (_task_id, mut agg_jobs_per_task) in agg_jobs {
        telem.reports_aggregated +=
            try_join_all(agg_jobs_per_task.drain(0..agg_jobs_per_task.len()))
                .await?
                .into_iter()
                .sum::<u64>();
    }

    // Put all pending collection jobs back in the queue.
    aggregator.enqueue_work(pending_coll_jobs).await?;

    Ok(telem)
}

fn check_response_content_type(resp: &DapResponse, expected: DapMediaType) -> Result<(), DapError> {
    if resp.media_type != expected {
        Err(fatal_error!(
            err = "response from peer has unexpected content-type",
            got = resp.media_type.as_str_for_version(resp.version),
            want = expected.as_str_for_version(resp.version),
        ))
    } else {
        Ok(())
    }
}
