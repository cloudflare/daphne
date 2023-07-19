use std::borrow::Cow;

use async_trait::async_trait;
use futures::TryFutureExt;
use prio::codec::{Encode, ParameterizedDecode};
use tracing::error;

use super::{check_batch, check_request_content_type, resolve_taskprov, DapAggregator};
use crate::{
    audit_log::AggregationJobAuditAction,
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{
        constant_time_eq, AggregateShare, AggregateShareReq, AggregationJobContinueReq,
        AggregationJobInitReq, PartialBatchSelector, ReportMetadata, TaskId,
    },
    metrics::DaphneRequestType,
    DapError, DapHelperState, DapHelperTransition, DapRequest, DapResource, DapResponse,
    DapTaskConfig, DapVersion, MetaAggregationJobId,
};

/// DAP Helper functionality.
#[async_trait(?Send)]
pub trait DapHelper<S>: DapAggregator<S> {
    /// Store the Helper's aggregation-flow state unless it already exists. Returns a boolean
    /// indicating if the operation succeeded.
    async fn put_helper_state_if_not_exists(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        helper_state: &DapHelperState,
    ) -> Result<bool, DapError>;

    /// Fetch the Helper's aggregation-flow state. `None` is returned if the Helper has no state
    /// associated with the given task and aggregation job.
    async fn get_helper_state(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
    ) -> Result<Option<DapHelperState>, DapError>;

    /// Handle a request pertaining to an aggregation job.
    async fn handle_agg_job_req(&self, req: &DapRequest<S>) -> Result<DapResponse, DapAbort> {
        let metrics = self.metrics().with_host(req.host());
        let task_id = req.task_id()?;

        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::version_unknown());
        }

        if let Some(reason) = self.unauthorized_reason(req).await? {
            error!("aborted unauthorized collect request: {reason}");
            return Err(DapAbort::UnauthorizedRequest {
                detail: reason,
                task_id: task_id.clone(),
            });
        }

        match req.media_type {
            DapMediaType::AggregationJobInitReq => {
                let agg_job_init_req =
                    AggregationJobInitReq::get_decoded_with_param(&req.version, &req.payload)
                        .map_err(|e| DapAbort::from_codec_error(e, task_id.clone()))?;

                metrics.agg_job_observe_batch_size(agg_job_init_req.report_shares.len());

                // taskprov: Resolve the task config to use for the request. We also need to ensure
                // that all of the reports include the task config in the report extensions. (See
                // section 6 of draft-wang-ppm-dap-taskprov-02.)
                let mut first_metadata: Option<&ReportMetadata> = None;
                let global_config = self.get_global_config();
                if global_config.allow_taskprov {
                    let using_taskprov = agg_job_init_req
                        .report_shares
                        .iter()
                        .filter(|share| {
                            share
                                .report_metadata
                                .is_taskprov(global_config.taskprov_version, task_id)
                        })
                        .count();

                    if using_taskprov == agg_job_init_req.report_shares.len() {
                        // All the extensions use taskprov and look ok, so compute first_metadata.
                        // Note this will always be Some().
                        first_metadata = agg_job_init_req
                            .report_shares
                            .first()
                            .map(|report_share| &report_share.report_metadata);
                    } else if using_taskprov != 0 {
                        // It's not all taskprov or no taskprov, so it's an error.
                        return Err(DapAbort::UnrecognizedMessage {
                            detail: "some reports include the taskprov extensions and some do not"
                                .to_string(),
                            task_id: Some(task_id.clone()),
                        });
                    }
                }
                resolve_taskprov(self, task_id, req, first_metadata).await?;

                let wrapped_task_config = self
                    .get_task_config_for(Cow::Borrowed(task_id))
                    .await?
                    .ok_or(DapAbort::UnrecognizedTask)?;
                let task_config = wrapped_task_config.as_ref();

                // draft02 compatibility: In draft02, the aggregation job ID is parsed from the
                // HTTP request payload; in the latest draft, the aggregation job ID is parsed from
                // the request path.
                let agg_job_id = match (
                    req.version,
                    &req.resource,
                    &agg_job_init_req.draft02_agg_job_id,
                ) {
                    (DapVersion::Draft02, DapResource::Undefined, Some(ref agg_job_id)) => {
                        MetaAggregationJobId::Draft02(Cow::Borrowed(agg_job_id))
                    }
                    (DapVersion::Draft05, DapResource::AggregationJob(ref agg_job_id), None) => {
                        MetaAggregationJobId::Draft05(Cow::Borrowed(agg_job_id))
                    }
                    (DapVersion::Draft05, DapResource::Undefined, None) => {
                        return Err(DapAbort::BadRequest("undefined resource".into()));
                    }
                    _ => unreachable!("unhandled resource {:?}", req.resource),
                };

                // Check whether the DAP version in the request matches the task config.
                if task_config.version != req.version {
                    return Err(DapAbort::version_mismatch(req.version, task_config.version));
                }

                // Ensure we know which batch the request pertains to.
                check_part_batch(
                    task_id,
                    task_config,
                    &agg_job_init_req.part_batch_sel,
                    &agg_job_init_req.agg_param,
                )?;

                let transition = task_config
                    .vdaf
                    .handle_agg_job_init_req(
                        self,
                        self,
                        task_id,
                        task_config,
                        &agg_job_init_req,
                        &metrics,
                    )
                    .map_err(DapError::Abort)
                    .await?;

                let agg_job_resp = match transition {
                    DapHelperTransition::Continue(state, agg_job_resp) => {
                        if !self
                            .put_helper_state_if_not_exists(task_id, &agg_job_id, &state)
                            .await?
                        {
                            // TODO spec: Consider an explicit abort for this case.
                            return Err(DapAbort::BadRequest(
                                "unexpected message for aggregation job (already exists)".into(),
                            ));
                        }
                        agg_job_resp
                    }
                    DapHelperTransition::Finish(..) => {
                        return Err(fatal_error!(err = "unexpected transition (finished)").into());
                    }
                };

                self.audit_log().on_aggregation_job(
                    req.host(),
                    task_id,
                    task_config,
                    agg_job_init_req.report_shares.len() as u64,
                    AggregationJobAuditAction::Init,
                );

                metrics.agg_job_started_inc();
                metrics.inbound_req_inc(DaphneRequestType::Aggregate);
                Ok(DapResponse {
                    version: req.version,
                    media_type: DapMediaType::AggregationJobResp,
                    payload: agg_job_resp.get_encoded(),
                })
            }
            DapMediaType::AggregationJobContinueReq => {
                resolve_taskprov(self, task_id, req, None).await?;
                let wrapped_task_config = self
                    .get_task_config_for(Cow::Borrowed(task_id))
                    .await?
                    .ok_or(DapAbort::UnrecognizedTask)?;
                let task_config = wrapped_task_config.as_ref();

                // Check whether the DAP version in the request matches the task config.
                if task_config.version != req.version {
                    return Err(DapAbort::version_mismatch(req.version, task_config.version));
                }

                let agg_job_cont_req =
                    AggregationJobContinueReq::get_decoded_with_param(&req.version, &req.payload)
                        .map_err(|e| DapAbort::from_codec_error(e, task_id.clone()))?;

                // draft02 compatibility: In draft02, the aggregation job ID is parsed from the
                // HTTP request payload; in the latest, the aggregation job ID is parsed from the
                // request path.
                let agg_job_id = match (
                    req.version,
                    &req.resource,
                    &agg_job_cont_req.draft02_agg_job_id,
                ) {
                    (DapVersion::Draft02, DapResource::Undefined, Some(ref agg_job_id)) => {
                        MetaAggregationJobId::Draft02(Cow::Borrowed(agg_job_id))
                    }
                    (DapVersion::Draft05, DapResource::AggregationJob(ref agg_job_id), None) => {
                        MetaAggregationJobId::Draft05(Cow::Borrowed(agg_job_id))
                    }
                    (DapVersion::Draft05, DapResource::Undefined, None) => {
                        return Err(DapAbort::BadRequest("undefined resource".into()));
                    }
                    _ => unreachable!("unhandled resource {:?}", req.resource),
                };

                let state = self.get_helper_state(task_id, &agg_job_id).await?.ok_or(
                    DapAbort::UnrecognizedAggregationJob {
                        task_id: task_id.clone(),
                        agg_job_id_base64url: agg_job_id.to_base64url(),
                    },
                )?;
                let part_batch_sel = state.part_batch_sel.clone();
                let transition = task_config.vdaf.handle_agg_job_cont_req(
                    task_id,
                    &agg_job_id,
                    state,
                    &agg_job_cont_req,
                    &metrics,
                )?;

                let (agg_job_resp, out_shares_count) = match transition {
                    DapHelperTransition::Continue(..) => {
                        return Err(fatal_error!(err = "unexpected transition (continued)").into());
                    }
                    DapHelperTransition::Finish(out_shares, agg_job_resp) => {
                        let out_shares_count = u64::try_from(out_shares.len()).unwrap();
                        self.put_out_shares(task_id, &part_batch_sel, out_shares)
                            .await?;
                        (agg_job_resp, out_shares_count)
                    }
                };

                self.audit_log().on_aggregation_job(
                    req.host(),
                    task_id,
                    task_config,
                    out_shares_count,
                    AggregationJobAuditAction::Continue,
                );

                metrics.report_inc_by("aggregated", out_shares_count);
                metrics.agg_job_completed_inc();
                metrics.inbound_req_inc(DaphneRequestType::Aggregate);
                Ok(DapResponse {
                    version: req.version,
                    media_type: DapMediaType::agg_job_cont_resp_for_version(task_config.version),
                    payload: agg_job_resp.get_encoded(),
                })
            }
            //TODO spec: Specify this behavior.
            _ => Err(DapAbort::BadRequest("unexpected media type".into())),
        }
    }

    /// Handle a request for an aggregate share. This is called by the Leader to complete a
    /// collection job.
    async fn handle_agg_share_req(&self, req: &DapRequest<S>) -> Result<DapResponse, DapAbort> {
        let now = self.get_current_time();
        let metrics = self.metrics().with_host(req.host());
        let task_id = req.task_id()?;

        // Check whether the DAP version indicated by the sender is supported.
        if req.version == DapVersion::Unknown {
            return Err(DapAbort::version_unknown());
        }

        check_request_content_type(req, DapMediaType::AggregateShareReq)?;

        resolve_taskprov(self, task_id, req, None).await?;

        if let Some(reason) = self.unauthorized_reason(req).await? {
            error!("aborted unauthorized collect request: {reason}");
            return Err(DapAbort::UnauthorizedRequest {
                detail: reason,
                task_id: task_id.clone(),
            });
        }

        let wrapped_task_config = self
            .get_task_config_for(Cow::Borrowed(req.task_id()?))
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_config = wrapped_task_config.as_ref();

        // Check whether the DAP version in the request matches the task config.
        if task_config.version != req.version {
            return Err(DapAbort::version_mismatch(req.version, task_config.version));
        }

        let agg_share_req = AggregateShareReq::get_decoded_with_param(&req.version, &req.payload)
            .map_err(|e| DapAbort::from_codec_error(e, task_id.clone()))?;

        // Ensure the batch boundaries are valid and that the batch doesn't overlap with previosuly
        // collected batches.
        check_batch(
            self,
            task_config,
            task_id,
            &agg_share_req.batch_sel,
            &agg_share_req.agg_param,
            now,
        )
        .await?;

        let agg_share = self
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
                task_id: task_id.clone(),
            });
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
                task_id: task_id.clone(),
            });
        }

        // Mark each aggregated report as collected.
        self.mark_collected(task_id, &agg_share_req.batch_sel)
            .await?;

        let encrypted_agg_share = task_config.vdaf.produce_helper_encrypted_agg_share(
            &task_config.collector_hpke_config,
            task_id,
            &agg_share_req.batch_sel,
            &agg_share,
            task_config.version,
        )?;

        let agg_share_resp = AggregateShare {
            encrypted_agg_share,
        };

        metrics.report_inc_by("collected", agg_share_req.report_count);
        metrics.inbound_req_inc(DaphneRequestType::Collect);
        Ok(DapResponse {
            version: req.version,
            media_type: DapMediaType::AggregateShare,
            payload: agg_share_resp.get_encoded(),
        })
    }
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
        return Err(DapAbort::UnrecognizedMessage {
            detail: "invalid aggregation parameter".into(),
            task_id: Some(task_id.clone()),
        });
    }

    Ok(())
}
