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
    fatal_error,
    messages::{
        constant_time_eq, AggregateShare, AggregateShareReq, AggregationJobContinueReq,
        AggregationJobInitReq, AggregationJobResp, Draft02AggregationJobId, PartialBatchSelector,
        ReportId, TaskId, TransitionFailure, TransitionVar,
    },
    metrics::{DaphneMetrics, DaphneRequestType},
    vdaf::ReportProcessedStatus,
    DapAggregateShare, DapAggregateSpan, DapAggregationJobState, DapError,
    DapHelperAggregationJobTransition, DapRequest, DapResource, DapResponse, DapTaskConfig,
    DapVersion, MetaAggregationJobId,
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
        helper_state: &DapAggregationJobState,
    ) -> Result<bool, DapError>;

    /// Fetch the Helper's aggregation-flow state. `None` is returned if the Helper has no state
    /// associated with the given task and aggregation job.
    async fn get_helper_state(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
    ) -> Result<Option<DapAggregationJobState>, DapError>;

    async fn handle_agg_job_init_req<'req>(
        &self,
        req: &'req DapRequest<S>,
        metrics: &DaphneMetrics,
        task_id: &TaskId,
    ) -> Result<DapResponse, DapAbort> {
        let agg_job_init_req =
            AggregationJobInitReq::get_decoded_with_param(&req.version, &req.payload)
                .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

        metrics.agg_job_observe_batch_size(agg_job_init_req.prep_inits.len());

        // taskprov: Resolve the task config to use for the request. We also need to ensure
        // that all of the reports include the task config in the report extensions. (See
        // section 6 of draft-wang-ppm-dap-taskprov-02.)
        if let Some(taskprov_version) = self.get_global_config().taskprov_version {
            let using_taskprov = agg_job_init_req
                .prep_inits
                .iter()
                .filter(|prep_init| {
                    prep_init
                        .report_share
                        .report_metadata
                        .is_taskprov(taskprov_version, task_id)
                })
                .count();

            let first_metadata = match using_taskprov {
                0 => None,
                c if c == agg_job_init_req.prep_inits.len() => {
                    // All the extensions use taskprov and look ok, so compute first_metadata.
                    // Note this will always be Some().
                    agg_job_init_req
                        .prep_inits
                        .first()
                        .map(|prep_init| &prep_init.report_share.report_metadata)
                }
                _ => {
                    // It's not all taskprov or no taskprov, so it's an error.
                    return Err(DapAbort::UnrecognizedMessage {
                        detail: "some reports include the taskprov extensions and some do not"
                            .to_string(),
                        task_id: Some(*task_id),
                    });
                }
            };
            resolve_taskprov(self, task_id, req, first_metadata, taskprov_version).await?;
        }

        let wrapped_task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_config = wrapped_task_config.as_ref();

        if let Some(reason) = self.unauthorized_reason(task_config, req).await? {
            error!("aborted unauthorized collect request: {reason}");
            return Err(DapAbort::UnauthorizedRequest {
                detail: reason,
                task_id: *task_id,
            });
        }

        let agg_job_id = resolve_agg_job_id(req, agg_job_init_req.draft02_agg_job_id.as_ref())?;

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

        let initialized_reports = task_config
            .vdaf
            .helper_initialize_reports(self, self, task_id, task_config, &agg_job_init_req)
            .await?;

        let agg_job_resp = match task_config.version {
            DapVersion::Draft02 => {
                let DapHelperAggregationJobTransition::Continued(state, agg_job_resp) =
                    task_config.vdaf.handle_agg_job_init_req(
                        task_id,
                        task_config,
                        &HashMap::default(), // no reports have been processed yet
                        &initialized_reports,
                        &agg_job_init_req,
                        metrics,
                    )?
                else {
                    return Err(DapAbort::from(fatal_error!(err = "unexpected transition")));
                };

                if !self
                    .put_helper_state_if_not_exists(task_id, &agg_job_id, &state)
                    .await?
                {
                    // TODO spec: Consider an explicit abort for this case.
                    return Err(DapAbort::BadRequest(
                        "unexpected message for aggregation job (already exists)".into(),
                    ));
                }
                metrics.agg_job_started_inc();
                agg_job_resp
            }

            DapVersion::Draft07 => {
                let agg_job_resp = finish_agg_job_and_aggregate(
                    self,
                    task_id,
                    task_config,
                    metrics,
                    |report_status| {
                        let DapHelperAggregationJobTransition::Finished(agg_span, agg_job_resp) =
                            task_config.vdaf.handle_agg_job_init_req(
                                task_id,
                                task_config,
                                report_status,
                                &initialized_reports,
                                &agg_job_init_req,
                                metrics,
                            )?
                        else {
                            return Err(DapAbort::from(fatal_error!(
                                err = "unexpected transition"
                            )));
                        };
                        Ok((agg_span, agg_job_resp))
                    },
                )
                .await?;

                metrics.agg_job_started_inc();
                metrics.agg_job_completed_inc();
                agg_job_resp
            }
        };

        self.audit_log().on_aggregation_job(
            req.host(),
            task_id,
            task_config,
            agg_job_init_req.prep_inits.len() as u64,
            AggregationJobAuditAction::Init,
        );

        metrics.inbound_req_inc(DaphneRequestType::Aggregate);
        Ok(DapResponse {
            version: req.version,
            media_type: DapMediaType::AggregationJobResp,
            payload: agg_job_resp.get_encoded(),
        })
    }

    async fn handle_agg_job_cont_req<'req>(
        &self,
        req: &'req DapRequest<S>,
        metrics: &DaphneMetrics,
        task_id: &TaskId,
    ) -> Result<DapResponse, DapAbort> {
        if let Some(taskprov_version) = self.get_global_config().taskprov_version {
            resolve_taskprov(self, task_id, req, None, taskprov_version).await?;
        }
        let wrapped_task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_config = wrapped_task_config.as_ref();

        if let Some(reason) = self.unauthorized_reason(task_config, req).await? {
            error!("aborted unauthorized collect request: {reason}");
            return Err(DapAbort::UnauthorizedRequest {
                detail: reason,
                task_id: *task_id,
            });
        }

        // Check whether the DAP version in the request matches the task config.
        if task_config.version != req.version {
            return Err(DapAbort::version_mismatch(req.version, task_config.version));
        }

        let agg_job_cont_req =
            AggregationJobContinueReq::get_decoded_with_param(&req.version, &req.payload)
                .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

        let agg_job_id = resolve_agg_job_id(req, agg_job_cont_req.draft02_agg_job_id.as_ref())?;

        let state = self
            .get_helper_state(task_id, &agg_job_id)
            .await?
            .ok_or_else(|| DapAbort::UnrecognizedAggregationJob {
                task_id: *task_id,
                agg_job_id_base64url: agg_job_id.to_base64url(),
            })?;

        let agg_job_resp =
            finish_agg_job_and_aggregate(self, task_id, task_config, metrics, |report_status| {
                task_config.vdaf.handle_agg_job_cont_req(
                    task_id,
                    task_config,
                    &state,
                    report_status,
                    &agg_job_id,
                    &agg_job_cont_req,
                )
            })
            .await?;

        for transition in agg_job_resp.transitions.iter() {
            if let TransitionVar::Failed(failure) = &transition.var {
                metrics.report_inc_by(&format!("rejected_{failure}"), 1)
            }
        }

        let out_shares_count = agg_job_resp
            .transitions
            .iter()
            .filter(|t| matches!(t.var, TransitionVar::Finished))
            .count()
            .try_into()
            .expect("usize to fit in u64");
        self.audit_log().on_aggregation_job(
            req.host(),
            task_id,
            task_config,
            out_shares_count,
            AggregationJobAuditAction::Continue,
        );

        metrics.agg_job_completed_inc();
        metrics.inbound_req_inc(DaphneRequestType::Aggregate);
        Ok(DapResponse {
            version: req.version,
            media_type: DapMediaType::agg_job_cont_resp_for_version(task_config.version),
            payload: agg_job_resp.get_encoded(),
        })
    }

    /// Handle a request pertaining to an aggregation job.
    async fn handle_agg_job_req(&self, req: &DapRequest<S>) -> Result<DapResponse, DapAbort> {
        let metrics = self.metrics();
        let task_id = req.task_id()?;

        match req.media_type {
            DapMediaType::AggregationJobInitReq => {
                self.handle_agg_job_init_req(req, metrics, task_id).await
            }
            DapMediaType::AggregationJobContinueReq => {
                self.handle_agg_job_cont_req(req, metrics, task_id).await
            }
            //TODO spec: Specify this behavior.
            _ => Err(DapAbort::BadRequest("unexpected media type".into())),
        }
    }

    /// Handle a request for an aggregate share. This is called by the Leader to complete a
    /// collection job.
    async fn handle_agg_share_req(&self, req: &DapRequest<S>) -> Result<DapResponse, DapAbort> {
        let now = self.get_current_time();
        let metrics = self.metrics();
        let task_id = req.task_id()?;

        check_request_content_type(req, DapMediaType::AggregateShareReq)?;

        if let Some(taskprov_version) = self.get_global_config().taskprov_version {
            resolve_taskprov(self, task_id, req, None, taskprov_version).await?;
        }

        let wrapped_task_config = self
            .get_task_config_for(req.task_id()?)
            .await?
            .ok_or(DapAbort::UnrecognizedTask)?;
        let task_config = wrapped_task_config.as_ref();

        if let Some(reason) = self.unauthorized_reason(task_config, req).await? {
            error!("aborted unauthorized collect request: {reason}");
            return Err(DapAbort::UnauthorizedRequest {
                detail: reason,
                task_id: *task_id,
            });
        }

        // Check whether the DAP version in the request matches the task config.
        if task_config.version != req.version {
            return Err(DapAbort::version_mismatch(req.version, task_config.version));
        }

        let agg_share_req = AggregateShareReq::get_decoded_with_param(&req.version, &req.payload)
            .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

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
                task_id: *task_id,
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
                task_id: *task_id,
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
            task_id: Some(*task_id),
        });
    }

    Ok(())
}

fn resolve_agg_job_id<'id, S>(
    req: &'id DapRequest<S>,
    draft02_agg_job_id: Option<&'id Draft02AggregationJobId>,
) -> Result<MetaAggregationJobId, DapAbort> {
    // draft02 compatibility: In draft02, the aggregation job ID is parsed from the
    // HTTP request payload; in the latest, the aggregation job ID is parsed from the
    // request path.
    match (req.version, &req.resource, draft02_agg_job_id) {
        (DapVersion::Draft02, DapResource::Undefined, Some(agg_job_id)) => {
            Ok(MetaAggregationJobId::Draft02(*agg_job_id))
        }
        (DapVersion::Draft07, DapResource::AggregationJob(agg_job_id), None) => {
            Ok(MetaAggregationJobId::Draft07(*agg_job_id))
        }
        (DapVersion::Draft07, DapResource::Undefined, None) => {
            Err(DapAbort::BadRequest("undefined resource".into()))
        }
        _ => unreachable!("unhandled resource {:?}", req.resource),
    }
}

async fn finish_agg_job_and_aggregate<S>(
    helper: &impl DapHelper<S>,
    task_id: &TaskId,
    task_config: &DapTaskConfig,
    metrics: &DaphneMetrics,
    finish_agg_job: impl Fn(
        &HashMap<ReportId, ReportProcessedStatus>,
    ) -> Result<
        (DapAggregateSpan<DapAggregateShare>, AggregationJobResp),
        DapAbort,
    >,
) -> Result<AggregationJobResp, DapAbort> {
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
        let (agg_span, agg_job_resp) = finish_agg_job(&report_status)?;

        let put_shares_result = helper
            .try_put_agg_share_span(task_id, task_config, agg_span)
            .await;

        let inc_restart_metric = Once::new();
        for (_bucket, result) in put_shares_result {
            match result {
                // This bucket had no replays.
                (Ok(replays), reports) if replays.is_empty() => {
                    // Every report in the bucket has been committed to aggregate storage.
                    report_status.extend(
                        reports.into_iter().map(|(report_id, _time)| {
                            (report_id, ReportProcessedStatus::Aggregated)
                        }),
                    );
                }
                // This bucket had replays.
                (Ok(replays), _reports) => {
                    // At least one report was replayed (no change to aggregate storage).
                    report_status.extend(replays.into_iter().map(|report_id| {
                        (
                            report_id,
                            ReportProcessedStatus::Rejected(TransitionFailure::ReportReplayed),
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
                (Err(e), _) => return Err(e.into()),
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
            metrics.report_inc_by("aggregated", out_shares_count);

            return Ok(agg_job_resp);
        }
    }

    // We need to prevent an attacker from keeping this loop running for too long, potentially
    // enabling an DOS attack.
    Err(DapAbort::BadRequest(
        "AggregationJobContinueReq contained too many replays".into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use futures::StreamExt;
    use prio::codec::ParameterizedDecode;

    use crate::messages::{AggregationJobInitReq, AggregationJobResp, Transition, TransitionVar};
    use crate::roles::DapHelper;
    use crate::{assert_metrics_include, MetaAggregationJobId};
    use crate::{roles::test::TestData, DapVersion};

    #[tokio::test]
    async fn replay_reports_when_continuing_aggregation_draft02() {
        let mut data = TestData::new(DapVersion::Draft02);
        let task_id = data.insert_task(
            DapVersion::Draft02,
            crate::VdafConfig::Prio3(crate::Prio3Config::Count),
        );
        let helper = data.new_helper();
        let test = data.with_leader(Arc::clone(&helper));

        let reports = futures::stream::iter(0..3)
            .then(|_| async { test.gen_test_report(&task_id).await })
            .collect::<Vec<_>>()
            .await;

        let report_ids = reports
            .iter()
            .map(|r| r.report_metadata.id)
            .collect::<Vec<_>>();

        let req = test
            .gen_test_agg_job_init_req(&task_id, DapVersion::Draft02, reports)
            .await;

        let meta_agg_job_id = MetaAggregationJobId::Draft02(
            AggregationJobInitReq::get_decoded_with_param(&DapVersion::Draft02, &req.payload)
                .unwrap()
                .draft02_agg_job_id
                .unwrap(),
        );

        helper
            .handle_agg_job_init_req(&req, &helper.metrics, &task_id)
            .await
            .unwrap();

        {
            let req = test
                .gen_test_agg_job_cont_req(
                    &meta_agg_job_id,
                    report_ids[0..2]
                        .iter()
                        .map(|id| Transition {
                            report_id: *id,
                            var: TransitionVar::Continued(vec![]),
                        })
                        .collect(),
                    DapVersion::Draft02,
                )
                .await;

            let resp = helper
                .handle_agg_job_cont_req(&req, &helper.metrics, &task_id)
                .await
                .unwrap();

            let a_job_resp =
                AggregationJobResp::get_decoded_with_param(&DapVersion::Draft02, &resp.payload)
                    .unwrap();
            assert_eq!(a_job_resp.transitions.len(), 2);
            assert!(a_job_resp
                .transitions
                .iter()
                .all(|t| matches!(t.var, TransitionVar::Finished)));
        }
        {
            let req = test
                .gen_test_agg_job_cont_req(
                    &meta_agg_job_id,
                    report_ids[1..3]
                        .iter()
                        .map(|id| Transition {
                            report_id: *id,
                            var: TransitionVar::Continued(vec![]),
                        })
                        .collect(),
                    DapVersion::Draft02,
                )
                .await;

            let resp = helper
                .handle_agg_job_cont_req(&req, &helper.metrics, &task_id)
                .await
                .unwrap();

            let a_job_resp =
                AggregationJobResp::get_decoded_with_param(&DapVersion::Draft02, &resp.payload)
                    .unwrap();
            assert_eq!(a_job_resp.transitions.len(), 2);
            assert_matches!(
                a_job_resp.transitions[0].var,
                TransitionVar::Failed(crate::messages::TransitionFailure::ReportReplayed)
            );
            assert_matches!(a_job_resp.transitions[1].var, TransitionVar::Finished);
        };

        assert_metrics_include!(test.helper_registry, {
            r#"report_counter{env="test_helper",host="helper.org",status="aggregated"}"#: 3,
            r#"report_counter{env="test_helper",host="helper.org",status="rejected_report_replayed"}"#: 1,
        });
    }
}
