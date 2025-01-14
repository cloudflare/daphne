// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{check_part_batch, DapHelper, HashedAggregationJobReq};
use crate::{
    error::DapAbort,
    messages::{
        AggregationJobInitReq, AggregationJobResp, PartialBatchSelector, ReportError, TaskId,
        TransitionVar,
    },
    metrics::ReportStatus,
    protocol::aggregator::ReportProcessedStatus,
    roles::{aggregator::MergeAggShareError, resolve_task_config},
    DapError, DapRequest, DapTaskConfig, InitializedReport, WithPeerPrepShare,
};
use std::{collections::HashMap, sync::Once};

/// A state machine for the handling of aggregation jobs.
pub struct HandleAggJob<S> {
    state: S,
}

/// The initial state, the aggregation request has been received.
pub struct Init(DapRequest<HashedAggregationJobReq>);

/// The aggregation job is legal. Which means that it's either new or it's parameters haven't
/// changed since the last time we've received it.
pub struct LegalAggregationJobReq(DapRequest<AggregationJobInitReq>);

/// The task configuration associated with the incoming request has been resolved.
pub struct WithTaskConfig {
    task_config: DapTaskConfig,
    request: DapRequest<AggregationJobInitReq>,
}

/// The transition between [`WithTaskConfig`] and [`InitializedReports`], this allows for the
/// costumization of how reports get initialized.
///
/// This type is returned by [`HandleAggJob::into_parts`] and [`Self::with_initialized_reports`]
/// can be used to return to the [`HandleAggJob`] state machine flow.
#[non_exhaustive]
pub struct ToInitializedReportsTransition {
    pub task_id: TaskId,
    pub part_batch_sel: PartialBatchSelector,
    pub task_config: DapTaskConfig,
}

/// The reports have been initialized and are ready for aggregation.
pub struct InitializedReports {
    task_id: TaskId,
    part_batch_sel: PartialBatchSelector,
    task_config: DapTaskConfig,
    reports: Vec<InitializedReport<WithPeerPrepShare>>,
}

macro_rules! impl_from {
    ($($t:ty),*$(,)?) => {
        $(impl From<$t> for HandleAggJob<$t> {
            fn from(state: $t) -> Self {
                Self { state }
            }
        })*
    };
}

impl_from!(Init, WithTaskConfig, InitializedReports);

pub fn start(request: DapRequest<HashedAggregationJobReq>) -> HandleAggJob<Init> {
    HandleAggJob::new(request)
}

impl HandleAggJob<Init> {
    pub fn new(request: DapRequest<HashedAggregationJobReq>) -> Self {
        Self {
            state: Init(request),
        }
    }

    pub async fn check_aggregation_job_legality<A: DapHelper>(
        self,
        aggregator: &A,
    ) -> Result<HandleAggJob<LegalAggregationJobReq>, DapError> {
        let Self { state: Init(req) } = self;
        aggregator
            .assert_agg_job_is_immutable(
                req.resource_id,
                req.version,
                &req.task_id,
                &req.payload.hash,
            )
            .await?;
        Ok(HandleAggJob {
            state: LegalAggregationJobReq(req.map(|r| r.request)),
        })
    }
}

impl HandleAggJob<LegalAggregationJobReq> {
    /// Resolve the task config in the default way.
    pub async fn resolve_task_config<A: DapHelper>(
        self,
        aggregator: &A,
    ) -> Result<HandleAggJob<WithTaskConfig>, DapError> {
        let task_config = resolve_task_config(aggregator, &self.state.0.meta).await?;
        self.with_task_config(task_config)
    }

    /// Provide the resolved task configuration.
    pub fn with_task_config(
        self,
        task_config: DapTaskConfig,
    ) -> Result<HandleAggJob<WithTaskConfig>, DapError> {
        let Self {
            state: LegalAggregationJobReq(request),
        } = self;

        check_part_batch(
            &request.task_id,
            &task_config,
            &request.payload.part_batch_sel,
            &request.payload.agg_param,
        )?;
        Ok(HandleAggJob {
            state: WithTaskConfig {
                task_config,
                request,
            },
        })
    }
}

impl HandleAggJob<WithTaskConfig> {
    /// Initialize the reports in the default way.
    pub async fn initialize_reports<A: DapHelper>(
        self,
        aggregator: &A,
        replay_protection: crate::ReplayProtection,
    ) -> Result<HandleAggJob<InitializedReports>, DapError> {
        let WithTaskConfig {
            task_config,
            request,
        } = self.state;
        let task_id = request.task_id;
        let part_batch_sel = request.payload.part_batch_sel.clone();
        let initialized_reports = task_config.consume_agg_job_req(
            &aggregator
                .get_hpke_receiver_configs(task_config.version)
                .await?,
            aggregator.valid_report_time_range(),
            &task_id,
            request.payload,
            replay_protection,
        )?;

        Ok(HandleAggJob {
            state: InitializedReports {
                task_id,
                task_config,
                part_batch_sel,
                reports: initialized_reports,
            },
        })
    }

    /// Splits the state machine into it's component parts, giving the caller more control over how
    /// the initialization of reports should be done.
    ///
    /// To return to the [`HandleAggJob`] state machine flow, call
    /// [`ToInitializedReportsTransition::with_initialized_reports`].
    pub fn into_parts(
        self,
        replay_protection: crate::ReplayProtection,
    ) -> Result<
        (
            ToInitializedReportsTransition,
            DapRequest<AggregationJobInitReq>,
        ),
        DapAbort,
    > {
        let task_id = self.state.request.task_id;
        if replay_protection.enabled() {
            crate::protocol::no_duplicates(
                self.state
                    .request
                    .payload
                    .prep_inits
                    .iter()
                    .map(|p| p.report_share.report_metadata.id),
            )
            .map_err(|id| DapAbort::InvalidMessage {
                detail: format!("report ID {id} appears twice in the same aggregation job"),
                task_id,
            })?;
        }
        Ok((
            ToInitializedReportsTransition {
                task_id,
                part_batch_sel: self.state.request.payload.part_batch_sel.clone(),
                task_config: self.state.task_config,
            },
            self.state.request,
        ))
    }
}

impl ToInitializedReportsTransition {
    /// Provide the initialized reports that should be aggregated.
    pub fn with_initialized_reports(
        self,
        reports: Vec<InitializedReport<WithPeerPrepShare>>,
    ) -> HandleAggJob<InitializedReports> {
        let Self {
            task_id,
            part_batch_sel,
            task_config,
        } = self;
        HandleAggJob {
            state: InitializedReports {
                task_id,
                part_batch_sel,
                task_config,
                reports,
            },
        }
    }
}

impl HandleAggJob<InitializedReports> {
    /// Aggregate the initialized reports, finishing the aggregation job.
    pub async fn finish_and_aggregate(
        self,
        helper: &impl DapHelper,
    ) -> Result<AggregationJobResp, DapError> {
        let metrics = helper.metrics();
        let Self {
            state:
                InitializedReports {
                    task_id,
                    part_batch_sel,
                    task_config,
                    reports,
                },
        } = self;

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
                task_id,
                &report_status,
                &part_batch_sel,
                &reports,
            )?;

            let put_shares_result = helper
                .try_put_agg_share_span(&task_id, &task_config, agg_span)
                .await;

            let inc_restart_metric = Once::new();
            for (_bucket, result) in put_shares_result {
                match result {
                    // This bucket had no replays.
                    (Ok(()), reports) => {
                        // Every report in the bucket has been committed to aggregate storage.
                        report_status.extend(reports.into_iter().map(|(report_id, _time)| {
                            (report_id, ReportProcessedStatus::Aggregated)
                        }));
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
                    if let TransitionVar::Failed(failure) = &transition.var {
                        metrics.report_inc_by(ReportStatus::Rejected(*failure), 1);
                    }
                }

                metrics.agg_job_started_inc();
                metrics.agg_job_completed_inc();

                helper.audit_log().on_aggregation_job(
                    &task_id,
                    &task_config,
                    agg_job_resp.transitions.len() as u64,
                    0, /* vdaf step */
                );

                return Ok(agg_job_resp);
            }
        }

        // We need to prevent an attacker from keeping this loop running for too long, potentially
        // enabling an DOS attack.
        Err(DapAbort::BadRequest("aggregation job contained too many replays".into()).into())
    }
}
