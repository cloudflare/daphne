// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    config::DaphneWorkerConfig,
    durable::{
        create_span_from_request, durable_name_queue,
        leader_agg_job_queue::{
            DURABLE_LEADER_AGG_JOB_QUEUE_FINISH, DURABLE_LEADER_AGG_JOB_QUEUE_PUT,
        },
        req_parse, state_get, state_set_if_not_exists, DurableConnector, DurableOrdered,
        BINDING_DAP_LEADER_AGG_JOB_QUEUE, BINDING_DAP_REPORTS_PENDING, MAX_KEYS,
    },
    initialize_tracing, int_err,
};
use daphne::{messages::TaskId, DapVersion};
use serde::{Deserialize, Serialize};
use std::{cmp::min, ops::ControlFlow};
use tracing::{debug, Instrument};
use worker::*;

use super::{DapDurableObject, GarbageCollectable};

pub(crate) const DURABLE_REPORTS_PENDING_GET: &str = "/internal/do/reports_pending/get";
pub(crate) const DURABLE_REPORTS_PENDING_PUT: &str = "/internal/do/reports_pending/put";

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReportsPendingResult {
    Ok,
    ErrReportExists,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct PendingReport {
    pub(crate) task_id: TaskId,
    pub(crate) version: DapVersion,

    /// Hex-encdoed, serialized report.
    //
    // TODO(cjpatton) Consider changing the type to `Report`. If I recall correctly, this triggers
    // the serde-wasm-bindgen bug we saw in workers-rs 0.0.12, which should be fixed as of 0.0.15.
    pub(crate) report_hex: String,
}

impl PendingReport {
    pub(crate) fn report_id_hex(&self) -> Option<&str> {
        match self.version {
            DapVersion::Draft02 if self.report_hex.len() >= 96 => Some(&self.report_hex[64..96]),
            DapVersion::Draft05 if self.report_hex.len() >= 32 => Some(&self.report_hex[..32]),
            DapVersion::Unknown => unreachable!("unhandled version {:?}", self.version),
            _ => None,
        }
    }
}

/// Durable Object (DO) for storing reports waiting to be processed.
///
/// The following API endpoints are defined:
///
/// - `DURABLE_REPORTS_PENDING_PUT`: Used to store a report uploaded by a Client. Whenever this
///   instance becomes non-empty, an aggregate job is created and dispatched to
///   `LeaderAggregationJobQueue`. If report is found in this instance with the same ID, then an
///   error is returned.
///
/// - `DURABLE_REPORTS_PENDING_GET`: Used to drain reports from storage so that they can be
///   aggregated. Whenever the instance becomes empty, the aggregation job is removed from
///   `LeadeerAggregationJobQueue`.
///
/// The schema for stored reports is as follows:
///
/// ```text
/// [Pending report]  pending/<report_id> -> PendingReport
/// [Aggregation job] agg_job -> DurableOrdered<PendingReport>
/// ```
///
/// where `<report_id>` is the ID of the report. The value is the hex-encoded report. The
/// aggregation job consists of a reference to the name of this DO instance stored in a queue in
/// `LeaderAggregationJobQueue`.
#[durable_object]
pub struct ReportsPending {
    #[allow(dead_code)]
    state: State,
    env: Env,
    config: DaphneWorkerConfig,
    touched: bool,
}

#[durable_object]
impl DurableObject for ReportsPending {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerConfig::from_worker_env(&env).expect("failed to load configuration");
        Self {
            state,
            env,
            config,
            touched: false,
        }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let span = create_span_from_request(&req);
        self.handle(req).instrument(span).await
    }
}

impl ReportsPending {
    async fn handle(&mut self, req: Request) -> Result<Response> {
        let id_hex = self.state.id().to_string();

        let mut req = match self
            .schedule_for_garbage_collection(req, BINDING_DAP_REPORTS_PENDING)
            .await?
        {
            ControlFlow::Continue(req) => req,
            // This req was a GC request and as such we must return from this function.
            ControlFlow::Break(_) => return Response::from_json(&()),
        };

        let durable = DurableConnector::new(&self.env);

        match (req.path().as_ref(), req.method()) {
            // Drain the requested number of reports from storage.
            //
            // Input: `reports_requested: usize`
            // Output: `Vec<PendingReport>`
            (DURABLE_REPORTS_PENDING_GET, Method::Post) => {
                let reports_requested: usize = req_parse(&mut req).await?;
                // Note we impose an upper limit on the user's specified limit.
                let opt = ListOptions::new()
                    .prefix("pending/")
                    .limit(min(reports_requested, MAX_KEYS));
                let iter = self.state.storage().list_with_options(opt).await?.entries();
                let mut item = iter.next()?;
                let mut reports = Vec::with_capacity(reports_requested);
                let mut keys = Vec::with_capacity(reports_requested);
                while !item.done() {
                    let (key, pending_report): (String, PendingReport) =
                        serde_wasm_bindgen::from_value(item.value()).map_err(int_err)?;
                    reports.push(pending_report);
                    keys.push(key);
                    item = iter.next()?;
                }

                // NOTE In order to support DAP tasks that require longer batch lifetimes, it will
                // necessary to check if the lifetime has been reached before removing reports from
                // storage. We might consider putting reports in KV instead.
                self.state.storage().delete_multiple(keys).await?;

                // Check if this bucket is now empty, and if so, remove it from the agg job queue.
                let empty = self
                    .state
                    .storage()
                    .list_with_options(ListOptions::new().prefix("pending/").limit(1))
                    .await?
                    .size()
                    == 0;

                if empty {
                    let agg_job: Option<DurableOrdered<String>> =
                        state_get(&self.state, "agg_job").await?;
                    if let Some(agg_job) = agg_job {
                        // This agg_job delete MUST occur right after the get above, with no
                        // intervening wait on anything other than this DO, in order for us to get
                        // the transactional I/O coalescing workers promises. If some report arrives
                        // before we delete the old agg_job_queue entry, that's ok as it will just
                        // cause a new leader agg job to be created.  There is no race here, as the
                        // new job will have a different name due to the timestamp and nonce that
                        // new_roughly_ordered() adds when constructing the name.
                        self.state.storage().delete("agg_job").await?;
                        // NOTE There is only one agg job queue for now. In the future, work will
                        // be sharded across multiple queues.
                        durable
                            .post(
                                BINDING_DAP_LEADER_AGG_JOB_QUEUE,
                                DURABLE_LEADER_AGG_JOB_QUEUE_FINISH,
                                durable_name_queue(0),
                                &agg_job,
                            )
                            .await?;
                    }
                }

                debug!(
                    "drained {} reports from bucket {}",
                    reports.len(),
                    self.state.id().to_string()
                );
                Response::from_json(&reports)
            }

            // Store a report.
            //
            // Input: `pending_report: PendingReport`
            // Output: `ReportsPendingResult`
            (DURABLE_REPORTS_PENDING_PUT, Method::Post) => {
                let pending_report: PendingReport = req_parse(&mut req).await?;
                let report_id_hex = pending_report
                    .report_id_hex()
                    .ok_or_else(|| int_err("failed to parse report ID from report"))?;
                let key = format!("pending/{report_id_hex}");
                let exists = state_set_if_not_exists(&self.state, &key, &pending_report)
                    .await?
                    .is_some();
                if exists {
                    return Response::from_json(&ReportsPendingResult::ErrReportExists);
                }

                // Check if processing for this bucket of reports has been scheduled. If not, add
                // this bucket to the aggregation job queue.
                let agg_job: Option<DurableOrdered<String>> =
                    state_get(&self.state, "agg_job").await?;
                if agg_job.is_none() {
                    let agg_job = DurableOrdered::new_roughly_ordered(id_hex, "agg_job");

                    // TODO Shard the work across multiple job queues rather than just one. (See
                    // issue #25.) For now there is jsut one job queue.
                    durable
                        .post(
                            BINDING_DAP_LEADER_AGG_JOB_QUEUE,
                            DURABLE_LEADER_AGG_JOB_QUEUE_PUT,
                            durable_name_queue(0),
                            &agg_job,
                        )
                        .await?;
                    self.state.storage().put("agg_job", agg_job).await?;
                }

                Response::from_json(&ReportsPendingResult::Ok)
            }

            _ => Err(int_err(format!(
                "ReportsPending: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

impl DapDurableObject for ReportsPending {
    #[inline(always)]
    fn state(&self) -> &State {
        &self.state
    }

    #[inline(always)]
    fn deployment(&self) -> crate::config::DaphneWorkerDeployment {
        self.config.deployment
    }
}

#[async_trait::async_trait(?Send)]
impl GarbageCollectable for ReportsPending {
    #[inline(always)]
    fn touched(&mut self) -> &mut bool {
        &mut self.touched
    }

    #[inline(always)]
    fn env(&self) -> &Env {
        &self.env
    }
}
