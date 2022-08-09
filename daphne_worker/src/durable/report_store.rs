// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{
        durable_queue_name,
        leader_agg_job_queue::{
            AggregationJob, DURABLE_LEADER_AGG_JOB_QUEUE_FINISH, DURABLE_LEADER_AGG_JOB_QUEUE_PUT,
        },
        state_get, state_get_or_default, BINDING_DAP_LEADER_AGG_JOB_QUEUE,
        BINDING_DAP_REPORT_STORE,
    },
    int_err, now,
};
use daphne::{messages::TransitionFailure, DapVersion};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use worker::*;

pub(crate) fn durable_report_store_name(
    version: &DapVersion,
    task_id_hex: &str,
    window: u64,
    bucket: u64,
) -> String {
    format!(
        "{}/task/{}/window/{}/bucket/{}",
        version.as_ref(),
        task_id_hex,
        window,
        bucket
    )
}

pub(crate) const DURABLE_REPORT_STORE_GET_PENDING: &str = "/internal/do/report_store/get_pending";
pub(crate) const DURABLE_REPORT_STORE_PUT_PENDING: &str = "/internal/do/report_store/put_pending";
pub(crate) const DURABLE_REPORT_STORE_PUT_PROCESSED: &str =
    "/internal/do/report_store/put_processed";
pub(crate) const DURABLE_REPORT_STORE_MARK_COLLECTED: &str =
    "/internal/do/report_store/mark_collected";

#[derive(Deserialize, Serialize)]
pub(crate) enum ReportStoreResult {
    Ok,
    Err(TransitionFailure),
}

/// Durable Object (DO) for storing reports and report metadata.
///
/// The naming convention for instances of the [`ReportStore`] DO is as follows:
///
/// > <version>/task/<task_id>/window/<window>/bucket/<bucket>
///
/// where `<version>` is the DAP version, `<task_id>` is a task ID, `<window>` is a batch window,
/// and `<bucket>` is a non-negative integer. A batch window is a UNIX timestamp (in seconds)
/// truncated by the minimum batch duration. The instance in which a report is stored is derived
/// from the task ID and nonce of the report itself.
#[durable_object]
pub struct ReportStore {
    #[allow(dead_code)]
    state: State,
    env: Env,
    touched: bool,
}

impl ReportStore {
    async fn checked_process(&self, nonce_hex: &str) -> Result<ReportStoreResult> {
        let key = format!("processed/{}", nonce_hex);
        let collected: bool = state_get_or_default(&self.state, "collected").await?;
        let observed: bool = state_get_or_default(&self.state, &key).await?;
        if observed && !collected {
            return Ok(ReportStoreResult::Err(TransitionFailure::ReportReplayed));
        } else if !observed && collected {
            return Ok(ReportStoreResult::Err(TransitionFailure::BatchCollected));
        }
        self.state.storage().put(&key, true).await?;
        Ok(ReportStoreResult::Ok)
    }
}

#[durable_object]
impl DurableObject for ReportStore {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            touched: false,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let mut rng = thread_rng();
        let id_hex = self.state.id().to_string();
        ensure_garbage_collected!(req, self, id_hex.clone(), BINDING_DAP_REPORT_STORE);

        match (req.path().as_ref(), req.method()) {
            (DURABLE_REPORT_STORE_GET_PENDING, Method::Post) => {
                let reports_requested: usize = req.json().await?;
                let opt = ListOptions::new()
                    .prefix("pending/")
                    .limit(reports_requested);
                let iter = self.state.storage().list_with_options(opt).await?.entries();
                let mut item = iter.next()?;
                let mut reports = Vec::with_capacity(reports_requested);
                let mut keys = Vec::with_capacity(reports_requested);
                while !item.done() {
                    let (key, report_hex): (String, String) = item.value().into_serde()?;
                    reports.push(report_hex);
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

                // BUG(issue#73) There is a race condition between DURABLE_REPORT_STORE_GET_PENDING
                // and DURABLE_REPORT_STORE_PUT_PENDING that could prevent a report from getting
                // processed.
                //
                //   1. DURABLE_REPORT_STORE_PUT_PENDING writes a report to storage and checks if
                //      "agg_job" is set. If not, it sets "agg_job" and enqueues the job.
                //
                //   2. DURABLE_REPORT_STORE_GET_PENDING drains a number of reports from storage,
                //      then checks if storage is empty. If so, it deletes "agg_job" if it exists
                //      and dequeues the job.
                //
                // Consider the following sequence of storage transactions (suppose "agg_job" is
                // set):
                //
                //   - DURABLE_REPORT_STORE_GET_PENDING drains all reports from storage
                //   - DURABLE_REPORT_STORE_GET_PENDING checks if storage is empty
                //   - DURABLE_REPORT_STORE_PUT_PENDING stores a report
                //   - DURABLE_REPORT_STORE_GET_PENDING unsets "agg_job"
                //
                // The last step occurs because the emptiness check got scheduled before a new
                // report was added. This will result in the report not getting processed until
                // "agg_job" is set by a future call to DURABLE_REPORT_STORE_PUT_PENDING.
                //
                // This bug would be prevented if either (1) the Workers runtime prevents reuquests
                // to the same DO instance from being handled concurrently or (2) the Workers
                // runtime guaranteeed that the emptiness check and unsetting "agg_job" occurred in
                // the same transaction.
                //
                //   TODO(cjpatton) (1) is supposed to be true, but because there is a reuqest to
                //   another DO here (LeaderAggregationJobQueue), there is an opportunity for
                //   requests to interleave between storage operations. (Where is this documented?)
                //   In all likelihood, miniflare matches the bahavior of prod here and we'll have
                //   to figure out a different design. Perhaps DURABLE_REPORT_STORE_PUT_PENDING
                //   could queue agg jobs directly? The agg job could have the set of reports to be
                //   processed. This way we can avoid storing "agg_job" here.
                //
                // In the meantime, to avoid flakyness in interop tests, supress the bug in
                // development environments by never clearing the agg job queue.
                if empty && self.env.var("DAP_DEPLOYMENT")?.to_string() != "dev" {
                    let agg_job: Option<AggregationJob> = state_get(&self.state, "agg_job").await?;
                    if let Some(agg_job) = agg_job {
                        // NOTE There is only one agg job queue for now. In the future, work will
                        // be sharded across multiple queues.
                        let namespace =
                            self.env.durable_object(BINDING_DAP_LEADER_AGG_JOB_QUEUE)?;
                        let stub = namespace.id_from_name(&durable_queue_name(0))?.get_stub()?;
                        durable_post!(stub, DURABLE_LEADER_AGG_JOB_QUEUE_FINISH, &agg_job).await?;
                        self.state.storage().delete("agg_job").await?;
                    }
                }

                console_debug!(
                    "drained {} reports from bucket {}",
                    reports.len(),
                    self.state.id().to_string()
                );
                Response::from_json(&reports)
            }

            (DURABLE_REPORT_STORE_PUT_PENDING, Method::Post) => {
                let report_hex: String = req.json().await?;
                let nonce_hex = nonce_hex_from_report(&report_hex)
                    .ok_or_else(|| int_err("failed to parse nonce from report"))?;

                let res = self.checked_process(nonce_hex).await?;
                if matches!(res, ReportStoreResult::Ok) {
                    let key = format!("pending/{}", nonce_hex);
                    self.state.storage().put(&key, report_hex).await?;
                }

                // Check if processing for this bucket of reports has been scheduled. If so, add
                // this bucket to the aggregation job queue.
                let agg_job: Option<AggregationJob> = state_get(&self.state, "agg_job").await?;
                if agg_job.is_none() {
                    let agg_job = AggregationJob {
                        report_store_id_hex: id_hex,
                        time: now(),
                        rand: rng.gen(),
                    };

                    let namespace = self.env.durable_object(BINDING_DAP_LEADER_AGG_JOB_QUEUE)?;
                    // TODO Shard the work across multiple job queues rather than just one. (See
                    // issue #25.) For now there is jsut one job queue.
                    let stub = namespace.id_from_name(&durable_queue_name(0))?.get_stub()?;
                    durable_post!(stub, DURABLE_LEADER_AGG_JOB_QUEUE_PUT, &agg_job).await?;
                    self.state.storage().put("agg_job", agg_job).await?;
                }
                Response::from_json(&res)
            }

            (DURABLE_REPORT_STORE_PUT_PROCESSED, Method::Post) => {
                let nonce_hex: String = req.json().await?;
                Response::from_json(&self.checked_process(&nonce_hex).await?)
            }

            (DURABLE_REPORT_STORE_MARK_COLLECTED, Method::Post) => {
                self.state.storage().put("collected", true).await?;
                Response::from_json(&ReportStoreResult::Ok)
            }

            _ => Err(int_err(format!(
                "ReportStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

pub(crate) fn nonce_hex_from_report(report_hex: &str) -> Option<&str> {
    // task_id
    if report_hex.len() < 64 {
        return None;
    }
    let report_hex = &report_hex[64..];

    // nonce
    if report_hex.len() < 48 {
        return None;
    }
    Some(&report_hex[..48])
}
