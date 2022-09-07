// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{
        durable_queue_name,
        leader_agg_job_queue::{
            AggregationJob, DURABLE_LEADER_AGG_JOB_QUEUE_FINISH, DURABLE_LEADER_AGG_JOB_QUEUE_PUT,
        },
        state_get, state_get_or_default, DurableConnector, BINDING_DAP_LEADER_AGG_JOB_QUEUE,
        BINDING_DAP_REPORT_STORE,
    },
    int_err, now,
};
use daphne::{messages::TransitionFailure, DapVersion};
use futures::future::try_join_all;
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

    async fn to_checked(&self, nonce_hex: String) -> Result<Option<(String, TransitionFailure)>> {
        if let ReportStoreResult::Err(failure_reason) = self.checked_process(&nonce_hex).await? {
            Ok(Some((nonce_hex, failure_reason)))
        } else {
            Ok(None)
        }
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
        let durable = DurableConnector::new(&self.env);
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
                // development environments by never clearing the agg job queue if a workaround flag
                // is set. Note that it is necessary to restart miniflare between test runs in order
                // to reset the DO state.
                if empty
                    && self
                        .env
                        .var("DAP_ISSUE73_DISABLE_AGG_JOB_QUEUE_GARBAGE_COLLECTION")?
                        .to_string()
                        == "true"
                {
                    let agg_job: Option<AggregationJob> = state_get(&self.state, "agg_job").await?;
                    if let Some(agg_job) = agg_job {
                        // NOTE There is only one agg job queue for now. In the future, work will
                        // be sharded across multiple queues.
                        durable
                            .post(
                                BINDING_DAP_LEADER_AGG_JOB_QUEUE,
                                DURABLE_LEADER_AGG_JOB_QUEUE_FINISH,
                                durable_queue_name(0),
                                &agg_job,
                            )
                            .await?;
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

                    // TODO Shard the work across multiple job queues rather than just one. (See
                    // issue #25.) For now there is jsut one job queue.
                    durable
                        .post(
                            BINDING_DAP_LEADER_AGG_JOB_QUEUE,
                            DURABLE_LEADER_AGG_JOB_QUEUE_PUT,
                            durable_queue_name(0),
                            &agg_job,
                        )
                        .await?;
                    self.state.storage().put("agg_job", agg_job).await?;
                }
                Response::from_json(&res)
            }

            (DURABLE_REPORT_STORE_PUT_PROCESSED, Method::Post) => {
                let nonce_hex_set: Vec<String> = req.json().await?;
                let mut requests = Vec::new();
                for nonce_hex in nonce_hex_set.into_iter() {
                    requests.push(self.to_checked(nonce_hex));
                }

                let responses: Vec<Option<(String, TransitionFailure)>> =
                    try_join_all(requests).await?;
                let res: Vec<(String, TransitionFailure)> =
                    responses.into_iter().flatten().collect();
                Response::from_json(&res)
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
    // task_id (32 bytes) + time (8 bytes)
    if report_hex.len() < 80 {
        return None;
    }
    let report_hex = &report_hex[80..];

    // nonce
    if report_hex.len() < 32 {
        return None;
    }
    Some(&report_hex[..32])
}
