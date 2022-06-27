// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::int_err;
use daphne::messages::{Nonce, Report, TransitionFailure};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryInto};
use worker::*;

pub(crate) fn durable_report_store_name(
    task_id_base64url: &str,
    window: u64,
    bucket: u64,
) -> String {
    format!(
        "/task/{}/window/{}/bucket/{}",
        task_id_base64url, window, bucket
    )
}

pub(crate) const DURABLE_REPORT_STORE_DELETE_ALL: &str = "/internal/do/report_store/delete_all";
pub(crate) const DURABLE_REPORT_STORE_GET_PENDING: &str = "/internal/do/report_store/get_pending";
pub(crate) const DURABLE_REPORT_STORE_PUT_PENDING: &str = "/internal/do/report_store/put_pending";
pub(crate) const DURABLE_REPORT_STORE_PUT_PROCESSED: &str =
    "/internal/do/report_store/put_processed";
pub(crate) const DURABLE_REPORT_STORE_MARK_COLLECTED: &str =
    "/internal/do/report_store/mark_collected";

const INITIAL_CAPACITY: usize = 100;

macro_rules! checked_process {
    (
        $store:expr,
        $nonce:expr
    ) => {{
        let observed = $store.processed.contains($nonce);
        if observed && !$store.collected {
            return Response::from_json(&ReportStoreResult::Err(TransitionFailure::ReportReplayed));
        } else if !observed && $store.collected {
            return Response::from_json(&ReportStoreResult::Err(TransitionFailure::BatchCollected));
        }
        $store.processed.insert($nonce.clone());
    }};
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ReportStoreGetPending {
    pub(crate) reports_requested: u64,
}

#[derive(Deserialize, Serialize)]
pub(crate) enum ReportStoreResult {
    Ok,
    Err(TransitionFailure),
}

/// Durable Object (DO) for storing reports and report metadata.
///
/// The naming convention for instances of the [`ReportStore`] DO is as follows:
///
/// > /task/<task_id>/window/<window>/bucket/<bucket>
///
/// where `<task_id>` is a task ID, `<window>` is a batch window, and `<bucket>` is a non-negative
/// integer. A batch window is a UNIX timestamp (in seconds) truncated by the minimum batch
/// duration. The instance in which a report is stored is derived from the task ID and nonce of the
/// report itself.
#[durable_object]
pub struct ReportStore {
    // TODO Write this to persistent storage instead of keeping it in memory. (See
    // https://developers.cloudflare.com/workers/learning/using-durable-objects#in-memory-state-in-a-durable-object.)
    pending: Vec<Report>,
    // TODO Back this up in persistent storage.
    processed: HashSet<Nonce>,
    // TODO Back this up in persistent storage.
    collected: bool,
    #[allow(dead_code)]
    state: State,
}

#[durable_object]
impl DurableObject for ReportStore {
    fn new(state: State, _env: Env) -> Self {
        Self {
            pending: Vec::with_capacity(INITIAL_CAPACITY),
            processed: HashSet::with_capacity(INITIAL_CAPACITY),
            collected: false,
            state,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            (DURABLE_REPORT_STORE_DELETE_ALL, Method::Post) => {
                self.pending.clear();
                self.processed.clear();
                self.collected = false;
                Response::from_json(&ReportStoreResult::Ok)
            }

            (DURABLE_REPORT_STORE_GET_PENDING, Method::Post) => {
                let info: ReportStoreGetPending = req.json().await?;

                // TODO Keep reports for as long as they can be observed. I.e., instead of
                // draining the reports, just advance an index into the `self.reports` vector
                // pointing to the next report to output. This also prevents data loss if the
                // caller encounters an internal error and has to drop the reports.
                let reports_drained = std::cmp::min(
                    info.reports_requested.try_into().unwrap(),
                    self.pending.len(),
                );
                let reports: Vec<Report> = self.pending.drain(..reports_drained).collect();

                Response::from_json(&reports)
            }

            (DURABLE_REPORT_STORE_PUT_PENDING, Method::Post) => {
                // BUG The following would be more idiomatic here:
                //
                //    let report: Report = req.json().await?;
                //
                // However there appears to be a bug somewhere (perhaps in wasm-bindgen?) that
                // causes the last few bits of nonce.rand to get cleared.
                let report: Report = match serde_json::from_str(&req.text().await?)? {
                    Some(report) => report,
                    None => return Err(int_err("Failed to parse report")),
                };

                checked_process!(self, &report.nonce);
                self.pending.push(report);
                Response::from_json(&ReportStoreResult::Ok)
            }

            (DURABLE_REPORT_STORE_PUT_PROCESSED, Method::Post) => {
                let nonce = req.json().await?;
                checked_process!(self, &nonce);
                Response::from_json(&ReportStoreResult::Ok)
            }

            (DURABLE_REPORT_STORE_MARK_COLLECTED, Method::Post) => {
                self.collected = true;
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
