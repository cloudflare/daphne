// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{req_parse, GcDurableObject};
use crate::int_err;
use daphne::messages::{AggregationJobId, ReportId};
use daphne_service_utils::durable_requests::bindings::{self, replay_checker, DurableMethod};
use std::{
    collections::{HashMap, HashSet},
    iter::zip,
    sync::OnceLock,
    time::Duration,
};
use wasm_bindgen::JsValue;
use worker::{js_sys, Env, Request, Response, Result, ScheduledTime, State};

super::mk_durable_object! {
    /// Where report ids are stored for replay protection.
    ///
    /// We store all report ids (of this shard) associated with the aggregation job id that first
    /// introduced that id. Since aggregation jobs can't change once submited and since no two
    /// jobs can contain the same report id.
    ///
    /// For every report id that arrives at this DO one of three things can happen:
    /// - The report id has never been seen before:
    ///     => We store it along with the agg job id it was seen with
    ///     => We don't return it in the duplicates set
    ///
    /// - The report id has been seen but belongs to the associated agg job id:
    ///     => We don't return it in the duplicates set
    ///
    /// - The report id has been seen but belongs to a different agg job id:
    ///     => We return it in duplicates set
    ///
    ///
    /// This is only correct for as long as two invariants are upheld somewhere else in the code:
    /// - We stricly require aggregation jobs to not change once submited (this is required per the DAP spec)
    /// - All storage operations after this point that rely on replay protection are idempotent.
    struct ReplayChecker {
        state: State,
        env: Env,
        seen: HashMap<ReportId, AggregationJobId>,
    }
}

impl GcDurableObject for ReplayChecker {
    type DurableMethod = bindings::AggregateStore;

    fn with_state_and_env(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            seen: Default::default(),
        }
    }

    async fn handle(&mut self, mut req: Request) -> Result<Response> {
        match replay_checker::Command::try_from_uri(&req.path()) {
            Some(replay_checker::Command::Check) => {
                let replay_checker::Request {
                    report_ids,
                    agg_job_id,
                } = req_parse(&mut req).await?;

                let mut duplicates = HashSet::new();

                // Check the cache for duplicates and compute the set of report IDs we need to read
                // from the disk.
                let report_ids_as_string = report_ids
                    .iter()
                    .filter(|r| match self.seen.get(r) {
                        Some(cached_agg_job_id) => {
                            if *cached_agg_job_id != agg_job_id {
                                duplicates.insert(**r);
                            }
                            false // skip checking
                        }
                        None => true, // check against disk
                    })
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();

                let agg_job_id_as_str = agg_job_id.to_string();

                let result = self
                    .state
                    .storage()
                    .get_multiple(report_ids_as_string.clone())
                    .await?;

                let obj_to_update = js_sys::Object::new();
                for (id, as_str) in zip(report_ids.iter(), &report_ids_as_string) {
                    self.seen.insert(*id, agg_job_id);

                    let v = result.get(&JsValue::from_str(as_str));
                    if let Some(stored_agg_job_id) = v.as_string() {
                        if stored_agg_job_id != agg_job_id_as_str {
                            duplicates.insert(*id);
                        }
                    } else {
                        js_sys::Reflect::set(
                            &obj_to_update,
                            &JsValue::from_str(as_str),
                            &JsValue::from_str(agg_job_id_as_str.as_ref()),
                        )?;
                    }
                }

                self.state.storage().put_multiple_raw(obj_to_update).await?;

                Response::from_json(&replay_checker::Response { duplicates })
            }
            None => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    fn should_cleanup_at(&self) -> Option<ScheduledTime> {
        const VAR_NAME: &str = "DO_REPLAY_CHECKER_GC_SECS";
        static SELF_DELETE_AFTER: OnceLock<Duration> = OnceLock::new();

        let duration = SELF_DELETE_AFTER.get_or_init(|| {
            Duration::from_secs(
                self.env
                    .var(VAR_NAME)
                    .map(|v| {
                        v.to_string().parse().unwrap_or_else(|e| {
                            panic!("{VAR_NAME} could not be parsed as a number of seconds: {e}")
                        })
                    })
                    .unwrap_or(60 * 60 * 24 * 7), // one week
            )
        });

        Some(ScheduledTime::from(*duration))
    }
}
