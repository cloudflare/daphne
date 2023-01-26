// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    config::DaphneWorkerConfig,
    durable::{state_set_if_not_exists, BINDING_DAP_REPORTS_PROCESSED},
    initialize_tracing, int_err,
};
use futures::future::try_join_all;
use std::time::Duration;
use worker::*;

pub(crate) const DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED: &str =
    "/internal/do/report_store/mark_aggregated";

/// Durable Object (DO) for tracking which reports have been processed.
///
/// This object defines a single API endpoint, `DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED`, which
/// is used to mark a set of reports as aggregated. It returns the set of reports in that have
/// already been aggregated (and thus need to be rejected by the caller).
///
/// The schema for stored report IDs is as follows:
///
/// ```text
///     processed/<report_id> -> bool
/// ```
///
/// where `<report_id>` is the hex-encoded report ID.
#[durable_object]
pub struct ReportsProcessed {
    #[allow(dead_code)]
    state: State,
    env: Env,
    config: DaphneWorkerConfig,
    touched: bool,
    alarmed: bool,
}

impl ReportsProcessed {
    /// Check if the report has been processed. If not, return None; otherwise, return the ID.
    async fn to_checked(&self, report_id_hex: String) -> Result<Option<String>> {
        let key = format!("processed/{report_id_hex}");
        let processed: bool = state_set_if_not_exists(&self.state, &key, &true)
            .await?
            .unwrap_or(false);
        if processed {
            Ok(Some(report_id_hex))
        } else {
            Ok(None)
        }
    }
}

#[durable_object]
impl DurableObject for ReportsProcessed {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerConfig::from_worker_env(&env).expect("failed to load configuration");
        Self {
            state,
            env,
            config,
            touched: false,
            alarmed: false,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let id_hex = self.state.id().to_string();
        ensure_garbage_collected!(req, self, id_hex.clone(), BINDING_DAP_REPORTS_PROCESSED);
        ensure_alarmed!(
            self,
            Duration::from_secs(self.config.global.report_storage_epoch_duration)
                .saturating_add(self.config.processed_alarm_safety_interval)
        );

        match (req.path().as_ref(), req.method()) {
            // Mark a set of reports as aggregated. Return the set of report IDs that already
            // exist.
            //
            // Input: `report_id_hex_set: Vec<String>` (hex-encoded report IDs)
            // Output: `Vec<String>` (subset of the inputs that already exist).
            (DURABLE_REPORTS_PROCESSED_MARK_AGGREGATED, Method::Post) => {
                let report_id_hex_set: Vec<String> = req.json().await?;
                let mut requests = Vec::new();
                for report_id_hex in report_id_hex_set.into_iter() {
                    requests.push(self.to_checked(report_id_hex));
                }

                let responses: Vec<Option<String>> = try_join_all(requests).await?;
                let res: Vec<String> = responses.into_iter().flatten().collect();
                Response::from_json(&res)
            }

            _ => Err(int_err(format!(
                "ReportsProcessed: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    async fn alarm(&mut self) -> Result<Response> {
        self.state.storage().delete_all().await?;
        self.alarmed = false;
        self.touched = false;
        Response::from_json(&())
    }
}
