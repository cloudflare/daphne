// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{config::DaphneWorkerConfig, durable::state_get, initialize_tracing, int_err};
use daphne::{messages::TaskId, DapVersion, MetaAggregationJobId};
use tracing::{trace, warn};
use worker::*;

pub(crate) fn durable_helper_state_name(
    version: &DapVersion,
    task_id: &TaskId,
    agg_job_id: &MetaAggregationJobId,
) -> String {
    format!(
        "{}/task/{}/agg_job/{}",
        version.as_ref(),
        task_id.to_hex(),
        agg_job_id.to_hex()
    )
}

pub(crate) const DURABLE_HELPER_STATE_PUT: &str = "/internal/do/helper_state/put";
pub(crate) const DURABLE_HELPER_STATE_GET: &str = "/internal/do/helper_state/get";

/// Durable Object (DO) for storing the Helper's state for a given aggregation job.
///
/// This object implements the following API endpoints:
///
/// - `DURABLE_HELPER_STATE_PUT`: Stores Helper's hex-encoded state.
/// - `DURABLE_HELPER_STATE_GET`: Drains the Helper's hex-encoded state.
///
/// The state blob is stored in `helper_state`.
#[durable_object]
pub struct HelperStateStore {
    state: State,
    config: DaphneWorkerConfig,
    alarmed: bool,
}

#[durable_object]
impl DurableObject for HelperStateStore {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerConfig::from_worker_env(&env).expect("failed to load configuration");
        Self {
            state,
            config,
            alarmed: false,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        // Ensure this DO instance is garbage collected eventually.
        ensure_alarmed!(
            self,
            self.config
                .helper_state_store_garbage_collect_after_secs
                .expect("Daphne-Worker not configured as helper")
        );

        match (req.path().as_ref(), req.method()) {
            // Store the Helper's state.
            //
            // Input: `helper_state_hex: String` (hex-encoded state)
            (DURABLE_HELPER_STATE_PUT, Method::Post) => {
                // The state is handled as an opaque hex string.
                let mut helper_state_hex: Option<String> =
                    state_get(&self.state, "helper_state").await?;
                if helper_state_hex.is_some() {
                    // TODO spec: Handle this as an abort rather than an internal error.
                    return Err(int_err("tried to overwrite helper state"));
                }

                helper_state_hex = req.json().await?;
                self.state
                    .storage()
                    .put("helper_state", helper_state_hex)
                    .await?;
                Response::from_json(&())
            }

            // Drain the Helper's state.
            //
            // Output: `String` (hex-encoded state)
            (DURABLE_HELPER_STATE_GET, Method::Post) => {
                let helper_state: Option<String> = state_get(&self.state, "helper_state").await?;
                if helper_state.is_some() {
                    self.state.storage().delete("helper_state").await?;
                }
                Response::from_json(&helper_state)
            }

            _ => Err(int_err(format!(
                "HelperStateStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    async fn alarm(&mut self) -> Result<Response> {
        self.state.storage().delete_all().await?;
        self.alarmed = false;
        trace!(
            "HelperStateStore: deleted instance {}",
            self.state.id().to_string()
        );
        Response::from_json(&())
    }
}
