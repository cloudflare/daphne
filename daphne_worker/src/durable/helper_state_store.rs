// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    config::DaphneWorkerConfig,
    durable::{create_span_from_request, state_get, state_set_if_not_exists},
    initialize_tracing, int_err,
};
use daphne::{messages::TaskId, DapVersion, MetaAggregationJobId};
use tracing::{trace, Instrument};
use worker::*;

use super::{Alarmed, DapDurableObject};

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

pub(crate) const DURABLE_HELPER_STATE_PUT_IF_NOT_EXISTS: &str =
    "/internal/do/helper_state/put_if_not_exists";
pub(crate) const DURABLE_HELPER_STATE_GET: &str = "/internal/do/helper_state/get";

/// Durable Object (DO) for storing the Helper's state for a given aggregation job.
///
/// This object implements the following API endpoints:
///
/// - `DURABLE_HELPER_STATE_PUT_IF_NOT_EXISTS`: Stores Helper's hex-encoded state unless the state
///    already exists. Returns a boolean indicating whether the operation succeeded.
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

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        // Ensure this DO instance is garbage collected eventually.
        self.ensure_alarmed(
            self.config
                .helper_state_store_garbage_collect_after_secs
                .expect("Daphne-Worker not configured as helper"),
        )
        .await?;

        let span = create_span_from_request(&req);
        self.handle(req).instrument(span).await
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

impl HelperStateStore {
    async fn handle(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            // Store the Helper's state.
            //
            // Non-idempotent
            // Input: `helper_state_hex: String` (hex-encoded state)
            // Output: `bool`
            (DURABLE_HELPER_STATE_PUT_IF_NOT_EXISTS, Method::Post) => {
                let helper_state_hex: String = req.json().await?;
                let success =
                    state_set_if_not_exists(&self.state, "helper_state", &helper_state_hex)
                        .await?
                        .is_none();
                Response::from_json(&success)
            }

            // Get the Helper's state.
            //
            // Idempotent
            // Output: `String` (hex-encoded state)
            (DURABLE_HELPER_STATE_GET, Method::Get) => {
                let helper_state: Option<String> = state_get(&self.state, "helper_state").await?;
                Response::from_json(&helper_state)
            }

            _ => Err(int_err(format!(
                "HelperStateStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

impl DapDurableObject for HelperStateStore {
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
impl Alarmed for HelperStateStore {
    #[inline(always)]
    fn alarmed(&mut self) -> &mut bool {
        &mut self.alarmed
    }
}
