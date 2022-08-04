// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{state_get, BINDING_DAP_HELPER_STATE_STORE},
    int_err,
};
use daphne::messages::Id;
use worker::*;

pub(crate) fn durable_helper_state_name(task_id: &Id, agg_job_id: &Id) -> String {
    format!(
        "/task/{}/agg_job/{}",
        task_id.to_base64url(),
        agg_job_id.to_base64url()
    )
}

pub(crate) const DURABLE_HELPER_STATE_PUT: &str = "/internal/do/helper_state/put";
pub(crate) const DURABLE_HELPER_STATE_GET: &str = "/internal/do/helper_state/get";

/// Durable Object (DO) for storing the Helper's state for a given aggregation job.
///
/// An instance of the [`LeaderStateStore`] DO is named `/task/<task_id>/agg_job/<agg_job_id>`,
/// where `<task_id>` is the task ID and `<agg_job_id>` is the aggregation job ID.
#[durable_object]
pub struct HelperStateStore {
    #[allow(dead_code)]
    state: State,
    env: Env,
    touched: bool,
}

#[durable_object]
impl DurableObject for HelperStateStore {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            touched: false,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let id_hex = self.state.id().to_string();
        ensure_garbage_collected!(req, self, id_hex, BINDING_DAP_HELPER_STATE_STORE);

        match (req.path().as_ref(), req.method()) {
            (DURABLE_HELPER_STATE_PUT, Method::Post) => {
                // The state is handled as an opaque hex string.
                let mut helper_state: Option<String> =
                    state_get(&self.state, "helper_state").await?;
                if helper_state.is_some() {
                    // TODO spec: Handle this as an abort rather than an internal error.
                    return Err(int_err("tried to overwrite helper state"));
                }

                helper_state = req.json().await?;
                self.state
                    .storage()
                    .put("helper_state", helper_state)
                    .await?;
                Response::empty()
            }

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
}
