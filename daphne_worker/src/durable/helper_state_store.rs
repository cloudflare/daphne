// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{state_get, DURABLE_DELETE_ALL},
    int_err,
};
use daphne::{messages::Id, DapVersion};
use worker::*;

pub(crate) fn durable_helper_state_name(
    version: &DapVersion,
    task_id: &Id,
    agg_job_id: &Id,
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
/// An instance of the [`LeaderStateStore`] DO is named
///
/// > <version>/task/<task_id>/agg_job/<agg_job_id>
///
/// where `<version>` is the DAP version, `<task_id>` is the task ID and `<agg_job_id>` is the
/// aggregation job ID.
//
// TODO Consider adding garbage collection for this DO. We are foregoing garbage collection for
// performance reasons. This DO is "self-cleaning" under normal operation, but if the Leader
// abandons an aggregation job before the last request, then the state would remain in storage
// indefinitely.
#[durable_object]
pub struct HelperStateStore {
    state: State,
    helper_state: Option<String>,
}

#[durable_object]
impl DurableObject for HelperStateStore {
    fn new(state: State, _env: Env) -> Self {
        Self {
            state,
            helper_state: None,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            (DURABLE_DELETE_ALL, Method::Post) => {
                self.state.storage().delete_all().await?;
                self.helper_state = None;
                Response::empty()
            }

            // Store the given state blob, overwriting the current state blob if it exists.
            (DURABLE_HELPER_STATE_PUT, Method::Post) => {
                let helper_state = req.json().await?;
                self.state
                    .storage()
                    .put("helper_state", &helper_state)
                    .await?;
                self.helper_state = Some(helper_state);
                Response::empty()
            }

            // Fetch the current state blob and delete it from storage.
            (DURABLE_HELPER_STATE_GET, Method::Post) => {
                if self.helper_state.is_none() {
                    self.helper_state = state_get(&self.state, "helper_state").await?;
                }
                self.state.storage().delete_all().await?;
                let helper_state = std::mem::replace(&mut self.helper_state, None);
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
