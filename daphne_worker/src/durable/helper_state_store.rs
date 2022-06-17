// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::utils::int_err;
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

const OK: &str = "Ok";

/// Durable Object (DO) for storing the Helper's state for a given aggregation job.
///
/// An instance of the [`LeaderStateStore`] DO is named `/task/<task_id>/agg_job/<agg_job_id>`,
/// where `<task_id>` is the task ID and `<agg_job_id>` is the aggregation job ID.
#[durable_object]
pub struct HelperStateStore {
    // A hex-encoded helper state blob. The DO instance is bound to the aggregation job, so one
    // instance of the helper state is sufficient.
    //
    // TODO Make this persistent. It should "expire" after about an hour.
    helper_state: Option<String>,
    #[allow(dead_code)]
    state: State,
}

#[durable_object]
impl DurableObject for HelperStateStore {
    fn new(state: State, _env: Env) -> Self {
        Self {
            helper_state: None,
            state,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            (DURABLE_HELPER_STATE_PUT, Method::Post) => {
                if self.helper_state.is_some() {
                    return Err(int_err("tried to overwrite helper state"));
                }

                self.helper_state = Some(req.json().await?);
                Response::ok(OK)
            }

            (DURABLE_HELPER_STATE_GET, Method::Post) => {
                if let Some(helper_state) = self.helper_state.to_owned() {
                    self.helper_state = None;
                    return Response::from_json(&helper_state);
                }

                Err(int_err("tried to get helper state before it was put"))
            }

            _ => Err(int_err(format!(
                "HelperStateStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}
