// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Durable Object (DO) for storing the Helper's state for a given aggregation job.
//!
//! This object implements the following API endpoints:
//!
//! - `DURABLE_HELPER_STATE_PUT_IF_NOT_EXISTS`: Stores Helper's hex-encoded state unless the state
//!    already exists. Returns a boolean indicating whether the operation succeeded.
//! - `DURABLE_HELPER_STATE_GET`: Drains the Helper's hex-encoded state.
//!
//! The state blob is stored in `helper_state`.

use std::{sync::OnceLock, time::Duration};

use crate::int_err;
use daphne_service_utils::durable_requests::bindings::{self, DurableMethod};
use worker::{Env, Request, Response, Result, ScheduledTime, State};

use super::{req_parse, GcDurableObject};

super::mk_durable_object! {
    /// Where the helper state is stored. For the binding name see its
    /// [`BINDING`](bindings::HelperState::BINDING)
    struct HelperStateStore {
        state: State,
        env: Env,
    }
}

impl GcDurableObject for HelperStateStore {
    type DurableMethod = bindings::HelperState;

    fn with_state_and_env(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn handle(&mut self, mut req: Request) -> Result<Response> {
        match bindings::HelperState::try_from_uri(&req.path()) {
            // Store the Helper's state.
            //
            // Non-idempotent
            // Input: `helper_state_hex: String` (hex-encoded state)
            // Output: `bool`
            Some(bindings::HelperState::PutIfNotExists) => {
                let helper_state_hex: String = req_parse(&mut req).await?;
                let success = self
                    .set_if_not_exists("helper_state", &helper_state_hex)
                    .await?
                    .is_none();
                Response::from_json(&success)
            }

            // Get the Helper's state.
            //
            // Idempotent
            // Output: `String` (hex-encoded state)
            Some(bindings::HelperState::Get) => {
                let helper_state: Option<String> = self.get("helper_state").await?;
                Response::from_json(&helper_state)
            }

            _ => Err(int_err(format!(
                "HelperStateStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    fn should_cleanup_at(&self) -> Option<ScheduledTime> {
        const VAR_NAME: &str = "DAP_DURABLE_HELPER_STATE_STORE_GC_AFTER_SECS";
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
