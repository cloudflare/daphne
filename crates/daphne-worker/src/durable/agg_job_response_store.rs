// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Durable Object for storing the result of an aggregation job.

use super::{req_parse, GcDurableObject};
use crate::int_err;
use daphne::protocol::ReadyAggregationJobResp;
use daphne_service_utils::durable_requests::bindings::{
    self, agg_job_response_store, DurableMethod as _,
};
use std::{sync::OnceLock, time::Duration};
use worker::{js_sys, Env, Request, Response, Result, ScheduledTime, State};

const AGGREGATE_RESPONSE_CHUNK_KEY_PREFIX: &str = "dap_agg_response_chunk";

super::mk_durable_object! {
    struct AggregationJobResp {
        state: State,
        env: Env,
        agg_job_resp: Option<ReadyAggregationJobResp>,
    }
}

impl AggregationJobResp {
    async fn get_agg_job_response(&mut self) -> Result<Option<&ReadyAggregationJobResp>> {
        let agg_job_resp = if let Some(agg_job_resp) = self.agg_job_resp.take() {
            agg_job_resp
        } else {
            let Some(agg_job_resp) = self
                .load_chuncked_value(AGGREGATE_RESPONSE_CHUNK_KEY_PREFIX)
                .await?
            else {
                return Ok(None);
            };
            agg_job_resp
        };

        self.agg_job_resp = Some(agg_job_resp);

        Ok(self.agg_job_resp.as_ref())
    }

    fn put_agg_job_response(&mut self, resp: ReadyAggregationJobResp) -> Result<js_sys::Object> {
        let obj = self.serialize_chunked_value(AGGREGATE_RESPONSE_CHUNK_KEY_PREFIX, &resp, None)?;
        self.agg_job_resp = Some(resp);
        Ok(obj)
    }
}

impl GcDurableObject for AggregationJobResp {
    type DurableMethod = bindings::AggregateStore;

    fn with_state_and_env(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            agg_job_resp: None,
        }
    }

    async fn handle(&mut self, mut req: Request) -> Result<Response> {
        match agg_job_response_store::Command::try_from_uri(&req.path()) {
            // Store an aggregate share and aggregation job response.
            //
            // Idempotent
            // Input: `agg_share_dellta: agg_job_result_store::FinishRequest`
            // Output: `agg_job_result_store::FinishResponse`
            Some(agg_job_response_store::Command::Put) => {
                let response = req_parse::<ReadyAggregationJobResp>(&mut req).await?;

                self.state
                    .storage()
                    .put_multiple_raw(self.put_agg_job_response(response)?)
                    .await?;

                Response::from_json(&())
            }

            // Get the AggregationJobResp
            //
            // Idempotent
            // Output: `Option<ReadyAggregationJobResp>`
            Some(agg_job_response_store::Command::Get) => {
                let response = self.get_agg_job_response().await?;
                Response::from_json(&response)
            }

            None => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    fn should_cleanup_at(&self) -> Option<ScheduledTime> {
        const VAR_NAME: &str = "DAP_DURABLE_AGGREGATE_STORE_GC_AFTER_SECS";
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
