// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::ControlFlow;

use crate::{
    config::DaphneWorkerConfig,
    durable::{create_span_from_request, state_get_or_default, BINDING_DAP_AGGREGATE_STORE},
    initialize_tracing, int_err,
};
use daphne::DapAggregateShare;
use tracing::Instrument;
use worker::*;

use super::{DapDurableObject, GarbageCollectable};

pub(crate) const DURABLE_AGGREGATE_STORE_GET: &str = "/internal/do/aggregate_store/get";
pub(crate) const DURABLE_AGGREGATE_STORE_MERGE: &str = "/internal/do/aggregate_store/merge";
pub(crate) const DURABLE_AGGREGATE_STORE_MARK_COLLECTED: &str =
    "/internal/do/aggregate_store/mark_collected";
pub(crate) const DURABLE_AGGREGATE_STORE_CHECK_COLLECTED: &str =
    "/internal/do/aggregate_store/check_collected";

/// Durable Object (DO) for storing aggregate shares for a bucket of reports.
///
/// This object defines the following API endpoints:
///
/// - `DURABLE_AGGREGATE_STORE_GET`: Return the current value of the aggregate share.
/// - `DURABLE_AGGREGATE_STORE_MERGE`: Update the aggregate share.
/// - `DURABLE_AGGREGATE_STORE_MARK_COLLECTED`: Mark the bucket as having been collected.
/// - `DURABLE_AGGREGATE_STORE_CHECK_COLLECTED`: Return a boolean indicating if the bucket has been
///   collected.
///
/// The schema for the data stored by this DO is as follows:
///
/// ```text
/// [Aggregate share] agg_share -> DapAggregateShare
/// [Collected flag]  collected -> bool
/// ```
#[durable_object]
pub struct AggregateStore {
    #[allow(dead_code)]
    state: State,
    env: Env,
    config: DaphneWorkerConfig,
    touched: bool,
    collected: Option<bool>,
}

#[durable_object]
impl DurableObject for AggregateStore {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerConfig::from_worker_env(&env).expect("failed to load configuration");
        Self {
            state,
            env,
            config,
            touched: false,
            collected: None,
        }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let span = create_span_from_request(&req);
        self.handle(req).instrument(span).await
    }
}

impl AggregateStore {
    async fn handle(&mut self, req: Request) -> Result<Response> {
        let mut req = match self
            .schedule_for_garbage_collection(req, BINDING_DAP_AGGREGATE_STORE)
            .await?
        {
            ControlFlow::Continue(req) => req,
            // This req was a GC request and as such we must return from this function.
            ControlFlow::Break(_) => return Response::from_json(&()),
        };

        match (req.path().as_ref(), req.method()) {
            // Merge an aggregate share into the stored aggregate.
            //
            // Non-idempotent (do not retry)
            // Input: `agg_share_dellta: DapAggregateShare`
            // Output: `()`
            (DURABLE_AGGREGATE_STORE_MERGE, Method::Post) => {
                let agg_share_delta = req.json().await?;

                // To keep this pair of get and put operations atomic, there should be no await
                // points between them. See the note below `transaction()` on
                // https://developers.cloudflare.com/workers/runtime-apis/durable-objects/#transactional-storage-api.
                // See issue #109.
                let mut agg_share: DapAggregateShare =
                    state_get_or_default(&self.state, "agg_share").await?;
                agg_share.merge(agg_share_delta).map_err(int_err)?;
                self.state.storage().put("agg_share", agg_share).await?;

                Response::from_json(&())
            }

            // Get the current aggregate share.
            //
            // Idempotent
            // Output: `DapAggregateShare`
            (DURABLE_AGGREGATE_STORE_GET, Method::Get) => {
                let agg_share: DapAggregateShare =
                    state_get_or_default(&self.state, "agg_share").await?;
                Response::from_json(&agg_share)
            }

            // Mark this bucket as collected.
            //
            // Non-idempotent (do not retry)
            // Output: `()`
            (DURABLE_AGGREGATE_STORE_MARK_COLLECTED, Method::Post) => {
                self.state.storage().put("collected", true).await?;
                self.collected = Some(true);
                Response::from_json(&())
            }

            // Get the value of the flag indicating whether this bucket has been collected.
            //
            // Idempotent
            // Output: `bool`
            (DURABLE_AGGREGATE_STORE_CHECK_COLLECTED, Method::Get) => {
                let collected = if let Some(collected) = self.collected {
                    collected
                } else {
                    let collected = state_get_or_default(&self.state, "collected").await?;
                    self.collected = Some(collected);
                    collected
                };
                Response::from_json(&collected)
            }

            _ => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

impl DapDurableObject for AggregateStore {
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
impl GarbageCollectable for AggregateStore {
    #[inline(always)]
    fn touched(&mut self) -> &mut bool {
        &mut self.touched
    }

    #[inline(always)]
    fn env(&self) -> &Env {
        &self.env
    }
}
