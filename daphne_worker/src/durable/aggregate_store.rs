// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{state_get_or_default, BINDING_DAP_AGGREGATE_STORE},
    int_err,
};
use daphne::DapAggregateShare;
use worker::*;

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
    touched: bool,
}

#[durable_object]
impl DurableObject for AggregateStore {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            touched: false,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let id_hex = self.state.id().to_string();
        ensure_garbage_collected!(req, self, id_hex, BINDING_DAP_AGGREGATE_STORE);

        match (req.path().as_ref(), req.method()) {
            // Merge an aggregate share into the stored aggregate.
            //
            // Input: `agg_share_dellta: DapAggregateShare`
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
            // Output: `DapAggregateShare`
            (DURABLE_AGGREGATE_STORE_GET, Method::Get) => {
                let agg_share: DapAggregateShare =
                    state_get_or_default(&self.state, "agg_share").await?;
                Response::from_json(&agg_share)
            }

            // Mark this bucket as collected.
            (DURABLE_AGGREGATE_STORE_MARK_COLLECTED, Method::Post) => {
                self.state.storage().put("collected", true).await?;
                Response::from_json(&())
            }

            // Get the value of the flag indicating whether this bucket has been collected
            //
            // Output: `bool`
            (DURABLE_AGGREGATE_STORE_CHECK_COLLECTED, Method::Get) => {
                let collected: bool = state_get_or_default(&self.state, "collected").await?;
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
