// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{state_get_or_default, BINDING_DAP_AGGREGATE_STORE},
    int_err,
};
use daphne::{DapAggregateShare, DapVersion};
use serde::{Deserialize, Serialize};
use worker::*;

pub(crate) fn durable_agg_store_name(
    version: &DapVersion,
    task_id_hex: &str,
    window: u64,
) -> String {
    format!(
        "{}/task/{}/window/{}",
        version.as_ref(),
        task_id_hex,
        window
    )
}

pub(crate) const DURABLE_AGGREGATE_STORE_GET: &str = "/internal/do/aggregate_store/get";
pub(crate) const DURABLE_AGGREGATE_STORE_MERGE: &str = "/internal/do/aggregate_store/merge";
pub(crate) const DURABLE_AGGREGATE_STORE_MARK_COLLECTED: &str =
    "/internal/do/aggregate_store/mark_collected";

#[derive(Deserialize, Serialize)]
pub(crate) enum AggregateStoreResult {
    Ok(DapAggregateShare),
    ErrBatchOverlap,
}

/// Durable Object (DO) for storing aggregate shares.
///
/// The naming conventions for instances of the [`AggregateStore`] DO is as follows:
///
/// > <version>/task/<task_id>/window/<window>
///
/// where <version> is the DAP version (e.g., "v01"), `<task_id>` is a task ID, `<window>` is a
/// batch window. A batch window is a UNIX timestamp (in seconds) truncated by the minimum batch
/// duration.
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
            (DURABLE_AGGREGATE_STORE_MERGE, Method::Post) => {
                let mut agg_share: DapAggregateShare =
                    state_get_or_default(&self.state, "agg_share").await?;
                let agg_share_delta = req.json().await?;
                agg_share.merge(agg_share_delta).map_err(int_err)?;
                self.state.storage().put("agg_share", agg_share).await?;
                Response::empty()
            }

            (DURABLE_AGGREGATE_STORE_GET, Method::Post) => {
                // NOTE: The following logic is correct for `max_batch_lifetime = 1`, but
                // requires changes when we allow batch lifetime longer than 1.
                let agg_share: DapAggregateShare =
                    state_get_or_default(&self.state, "agg_share").await?;
                let collected: bool = state_get_or_default(&self.state, "collected").await?;
                if !collected {
                    Response::from_json(&AggregateStoreResult::Ok(agg_share))
                } else {
                    Response::from_json(&AggregateStoreResult::ErrBatchOverlap)
                }
            }

            (DURABLE_AGGREGATE_STORE_MARK_COLLECTED, Method::Post) => {
                self.state.storage().put("collected", true).await?;
                Response::empty()
            }

            _ => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}
