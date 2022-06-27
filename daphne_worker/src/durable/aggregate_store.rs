// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::int_err;
use daphne::DapAggregateShare;
use worker::*;

pub(crate) fn durable_agg_store_name(task_id_base64url: &str, window: u64) -> String {
    format!("/task/{}/window/{}", task_id_base64url, window)
}

pub(crate) const DURABLE_AGGREGATE_STORE_DELETE_ALL: &str =
    "/internal/do/aggregate_store/delete_all";
pub(crate) const DURABLE_AGGREGATE_STORE_GET: &str = "/internal/do/aggregate_store/get";
pub(crate) const DURABLE_AGGREGATE_STORE_MERGE: &str = "/internal/do/aggregate_store/merge";

const OK: &str = "Ok";

/// Durable Object (DO) for storing aggregate shares.
///
/// The naming conventions for instances of the [`AggregateStore`] DO is as follows:
///
/// > /task/<task_id>/window/<window>
///
/// where `<task_id>` is a task ID, `<window>` is a batch window. A batch window is a UNIX
/// timestamp (in seconds) truncated by the minimum batch duration.
#[durable_object]
pub struct AggregateStore {
    // TODO Write this to persistent storage instead of keeping it in memory.
    agg_share: DapAggregateShare,
    #[allow(dead_code)]
    state: State,
}

#[durable_object]
impl DurableObject for AggregateStore {
    fn new(state: State, _env: Env) -> Self {
        Self {
            agg_share: DapAggregateShare::default(),
            state,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            (DURABLE_AGGREGATE_STORE_DELETE_ALL, Method::Post) => {
                self.agg_share.reset();
                Response::ok(OK)
            }

            (DURABLE_AGGREGATE_STORE_MERGE, Method::Post) => {
                let agg_share_delta = req.json().await?;
                self.agg_share.merge(agg_share_delta).map_err(int_err)?;

                Response::ok(OK)
            }

            (DURABLE_AGGREGATE_STORE_GET, Method::Post) => Response::from_json(&self.agg_share),

            _ => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}
