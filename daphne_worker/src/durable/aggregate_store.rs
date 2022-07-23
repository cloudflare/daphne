// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{state_get_or_default, DURABLE_DELETE_ALL},
    int_err,
};
use daphne::DapAggregateShare;
use worker::*;

pub(crate) fn durable_agg_store_name(task_id_base64url: &str, window: u64) -> String {
    format!("/task/{}/window/{}", task_id_base64url, window)
}

pub(crate) const DURABLE_AGGREGATE_STORE_GET: &str = "/internal/do/aggregate_store/get";
pub(crate) const DURABLE_AGGREGATE_STORE_MERGE: &str = "/internal/do/aggregate_store/merge";

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
    #[allow(dead_code)]
    state: State,
}

#[durable_object]
impl DurableObject for AggregateStore {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            (DURABLE_DELETE_ALL, Method::Post) => {
                self.state.storage().delete_all().await?;
                Response::empty()
            }

            (DURABLE_AGGREGATE_STORE_MERGE, Method::Post) => {
                let mut agg_share: DapAggregateShare =
                    state_get_or_default(&self.state, "agg_share").await?;
                let agg_share_delta = req.json().await?;
                agg_share.merge(agg_share_delta).map_err(int_err)?;
                self.state.storage().put("agg_share", agg_share).await?;
                Response::empty()
            }

            (DURABLE_AGGREGATE_STORE_GET, Method::Post) => {
                let agg_share: DapAggregateShare =
                    state_get_or_default(&self.state, "agg_share").await?;
                Response::from_json(&agg_share)
            }

            _ => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}
