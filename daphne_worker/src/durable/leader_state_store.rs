// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{state_get, state_get_or_default},
    int_err,
};
use daphne::{
    messages::{CollectReq, CollectResp, Id},
    DapCollectJob,
};
use prio::codec::Encode;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use worker::*;

pub(crate) fn durable_leader_state_name(task_id: &Id) -> String {
    format!("/task/{}", task_id.to_base64url())
}

pub(crate) const DURABLE_LEADER_STATE_DELETE_ALL: &str = "/internal/do/leader_state/delete_all";
pub(crate) const DURABLE_LEADER_STATE_PUT_COLLECT_REQ: &str =
    "/internal/do/leader_state/put_collect_req";
pub(crate) const DURABLE_LEADER_STATE_GET_COLLECT_REQS: &str =
    "/internal/do/leader_state/get_collect_reqs";
pub(crate) const DURABLE_LEADER_STATE_FINISH_COLLECT_REQ: &str =
    "/internal/do/leader_state/finish_collect_req";
pub(crate) const DURABLE_LEADER_STATE_GET_COLLECT_RESP: &str =
    "/internal/do/leader_state/get_collect_resp";

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct LeaderStateStoreUpdateCollectReq {
    pub(crate) collect_id: Id,
    pub(crate) collect_resp: CollectResp,
}

#[derive(Debug, Deserialize, Serialize)]
struct OrderedCollectReq {
    priority: usize,
    collect_req: CollectReq,
}

/// Durable Object (DO) for storing the Leader's state for a given task.
///
/// An instance of the [`LeaderStateStore`] DO is named `/task/<task_id>`, where `<task_id>` is
/// the task ID.
#[durable_object]
pub struct LeaderStateStore {
    #[allow(dead_code)]
    state: State,
}

#[durable_object]
impl DurableObject for LeaderStateStore {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            (DURABLE_LEADER_STATE_DELETE_ALL, Method::Post) => {
                self.state.storage().delete_all().await?;
                Response::empty()
            }

            // Store a CollectReq issued by the collector.
            (DURABLE_LEADER_STATE_PUT_COLLECT_REQ, Method::Post) => {
                // TODO Disallow overlapping collect requests, as required by
                // draft-ietf-ppm-dap-01.
                let collect_req: CollectReq = req.json().await?;
                let collect_req_digest = digest(&SHA256, &collect_req.get_encoded());
                let collect_id = Id(collect_req_digest.as_ref().try_into().unwrap());
                let collect_id_hex = hex::encode(collect_req_digest);
                let pending_key = format!("pending/{}", collect_id_hex);
                let pending: Option<OrderedCollectReq> =
                    state_get(&self.state, &pending_key).await?;
                let processed: Option<CollectResp> =
                    state_get(&self.state, &format!("processed/{}", collect_id_hex)).await?;
                let resp = Response::from_json(&collect_id);
                if processed.is_none() && pending.is_none() {
                    let next_priority: usize =
                        state_get_or_default(&self.state, "next_priority").await?;
                    self.state
                        .storage()
                        .put(
                            &pending_key,
                            OrderedCollectReq {
                                priority: next_priority,
                                collect_req,
                            },
                        )
                        .await?;
                    self.state
                        .storage()
                        .put("next_priority", next_priority + 1)
                        .await?;
                }
                resp
            }

            // Retrieve the list of pending CollectReqs.
            (DURABLE_LEADER_STATE_GET_COLLECT_REQS, Method::Get) => {
                // Return the list of (Id, CollectReq) in order of arrival.
                //
                // TODO Consider limting the length of the response.
                let opt = ListOptions::new().prefix("pending/");
                let iter = self.state.storage().list_with_options(opt).await?.entries();
                let mut item = iter.next()?;
                let mut res = Vec::new();
                while !item.done() {
                    let (pending_key, ordered_collect_req): (String, OrderedCollectReq) =
                        item.value().into_serde()?;
                    let collect_id_hex = &pending_key["pending/".len()..];
                    let collect_id =
                        Id(hex::decode(collect_id_hex)
                            .map_err(int_err)?
                            .try_into()
                            .map_err(|_| int_err("malformed key for pending CollectReq"))?);
                    res.push((collect_id, ordered_collect_req));
                    item = iter.next()?;
                }

                res.sort_unstable_by_key(|(_id, prioritized)| prioritized.priority);
                let res: Vec<(Id, CollectReq)> = res
                    .into_iter()
                    .map(|(id, prioritized)| (id, prioritized.collect_req))
                    .collect();
                Response::from_json(&res)
            }

            // Store a CollectResp corresponding to a pending CollectReq.
            (DURABLE_LEADER_STATE_FINISH_COLLECT_REQ, Method::Post) => {
                let update: LeaderStateStoreUpdateCollectReq = req.json().await?;
                let collect_id_hex = update.collect_id.to_hex();
                let processed_key = format!("processed/{}", collect_id_hex);
                let processed: Option<CollectResp> = state_get(&self.state, &processed_key).await?;
                if processed.is_some() {
                    return Err(int_err(
                        "LeaderStateStore: tried to overwrite collect response",
                    ));
                }

                let pending: Option<OrderedCollectReq> =
                    state_get(&self.state, &format!("pending/{}", collect_id_hex)).await?;
                if pending.is_none() {
                    return Err(int_err("LeaderStateStore: missing collect request"));
                }

                self.state
                    .storage()
                    .put(&processed_key, update.collect_resp)
                    .await?;
                Response::empty()
            }

            // Retrieve a completed CollectResp.
            (DURABLE_LEADER_STATE_GET_COLLECT_RESP, Method::Post) => {
                let collect_id: Id = req.json().await?;
                let collect_id_hex = collect_id.to_hex();
                let pending_key = format!("pending/{}", collect_id_hex);
                let pending: Option<OrderedCollectReq> =
                    state_get(&self.state, &pending_key).await?;
                if pending.is_none() {
                    return Response::from_json(&DapCollectJob::Unknown);
                }

                let processed_key = format!("processed/{}", collect_id_hex);
                let processed: Option<CollectResp> = state_get(&self.state, &processed_key).await?;
                if let Some(collect_resp) = processed {
                    self.state
                        .storage()
                        .delete_multiple(vec![pending_key, processed_key])
                        .await?;
                    Response::from_json(&DapCollectJob::Done(collect_resp))
                } else {
                    Response::from_json(&DapCollectJob::Pending)
                }
            }

            _ => Err(int_err(format!(
                "LeaderStateStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}
