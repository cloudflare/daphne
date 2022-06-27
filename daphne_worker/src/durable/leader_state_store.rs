// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::int_err;
use daphne::{
    messages::{CollectReq, CollectResp, Id},
    DapCollectJob,
};
use prio::codec::Encode;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryInto};
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
    // TODO Write this to persistent storage instead of keeping it in memory.
    collect_req_pending: HashMap<Id, OrderedCollectReq>,
    collect_req_processed: HashMap<Id, CollectResp>,
    next_priority: usize,
    #[allow(dead_code)]
    state: State,
}

#[durable_object]
impl DurableObject for LeaderStateStore {
    fn new(state: State, _env: Env) -> Self {
        Self {
            collect_req_pending: HashMap::new(),
            collect_req_processed: HashMap::new(),
            next_priority: 0,
            state,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match (req.path().as_ref(), req.method()) {
            (DURABLE_LEADER_STATE_DELETE_ALL, Method::Post) => {
                self.collect_req_pending.drain();
                self.collect_req_processed.drain();
                self.next_priority = 0;
                Response::empty()
            }

            // Store a CollectReq issued by the collector.
            (DURABLE_LEADER_STATE_PUT_COLLECT_REQ, Method::Post) => {
                // TODO Consider disallowing overlapping collect requests. Would this require a
                // spec change?
                //
                // TODO Figure out if we can avoid re-serializing by passing raw bytes here instead
                // of JSON.
                let collect_req: CollectReq = req.json().await?;
                let collect_req_digest = digest(&SHA256, &collect_req.get_encoded());
                let collect_id = Id(collect_req_digest.as_ref().try_into().unwrap());
                let resp = Response::from_json(&collect_id);
                if self.collect_req_processed.get(&collect_id).is_none()
                    && self.collect_req_pending.get(&collect_id).is_none()
                {
                    self.collect_req_pending.insert(
                        collect_id,
                        OrderedCollectReq {
                            priority: self.next_priority,
                            collect_req,
                        },
                    );
                    self.next_priority += 1;
                }
                resp
            }

            // Retrieve the list of pending CollectReqs.
            (DURABLE_LEADER_STATE_GET_COLLECT_REQS, Method::Get) => {
                // Return a list of (Id, CollectReq) in order of arrival.
                let mut res: Vec<(&Id, &OrderedCollectReq)> =
                    self.collect_req_pending.iter().collect();
                res.sort_unstable_by_key(|(_id, prioritized)| prioritized.priority);
                let res: Vec<(&Id, &CollectReq)> = res
                    .iter()
                    .map(|(id, prioritized)| (*id, &prioritized.collect_req))
                    .collect();
                Response::from_json(&res)
            }

            // Store a CollectResp corresponding to a pending CollectReq.
            (DURABLE_LEADER_STATE_FINISH_COLLECT_REQ, Method::Post) => {
                let update: LeaderStateStoreUpdateCollectReq = req.json().await?;
                if self.collect_req_processed.get(&update.collect_id).is_some() {
                    return Err(int_err(
                        "LeaderStateStore: tried to overwrite collect response",
                    ));
                }

                if self.collect_req_pending.get(&update.collect_id).is_none() {
                    return Err(int_err("LeaderStateStore: missing collect request"));
                }

                self.collect_req_processed
                    .insert(update.collect_id, update.collect_resp);
                Response::empty()
            }

            // Retrieve a completed CollectResp.
            (DURABLE_LEADER_STATE_GET_COLLECT_RESP, Method::Post) => {
                let collect_id = req.json().await?;
                if self.collect_req_pending.get(&collect_id).is_none() {
                    return Response::from_json(&DapCollectJob::Unknown);
                }

                if let Some((_, collect_resp)) =
                    self.collect_req_processed.remove_entry(&collect_id)
                {
                    self.collect_req_pending.remove(&collect_id);
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
