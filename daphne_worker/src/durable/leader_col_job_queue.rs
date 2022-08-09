// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{state_get, state_get_or_default, BINDING_DAP_LEADER_COL_JOB_QUEUE},
    int_err,
};
use daphne::{
    messages::{CollectReq, CollectResp, Id},
    DapCollectJob,
};
use prio::{
    codec::{Decode, Encode},
    vdaf::prg::{Prg, PrgAes128, Seed, SeedStream},
};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, convert::TryInto};
use worker::*;

pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_PUT: &str = "/internal/do/leader_col_job_queue/put";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_GET: &str = "/internal/do/leader_col_job_queue/get";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_FINISH: &str =
    "/internal/do/leader_col_job_queue/finish";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT: &str =
    "/internal/do/leader_col_job_queue/get_result";

#[derive(Debug, Deserialize, Serialize)]
struct OrderedCollectReq {
    priority: usize,
    collect_req: CollectReq,
}

// XXX Rename instance
/// Durable Object (DO) for storing the Leader's state for a given task.
///
/// An instance of the [`LeaderCollectionJobQueue`] DO is named `queue/<queue_num>`, where
/// `<queue_num>` is an integer representing a specific queue.
//
// TODO spec: Consider allowing completed aggregate results to be deleted after a period of time.
#[durable_object]
pub struct LeaderCollectionJobQueue {
    #[allow(dead_code)]
    state: State,
    env: Env,
    touched: bool,
}

#[durable_object]
impl DurableObject for LeaderCollectionJobQueue {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            touched: false,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let id_hex = self.state.id().to_string();
        ensure_garbage_collected!(req, self, id_hex, BINDING_DAP_LEADER_COL_JOB_QUEUE);

        match (req.path().as_ref(), req.method()) {
            // Store a CollectReq issued by the collector.
            (DURABLE_LEADER_COL_JOB_QUEUE_PUT, Method::Post) => {
                let collect_req: CollectReq = req.json().await?;

                // Compute the collect job ID, used to derive the collect URI for this request.
                // This value is computed by applying a pseudorandom function to the request. This
                // has two desirable properties. First, it makes the collect URI unpredictable,
                // which prevents clients from enumerating collect URIs. Second, it provides a
                // stable map from requests to URIs, which prevents us from processing the same
                // collect request more than once.
                let collect_req_bytes = collect_req.get_encoded();
                let collect_id_key_hex = self
                    .env
                    .secret("DAP_COLLECT_ID_KEY")
                    .map_err(|e| format!("failed to load DAP_COLLECT_ID_KEY: {}", e))?
                    .to_string();
                let collect_id_key =
                    Seed::get_decoded(&hex::decode(&collect_id_key_hex).map_err(int_err)?)
                        .map_err(int_err)?;
                let mut collect_id_bytes = [0; 32];
                PrgAes128::seed_stream(&collect_id_key, &collect_req_bytes)
                    .fill(&mut collect_id_bytes);
                let collect_id = Id(collect_id_bytes);
                let collect_id_hex = collect_id.to_hex();

                // If the the request is new, then put it in the job queue.
                let pending_key = format!("pending/{}", collect_id_hex);
                let pending: Option<OrderedCollectReq> =
                    state_get(&self.state, &pending_key).await?;
                let processed: Option<CollectResp> =
                    state_get(&self.state, &format!("processed/{}", collect_id_hex)).await?;
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
                Response::from_json(&collect_id)
            }

            // Retrieve the list of pending CollectReqs.
            (DURABLE_LEADER_COL_JOB_QUEUE_GET, Method::Get) => {
                // Return the list of (Id, CollectReq) in order of arrival.
                //
                // TODO Consider limting the length of the response.
                let opt = ListOptions::new().prefix("pending/");
                let iter = self.state.storage().list_with_options(opt).await?.entries();
                let mut item = iter.next()?;
                let mut list = Vec::new();
                while !item.done() {
                    let (pending_key, ordered_collect_req): (String, OrderedCollectReq) =
                        item.value().into_serde()?;
                    let collect_id_hex = &pending_key["pending/".len()..];
                    let collect_id =
                        Id(hex::decode(collect_id_hex)
                            .map_err(int_err)?
                            .try_into()
                            .map_err(|_| int_err("malformed key for pending CollectReq"))?);
                    list.push((collect_id, ordered_collect_req));
                    item = iter.next()?;
                }

                list.sort_unstable_by_key(|(_id, prioritized)| prioritized.priority);
                let list: VecDeque<(Id, CollectReq)> = list
                    .into_iter()
                    .map(|(id, ordered_collect_req)| (id, ordered_collect_req.collect_req))
                    .collect();
                Response::from_json(&list)
            }

            // Store a CollectResp corresponding to a pending CollectReq.
            (DURABLE_LEADER_COL_JOB_QUEUE_FINISH, Method::Post) => {
                let (collect_id, collect_resp): (Id, CollectResp) = req.json().await?;
                let collect_id_hex = collect_id.to_hex();
                let processed_key = format!("processed/{}", collect_id_hex);
                let processed: Option<CollectResp> = state_get(&self.state, &processed_key).await?;
                if processed.is_some() {
                    return Err(int_err(
                        "LeaderCollectionJobQueue: tried to overwrite collect response",
                    ));
                }

                let mut storage = self.state.storage();
                let pending_key = format!("pending/{}", collect_id_hex);
                let delete_pending_future = storage.delete(&pending_key);
                self.state
                    .storage()
                    .put(&processed_key, collect_resp)
                    .await?;
                delete_pending_future.await?;
                Response::empty()
            }

            // Retrieve a completed CollectResp.
            (DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT, Method::Post) => {
                let collect_id: Id = req.json().await?;
                let collect_id_hex = collect_id.to_hex();
                let pending_key = format!("pending/{}", collect_id_hex);
                let pending: Option<OrderedCollectReq> =
                    state_get(&self.state, &pending_key).await?;
                let processed_key = format!("processed/{}", collect_id_hex);
                let processed: Option<CollectResp> = state_get(&self.state, &processed_key).await?;
                if let Some(collect_resp) = processed {
                    if pending.is_some() {
                        self.state.storage().delete(&pending_key).await?;
                    }
                    Response::from_json(&DapCollectJob::Done(collect_resp))
                } else if pending.is_some() {
                    Response::from_json(&DapCollectJob::Pending)
                } else {
                    Response::from_json(&DapCollectJob::Unknown)
                }
            }

            _ => Err(int_err(format!(
                "LeaderCollectionJobQueue: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}
