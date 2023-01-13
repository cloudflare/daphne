// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    config::DaphneWorkerConfig,
    durable::{state_get, state_get_or_default, DurableOrdered, BINDING_DAP_LEADER_COL_JOB_QUEUE},
    initialize_tracing, int_err,
};
use daphne::{
    messages::{CollectReq, CollectResp, Id},
    DapCollectJob, DapVersion,
};
use prio::{
    codec::ParameterizedEncode,
    vdaf::prg::{Prg, PrgAes128, SeedStream},
};
use worker::*;

const PENDING_PREFIX: &str = "pending";
const PROCESSED_PREFIX: &str = "processed";

pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_PUT: &str = "/internal/do/leader_col_job_queue/put";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_GET: &str = "/internal/do/leader_col_job_queue/get";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_FINISH: &str =
    "/internal/do/leader_col_job_queue/finish";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT: &str =
    "/internal/do/leader_col_job_queue/get_result";

/// Durable Object (DO) for storing the Leader's state for a given task.
///
/// This object implements the following API endpoints:
///
/// - `DURABLE_LEADER_COL_JOB_QUEUE_PUT:` Create a collection job for a CollectReq.
/// - `DURABLE_LEADER_COL_JOB_QUEUE_GET`: Get the entire list of pending collection jobs.
/// - `DURABLE_LEADER_COL_JOB_QUEUE_FINISH`: Complete a collection job and store the CollectResp.
/// - `DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT`: Poll the queue to see if a collect job is
///   complete.
///
/// The schema for data stored in instances of this DO is as follows:
///
/// ```text
/// [Pending Lookup ID] pending/id/<collect_id> -> String (reference to queue element)
/// [Pending queue]     pending/next_ordinal -> u64
/// [Pending queue]     pending/item/order/<order> -> (Id, CollectReq)
/// [Processed]         processed/<collect_id> -> CollectResp
/// ```
///
/// Note that the queue ordinal format is inherited from [`DurableOrdered::new_strictly_ordered`].
//
// TODO Implement collection job deletion per the DAP-02.
#[durable_object]
pub struct LeaderCollectionJobQueue {
    #[allow(dead_code)]
    state: State,
    env: Env,
    config: DaphneWorkerConfig,
    touched: bool,
}

#[durable_object]
impl DurableObject for LeaderCollectionJobQueue {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerConfig::from_worker_env(&env).expect("failed to load configuration");
        Self {
            state,
            env,
            config,
            touched: false,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let id_hex = self.state.id().to_string();
        ensure_garbage_collected!(req, self, id_hex, BINDING_DAP_LEADER_COL_JOB_QUEUE);

        match (req.path().as_ref(), req.method()) {
            // Create a collect job for a collect request issued by the Collector.
            //
            // Input: `collect_req: CollectReq`
            // Output: `Id` (collect job ID)
            (DURABLE_LEADER_COL_JOB_QUEUE_PUT, Method::Post) => {
                let collect_req: CollectReq = req.json().await?;

                // Compute the collect job ID, used to derive the collect URI for this request.
                // This value is computed by applying a pseudorandom function to the request. This
                // has two desirable properties. First, it makes the collect URI unpredictable,
                // which prevents clients from enumerating collect URIs. Second, it provides a
                // stable map from requests to URIs, which prevents us from processing the same
                // collect request more than once.
                //
                // We are serializing the collect_req into binary, and for now we assume the
                // version is always Draf03 since that works for both Draft02 and Draft03, but
                // if this structure changes further, then version information will need to be
                // added to this request.
                let collect_req_bytes = collect_req.get_encoded_with_param(&DapVersion::Draft03);
                let mut collect_id_bytes = [0; 32];
                PrgAes128::seed_stream(
                    self.config.collect_id_key.as_ref().unwrap(),
                    &collect_req_bytes,
                )
                .fill(&mut collect_id_bytes);
                let collect_id = Id(collect_id_bytes);
                let collect_id_hex = collect_id.to_hex();

                // If the the request is new, then put it in the job queue.
                let pending_key = format!("pending/id/{}", collect_id_hex);
                let pending: bool = state_get_or_default(&self.state, &pending_key).await?;
                let processed: Option<CollectResp> = state_get(
                    &self.state,
                    &format!("{}/{}", PROCESSED_PREFIX, collect_id_hex),
                )
                .await?;
                if processed.is_none() && !pending {
                    let queued = DurableOrdered::new_strictly_ordered(
                        &self.state,
                        (collect_id, collect_req),
                        PENDING_PREFIX,
                    )
                    .await?;
                    queued.put(&self.state).await?;
                    self.state
                        .storage()
                        .put(&lookup_key(&collect_id_hex), &queued.key())
                        .await?;
                }
                Response::from_json(&collect_id_hex)
            }

            // Get the list of pending collection jobs (oldest jobs first).
            //
            // Output: `Vec<(Id, CollectReq)>`
            (DURABLE_LEADER_COL_JOB_QUEUE_GET, Method::Get) => {
                let queue: Vec<(Id, CollectReq)> =
                    DurableOrdered::get_all(&self.state, PENDING_PREFIX)
                        .await?
                        .into_iter()
                        .map(|queued| queued.into_item())
                        .collect();
                Response::from_json(&queue)
            }

            // Remove a collection job from the pending queue and store the CollectResp.
            //
            // Input: `(collect_id, collect_resp): (Id, CollectResp)`
            (DURABLE_LEADER_COL_JOB_QUEUE_FINISH, Method::Post) => {
                let (collect_id, collect_resp): (Id, CollectResp) = req.json().await?;
                let collect_id_hex = collect_id.to_hex();
                let processed_key = format!("{}/{}", PROCESSED_PREFIX, collect_id_hex);
                let processed: Option<CollectResp> = state_get(&self.state, &processed_key).await?;
                if processed.is_some() {
                    return Err(int_err(
                        "LeaderCollectionJobQueue: tried to overwrite collect response",
                    ));
                }

                // Remove the collection job from the pending queue.
                let pending_lookup_key = lookup_key(&collect_id_hex);
                if let Some(lookup_val) =
                    state_get::<String>(&self.state, &pending_lookup_key).await?
                {
                    self.state.storage().delete(&lookup_val).await?;
                }

                let mut storage = self.state.storage();
                let f = storage.delete(&pending_lookup_key);

                // Store the CollectResp.
                self.state
                    .storage()
                    .put(&processed_key, collect_resp)
                    .await?;

                // Remove the lookup key.
                f.await?;
                Response::from_json(&())
            }

            // Check if a collection job is complete.
            //
            // Input: `collect_id: Id`
            // Output: `DapCollectionJob`
            (DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT, Method::Post) => {
                let collect_id: Id = req.json().await?;
                let collect_id_hex = collect_id.to_hex();
                let pending_lookup_key = lookup_key(&collect_id_hex);
                let pending = state_get::<String>(&self.state, &pending_lookup_key)
                    .await?
                    .is_some();
                let processed_key = format!("{}/{}", PROCESSED_PREFIX, collect_id_hex);
                let processed: Option<CollectResp> = state_get(&self.state, &processed_key).await?;
                if let Some(collect_resp) = processed {
                    if pending {
                        self.state.storage().delete(&pending_lookup_key).await?;
                    }
                    Response::from_json(&DapCollectJob::Done(collect_resp))
                } else if pending {
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

fn lookup_key(collect_id_hex: &str) -> String {
    format!("{}/id/{}", PENDING_PREFIX, collect_id_hex)
}
