// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::ControlFlow;

use crate::{
    config::DaphneWorkerConfig,
    durable::{
        create_span_from_request, state_get, state_get_or_default, DurableOrdered,
        BINDING_DAP_LEADER_COL_JOB_QUEUE,
    },
    initialize_tracing, int_err,
};
use daphne::{
    messages::{Collection, CollectionJobId, CollectionReq, TaskId},
    DapCollectJob, DapVersion,
};
use prio::codec::ParameterizedEncode;
use serde::{Deserialize, Serialize};
use tracing::Instrument;
use worker::*;

use super::{req_parse, DapDurableObject, GarbageCollectable};

const PENDING_PREFIX: &str = "pending";
const PROCESSED_PREFIX: &str = "processed";

pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_PUT: &str = "/internal/do/leader_col_job_queue/put";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_GET: &str = "/internal/do/leader_col_job_queue/get";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_FINISH: &str =
    "/internal/do/leader_col_job_queue/finish";
pub(crate) const DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT: &str =
    "/internal/do/leader_col_job_queue/get_result";

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) struct CollectQueueRequest {
    pub collect_req: CollectionReq,
    pub task_id: TaskId,
    pub collect_job_id: Option<CollectionJobId>,
}

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
/// [Pending Lookup ID] pending/id/<collection_job_id> -> String (reference to queue element)
/// [Pending queue]     pending/next_ordinal -> u64
/// [Pending queue]     pending/item/order/<order> -> (CollectionJobId, CollectReq)
/// [Processed]         processed/<collection_job_id> -> CollectResp
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

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let span = create_span_from_request(&req);
        self.handle(req).instrument(span).await
    }
}

impl LeaderCollectionJobQueue {
    async fn handle(&mut self, req: Request) -> Result<Response> {
        let mut req = match self
            .schedule_for_garbage_collection(req, BINDING_DAP_LEADER_COL_JOB_QUEUE)
            .await?
        {
            ControlFlow::Continue(req) => req,
            // This req was a GC request and as such we must return from this function.
            ControlFlow::Break(_) => return Response::from_json(&()),
        };
        match (req.path().as_ref(), req.method()) {
            // Create a collect job for a collect request issued by the Collector.
            //
            // Input: `collect_req: CollectReq`
            // Output: `Id` (collect job ID)
            (DURABLE_LEADER_COL_JOB_QUEUE_PUT, Method::Post) => {
                let collect_queue_req: CollectQueueRequest = req_parse(&mut req).await?;
                let collection_job_id: CollectionJobId =
                    if let Some(cid) = &collect_queue_req.collect_job_id {
                        cid.clone()
                    } else {
                        // draft02 legacy: Compute the collect job ID, used to derive the collect
                        // URI for this request. This value is computed by applying a pseudorandom
                        // function to the request. This has two desirable properties. First, it
                        // makes the collect URI unpredictable, which prevents clients from
                        // enumerating collect URIs. Second, it provides a stable map from requests
                        // to URIs, which prevents us from processing the same collect request more
                        // than once.
                        let collection_job_id_bytes = {
                            let collect_req_bytes = collect_queue_req
                                .collect_req
                                .get_encoded_with_param(&DapVersion::Draft02);

                            let mut buf = [0; 16];
                            let key = ring::hmac::Key::new(
                                ring::hmac::HMAC_SHA256,
                                self.config.collection_job_id_key.as_ref().ok_or_else(|| {
                                    Error::RustError("missing collection job ID key".into())
                                })?,
                            );
                            let tag = ring::hmac::sign(&key, &collect_req_bytes);
                            buf.copy_from_slice(&tag.as_ref()[..16]);
                            buf
                        };
                        CollectionJobId(collection_job_id_bytes)
                    };

                // If the the request is new, then put it in the job queue.
                let pending_key = pending_key(&collect_queue_req.task_id, &collection_job_id);
                let processed_key = processed_key(&collect_queue_req.task_id, &collection_job_id);
                let pending: bool = state_get_or_default(&self.state, &pending_key).await?;
                let processed: Option<Collection> = state_get(&self.state, &processed_key).await?;
                if processed.is_none() && !pending {
                    let queued = DurableOrdered::new_strictly_ordered(
                        &self.state,
                        (
                            collect_queue_req.task_id,
                            collection_job_id.clone(),
                            collect_queue_req.collect_req,
                        ),
                        PENDING_PREFIX,
                    )
                    .await?;
                    queued.put(&self.state).await?;
                    self.state
                        .storage()
                        .put(&pending_key, &queued.key())
                        .await?;
                }
                Response::from_json(&collection_job_id.to_hex())
            }

            // Get the list of pending collection jobs (oldest jobs first).
            //
            // Output: `Vec<(Id, CollectReq)>`
            (DURABLE_LEADER_COL_JOB_QUEUE_GET, Method::Get) => {
                let queue: Vec<(TaskId, CollectionJobId, CollectionReq)> =
                    DurableOrdered::get_all(&self.state, PENDING_PREFIX)
                        .await?
                        .into_iter()
                        .map(|queued| queued.into_item())
                        .collect();
                Response::from_json(&queue)
            }

            // Remove a collection job from the pending queue and store the CollectResp.
            //
            // Input: `(collection_job_id, collect_resp): (Id, CollectResp)`
            (DURABLE_LEADER_COL_JOB_QUEUE_FINISH, Method::Post) => {
                let (task_id, collection_job_id, collect_resp): (
                    TaskId,
                    CollectionJobId,
                    Collection,
                ) = req_parse(&mut req).await?;
                let processed_key = processed_key(&task_id, &collection_job_id);
                let processed: Option<Collection> = state_get(&self.state, &processed_key).await?;
                if processed.is_some() {
                    return Err(int_err(
                        "LeaderCollectionJobQueue: tried to overwrite collect response",
                    ));
                }

                // Remove the collection job from the pending queue.
                let pending_key = pending_key(&task_id, &collection_job_id);
                if let Some(lookup_val) = state_get::<String>(&self.state, &pending_key).await? {
                    self.state.storage().delete(&lookup_val).await?;
                }

                let mut storage = self.state.storage();
                let f = storage.delete(&pending_key);

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
            // Input: `collection_job_id: Id`
            // Output: `DapCollectionJob`
            (DURABLE_LEADER_COL_JOB_QUEUE_GET_RESULT, Method::Post) => {
                let (task_id, collection_job_id): (TaskId, CollectionJobId) =
                    req_parse(&mut req).await?;
                let pending_key = pending_key(&task_id, &collection_job_id);
                let pending = state_get::<String>(&self.state, &pending_key)
                    .await?
                    .is_some();
                let processed_key = processed_key(&task_id, &collection_job_id);
                let processed: Option<Collection> = state_get(&self.state, &processed_key).await?;
                if let Some(collect_resp) = processed {
                    if pending {
                        self.state.storage().delete(&pending_key).await?;
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

fn pending_key(task_id: &TaskId, collection_job_id: &CollectionJobId) -> String {
    format!(
        "{PENDING_PREFIX}/tasks/{}/collection_jobs/{}",
        task_id.to_base64url(),
        collection_job_id.to_base64url()
    )
}

fn processed_key(task_id: &TaskId, collection_job_id: &CollectionJobId) -> String {
    format!(
        "{PROCESSED_PREFIX}/tasks/{}/collection_jobs/{}",
        task_id.to_base64url(),
        collection_job_id.to_base64url()
    )
}

impl DapDurableObject for LeaderCollectionJobQueue {
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
impl GarbageCollectable for LeaderCollectionJobQueue {
    #[inline(always)]
    fn touched(&mut self) -> &mut bool {
        &mut self.touched
    }

    #[inline(always)]
    fn env(&self) -> &Env {
        &self.env
    }
}
