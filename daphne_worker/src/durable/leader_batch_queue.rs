// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::ControlFlow;

use crate::{
    config::DaphneWorkerDurableConfig,
    durable::{create_span_from_request, state_get, DurableOrdered},
    initialize_tracing, int_err,
};
use daphne::messages::BatchId;
use daphne_service_utils::{
    config::DaphneWorkerDeployment,
    durable_requests::bindings::{self, BatchCount, DurableMethod, LeaderBatchQueueResult},
};
use rand::prelude::*;
use tracing::{debug, Instrument};
use worker::{
    async_trait, durable_object, js_sys, wasm_bindgen, wasm_bindgen_futures, worker_sys, Env,
    Request, Response, Result, State,
};

use super::{req_parse, DapDurableObject, GarbageCollectable};

const CURRENT: &str = "current";
const PENDING_PREFIX: &str = "pending";

/// Durable Object (DO) for assigning reports to batches (applicable to fixed-size tasks only).
///
/// This object implements the following API endpoints:
///
/// - `DURABLE_LEADER_BATCH_QUEUE_ASSIGN`: Assign the requested number of reports to batches.
/// - `DURABLE_LEADER_BATCH_QUEUE_CURRENT`: Return the ID of the oldest, non-yet-collected batch.
/// - `DURABLE_LEADER_BATCH_QUEUE_REMOVE`: Remove the given batch from the queue.
///
/// The schema for data stored in instances of this DO is as follows:
///
/// ```text
/// [Pending Lookup ID] pending/id/<batch_id> -> String (reference to queue element)
/// [Pending queue]     pending/next_ordinal -> u64
/// [Pending queue]     pending/item/order/<order> -> BatchCount
/// [Current batch]     current -> BatchCount (the batch currently being filled)
/// ```
///
/// Note that the queue ordinal format is inherited from [`DurableOrdered::new_strictly_ordered`].
#[durable_object]
pub struct LeaderBatchQueue {
    #[allow(dead_code)]
    state: State,
    env: Env,
    config: DaphneWorkerDurableConfig,
    touched: bool,
}

impl LeaderBatchQueue {
    async fn create_batch(&self) -> Result<BatchCount> {
        let mut rng = thread_rng();

        let queued = DurableOrdered::new_strictly_ordered(
            &self.state,
            BatchCount {
                batch_id: BatchId(rng.gen()),
                report_count: 0,
            },
            PENDING_PREFIX,
        )
        .await?;
        queued.put(&self.state).await?;

        // Create a reverse look-up key for the batch.
        let batch_id_hex = queued.as_ref().batch_id.to_hex();
        self.state
            .storage()
            .put(&lookup_key(&batch_id_hex), &queued.key())
            .await?;

        // Generate a random batch ID and write the batch count to the queue.
        debug!("LeaderBatchQueue: created batch {batch_id_hex}");
        Ok(queued.into_item())
    }
}

#[durable_object]
impl DurableObject for LeaderBatchQueue {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerDurableConfig::from_worker_env(&env).expect("failed to load configuration");
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

impl LeaderBatchQueue {
    async fn handle(&mut self, req: Request) -> Result<Response> {
        let mut req = match self.schedule_for_garbage_collection(req).await? {
            ControlFlow::Continue(req) => req,
            // This req was a GC request and as such we must return from this function.
            ControlFlow::Break(_) => return Response::from_json(&()),
        };

        match bindings::LeaderBatchQueue::try_from_uri(&req.path()) {
            // Return the ID of the oldest, not-yet-collected batch.
            //
            // Output: `LeaderBatchQueueResult`
            Some(bindings::LeaderBatchQueue::Current) => {
                let mut queued: Vec<DurableOrdered<BatchCount>> =
                    DurableOrdered::get_front(&self.state, PENDING_PREFIX, 1).await?;
                if queued.is_empty() {
                    Response::from_json(&LeaderBatchQueueResult::EmptyQueue)
                } else {
                    Response::from_json(&LeaderBatchQueueResult::Ok(
                        queued.pop().unwrap().into_item().batch_id,
                    ))
                }
            }

            // Assign the requested number of reports to a sequence of batch IDs. For each batch
            // ID, return the number of reports assigned to the batch.
            //
            // Input: `(batch_size, num_unassigned): (usize, usize)`
            // Output: `Vec<BatchCount>`
            Some(bindings::LeaderBatchQueue::Assign) => {
                let (batch_size, mut num_unassigned): (usize, usize) = req_parse(&mut req).await?;
                if batch_size == 0 {
                    return Err(int_err("LeaderBatchQueue: called with batch_size is 0"));
                }

                // Read the batch that is currently being filled from storage, or, if this is the
                // first time this LeaderBatchQueue instance has been touched, create a new batch.
                let mut curr = if let Some(curr) = state_get(&self.state, CURRENT).await? {
                    curr
                } else {
                    self.create_batch().await?
                };

                let mut batch_assignments = vec![BatchCount {
                    batch_id: curr.batch_id,
                    report_count: 0,
                }];

                while num_unassigned > 0 {
                    let num_assigned =
                        std::cmp::min(batch_size, curr.report_count + num_unassigned)
                            - curr.report_count;
                    curr.report_count += num_assigned;
                    batch_assignments.last_mut().unwrap().report_count += num_assigned;
                    num_unassigned -= num_assigned;

                    // If the current batch is saturated, then create a new one.
                    if curr.report_count >= batch_size {
                        curr = self.create_batch().await?;
                        batch_assignments.push(curr.clone());
                    }
                }

                // Write the current batch to storage.
                self.state.storage().put(CURRENT, &curr).await?;
                Response::from_json(&batch_assignments)
            }

            // Remove the indicated batch (i.e., the hex-encoded batch ID) from the queue. This is
            // done after the corresponding collect job is finished.
            //
            // Input: `batch_id_hex: String`
            Some(bindings::LeaderBatchQueue::Remove) => {
                let batch_id_hex: String = req_parse(&mut req).await?;
                let lookup_key = lookup_key(&batch_id_hex);
                if let Some(lookup_val) = state_get::<String>(&self.state, &lookup_key).await? {
                    self.state.storage().delete(&lookup_val).await?;
                }

                self.state.storage().delete(&lookup_key).await?;
                debug!("LeaderBatchQueue: removed batch {}", batch_id_hex);
                Response::from_json(&())
            }

            _ => Err(int_err(format!(
                "LeaderBatchQueue: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

fn lookup_key(batch_id_hex: &str) -> String {
    format!("{PENDING_PREFIX}/id/{batch_id_hex}")
}

impl DapDurableObject for LeaderBatchQueue {
    type DurableMethod = bindings::LeaderBatchQueue;

    #[inline(always)]
    fn state(&self) -> &State {
        &self.state
    }

    #[inline(always)]
    fn deployment(&self) -> DaphneWorkerDeployment {
        self.config.deployment
    }
}

#[async_trait::async_trait(?Send)]
impl GarbageCollectable for LeaderBatchQueue {
    #[inline(always)]
    fn touched(&mut self) -> &mut bool {
        &mut self.touched
    }

    #[inline(always)]
    fn env(&self) -> &Env {
        &self.env
    }
}
