// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::ControlFlow;

use crate::{
    config::DaphneWorkerDurableConfig,
    durable::{create_span_from_request, req_parse, DurableOrdered},
    initialize_tracing, int_err,
};
use daphne_service_utils::{
    config::DaphneWorkerDeployment,
    durable_requests::bindings::{self, DurableMethod},
};
use tracing::{debug, Instrument};
use worker::{
    async_trait, durable_object, js_sys, wasm_bindgen, wasm_bindgen_futures, worker_sys, Env,
    Request, Response, Result, State,
};

use super::{DapDurableObject, GarbageCollectable};

/// Durable Object (DO) representing an aggregation job queue.
///
/// This object defines the following API endpoints:
///
/// - `DURABLE_LEADER_AGG_JOB_QUEUE_PUT`: Adds a job to the queue. This is called by an instance of
///   `ReportsPending`.
/// - `DURABLE_LEADER_AGG_JOB_QUEUE_PUT`: Fetches the desired number of jobs from the front of the
///    queue.
/// - `DURABLE_LEADER_AGG_JOB_QUEUE_FINISH`: Removes the indicated job from the queue.
///
/// The schemea for data stored in instances of this DO is as follows:
///
/// ```text
///     agg_job/item/time/<time>/nonce/<nonce> -> String
/// ```
///
/// where `<time>` and `<nonce>` were generated by the `ReportsPending` instance at creation time.
/// The value stored is the unique name of the `ReportsPending` instance. Note that this schema
/// matches the ordinal generated by [`DurableOrdered::new_roughly_ordered`].
#[durable_object]
pub struct LeaderAggregationJobQueue {
    #[allow(dead_code)]
    state: State,
    env: Env,
    config: DaphneWorkerDurableConfig,
    touched: bool,
}

#[durable_object]
impl DurableObject for LeaderAggregationJobQueue {
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

impl LeaderAggregationJobQueue {
    async fn handle(&mut self, req: Request) -> Result<Response> {
        let mut req = match self.schedule_for_garbage_collection(req).await? {
            ControlFlow::Continue(req) => req,
            // This req was a GC request and as such we must return from this function.
            ControlFlow::Break(_) => return Response::from_json(&()),
        };
        match bindings::LeaderAggJobQueue::try_from_uri(&req.path()) {
            // Put a job (near) the back of the queue.
            //
            // Input: `agg_job: DurableOrdered<String>` (the `String` is the name of the
            // `ReportsPending` instance)
            Some(bindings::LeaderAggJobQueue::Put) => {
                let agg_job: DurableOrdered<String> = req_parse(&mut req).await?;
                agg_job.put(&self.state).await?;
                debug!(
                    "LeaderAggregationJobQueue: {} has been scheduled",
                    agg_job.as_ref(),
                );
                Response::from_json(&())
            }

            // Fetch the aggregation jobs at the fron tf the queue.
            //
            // Input: `max_agg_jobs: usize`,
            // Output: `Vec<String>` (the names of the `ReportsPending` instances from which to
            // drain reports)
            Some(bindings::LeaderAggJobQueue::Get) => {
                let max_agg_jobs: usize = req_parse(&mut req).await?;
                let res: Vec<String> =
                    DurableOrdered::get_front(&self.state, "agg_job", max_agg_jobs)
                        .await?
                        .into_iter()
                        .map(|agg_job| agg_job.into_item())
                        .collect();

                debug!("agg job queue: {:?}", res);
                Response::from_json(&res)
            }

            // Remove a job from the queue.
            //
            // Input: `agg_job: DurableOrdered<String>` (the `String` is the name of the
            // `ReportsPending` instance that has become empty)
            Some(bindings::LeaderAggJobQueue::Finish) => {
                let agg_job: DurableOrdered<String> = req_parse(&mut req).await?;
                agg_job.delete(&self.state).await?;
                Response::from_json(&())
            }

            _ => Err(int_err(format!(
                "LeaderAggregationJobQueue: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

impl DapDurableObject for LeaderAggregationJobQueue {
    type DurableMethod = bindings::LeaderAggJobQueue;

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
impl GarbageCollectable for LeaderAggregationJobQueue {
    #[inline(always)]
    fn touched(&mut self) -> &mut bool {
        &mut self.touched
    }

    #[inline(always)]
    fn env(&self) -> &Env {
        &self.env
    }
}
