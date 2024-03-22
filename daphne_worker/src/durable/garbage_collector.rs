// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    durable::{
        create_span_from_request, req_parse, DurableConnector, DurableOrdered, DurableReference,
    },
    initialize_tracing, int_err,
};
use daphne_service_utils::durable_requests::bindings::{self, DurableMethod};
use tracing::{error, trace, Instrument};
use worker::{
    async_trait, durable_object, js_sys, wasm_bindgen, wasm_bindgen_futures, worker_sys, Env,
    Request, Response, Result, State,
};

/// Durable Object (DO) for keeping track of all persistent DO storage.
#[durable_object]
pub struct GarbageCollector {
    #[allow(dead_code)]
    state: State,
    env: Env,
}

#[durable_object]
impl DurableObject for GarbageCollector {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        Self { state, env }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let span = create_span_from_request(&req);
        self.handle(req).instrument(span).await
    }
}

impl GarbageCollector {
    async fn handle(&mut self, mut req: Request) -> Result<Response> {
        let durable = DurableConnector::new(&self.env);
        match bindings::GarbageCollector::try_from_uri(&req.path()) {
            // Schedule a durable object (DO) instance for deletion.
            Some(bindings::GarbageCollector::Put) => {
                let durable_ref: DurableReference = req_parse(&mut req).await?;
                match durable_ref.binding.as_ref() {
                    bindings::AggregateStore::BINDING | bindings::HelperState::BINDING => (),
                    s => {
                        let message = format!("GarbageCollector: unrecognized binding: {s}");
                        error!("{}", message);
                        return Err(int_err(message));
                    }
                };

                let queued = DurableOrdered::new_roughly_ordered(durable_ref, "object");
                queued.put(&self.state).await?;
                trace!(
                    binding = queued.as_ref().binding,
                    instance = queued.as_ref().id_hex,
                    "registered DO instance for deletion",
                );
                Response::from_json(&())
            }

            // Delete all DO instances.
            //
            // NOTE This method is likely to hit memory and/or time limits when run in a production
            // deployment. This method is not intended for production use. If deleting all memory
            // for a deployment is needed, then the proper way is to do a Workers migration that
            // deletes each of the DO classes.
            //
            //   TODO Add a method for deleting all instances scheduled before a given time. This
            //   will allow us to prune storage we're not likely to need anymore, e.g., for
            //   replay protection. However, for replay protection in particular, it'll be
            //   important to make sure the Leader rejects reports with old timestamps.
            Some(bindings::GarbageCollector::DeleteAll) => {
                let queued: Vec<DurableOrdered<DurableReference>> =
                    DurableOrdered::get_all(&self.state, "object").await?;
                for durable_ref in queued.iter().map(|queued| queued.as_ref()) {
                    durable
                        .post_by_id_hex(
                            &durable_ref.binding,
                            bindings::GarbageCollector::DeleteAll.to_uri(),
                            durable_ref.id_hex.clone(),
                            &(),
                        )
                        .await?;
                    trace!(
                        binding = durable_ref.binding,
                        instance = durable_ref.id_hex,
                        "deleted instance",
                    );
                }

                self.state.storage().delete_all().await?;
                Response::from_json(&())
            }

            _ => {
                let message = format!(
                    "unexpected request: method={:?}; path={:?}",
                    req.method(),
                    req.path()
                );
                error!("{}", message);
                Err(int_err(message))
            }
        }
    }
}
