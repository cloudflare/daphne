// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::cmp::min;

use crate::{
    durable::{create_span_from_request, req_parse, DurableConnector},
    initialize_tracing, int_err, now,
};
use daphne::messages::TaskId;
use daphne_service_utils::durable_requests::bindings::{self, DurableMethod};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tracing::{error, trace, Instrument};
use worker::{
    async_trait, durable_object, js_sys, wasm_bindgen, wasm_bindgen_futures, worker_sys, Env,
    ListOptions, Request, Response, Result, State,
};

/// Durable Object (DO) for keeping track of all persistent DO storage.
#[durable_object]
pub struct TestStateCleaner {
    #[allow(dead_code)]
    state: State,
    env: Env,
}

#[durable_object]
impl DurableObject for TestStateCleaner {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        Self { state, env }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let span = create_span_from_request(&req);
        self.handle(req).instrument(span).await
    }
}

impl TestStateCleaner {
    async fn handle(&mut self, mut req: Request) -> Result<Response> {
        let durable = DurableConnector::new(&self.env);
        match bindings::TestStateCleaner::try_from_uri(&req.path()) {
            // Schedule a durable object (DO) instance for deletion.
            Some(bindings::TestStateCleaner::Put) => {
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
            Some(bindings::TestStateCleaner::DeleteAll) => {
                let queued: Vec<DurableOrdered<DurableReference>> =
                    DurableOrdered::get_all(&self.state, "object").await?;
                for durable_ref in queued.iter().map(|queued| queued.as_ref()) {
                    durable
                        .post_by_id_hex(
                            &durable_ref.binding,
                            bindings::TestStateCleaner::DeleteAll.to_uri(),
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

// The maximum number of keys to get at once in a list command.
//
// The DO API does not say that there is any limit on the number of keys it is willing to return
// other than overall DO/worker memory, which it warns you not to exceed. Imposing some sort of
// limit is a good idea, lest we get DoS'd by a task configuration with a large value.
//
// Currently the value is set to 128, as the miniflare environment will fail with more than this.
// This appears to be a miniflare bug and not part of the API.
//
// We have not been able to replicate failures with wrangler2 in local or experimental-local mode.
//
// TODO(bhalley) does this need to be configurable?
const MAX_KEYS: usize = 128;

/// An element of a queue stored in a DO instance.
#[derive(Deserialize, Serialize)]
pub(crate) struct DurableOrdered<T> {
    item: T,
    prefix: String,
    ordinal: String,
}

impl<T: for<'a> Deserialize<'a> + Serialize> DurableOrdered<T> {
    /// Return all elements in the queue.
    ///
    /// WARNING: If the queue is too long, then this action is likely to cause the Workers runtime
    /// to start rate limiting the Worker. This should only be used when the size of the queue is
    /// strictly controlled.
    async fn get_all(state: &State, prefix: &str) -> Result<Vec<Self>> {
        get_front(state, prefix, None).await
    }

    /// Create a new element for a roughly ordered queue. (Use `put()` to store it.)
    ///
    /// Items in this queue are handled roughly in order of creation (oldest elements first).
    /// Specifically, the ordinal is the UNIX time (in seconds) at which this method was called.
    /// Ties are broken by a random nonce tacked on to the key. The format of the ordinal is:
    ///
    /// ```text
    ///     time/<time>/nonce/<nonce>
    /// ```
    ///
    /// where <time> is the timestamp and <nonce> is a random nonce.
    pub(crate) fn new_roughly_ordered(item: T, prefix: &str) -> Self {
        let mut rng = thread_rng();
        let time = now();
        let nonce = rng.gen::<[u8; 16]>();

        // Pad the timestamp with 0s to the length of the longest 64-bit integer encoded in
        // decimal. This ensures that queue elements stay ordered.
        let ordinal = format!("time/{:020}/nonce/{}", time, hex::encode(nonce));

        Self {
            item,
            prefix: prefix.to_string(),
            ordinal,
        }
    }

    /// Store the item in the provided DO state.
    pub(crate) async fn put(&self, state: &State) -> Result<()> {
        state.storage().put(&self.key(), &self.item).await
    }

    /// Compute the key used to store store the item. The key format is:
    ///
    /// ```text
    ///     <prefix>/item/<ordinal>
    /// ```
    ///
    /// where `<prefix>` is the indicated namespace and `<ordinal>` is the item's ordinal.
    pub(crate) fn key(&self) -> String {
        format!("{}/item/{}", self.prefix, self.ordinal)
    }
}

impl<T> AsRef<T> for DurableOrdered<T> {
    fn as_ref(&self) -> &T {
        &self.item
    }
}

async fn get_front<T: for<'a> Deserialize<'a> + Serialize>(
    state: &State,
    prefix: &str,
    limit: Option<usize>,
) -> Result<Vec<DurableOrdered<T>>> {
    let key_prefix = format!("{prefix}/item/");
    let mut opt = ListOptions::new().prefix(&key_prefix);
    if let Some(limit) = limit {
        // Note we impose an upper limit on the user's specified limit.
        opt = opt.limit(min(limit, MAX_KEYS));
    }
    let iter = state.storage().list_with_options(opt).await?.entries();
    let mut js_item = iter.next()?;
    let mut res = Vec::new();
    while !js_item.done() {
        let (key, item): (String, T) =
            serde_wasm_bindgen::from_value(js_item.value()).map_err(int_err)?;
        if key[..key_prefix.len()] != key_prefix {
            return Err(int_err("queue element key is improperly formatted"));
        }
        let ordinal = &key[key_prefix.len()..];
        res.push(DurableOrdered {
            item,
            prefix: prefix.to_string(),
            ordinal: ordinal.to_string(),
        });
        js_item = iter.next()?;
    }
    Ok(res)
}

/// Reference to a DO instance.
#[derive(Deserialize, Serialize)]
pub(crate) struct DurableReference {
    /// The DO binding, e.g., "DAP_REPORT_STORE".
    pub(crate) binding: String,

    /// Unique ID assigned to the DO instance by the Workers runtime.
    pub(crate) id_hex: String,

    /// If applicable, the DAP task ID to which the DO instance is associated.
    pub(crate) task_id: Option<TaskId>,
}
