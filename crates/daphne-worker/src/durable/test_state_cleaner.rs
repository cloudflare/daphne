// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{cmp::min, ops::ControlFlow};

use crate::{durable::create_span_from_request, initialize_tracing, int_err};
use daphne::messages::TaskId;
use daphne_service_utils::durable_requests::bindings::{self, DurableMethod};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tracing::{error, trace, Instrument};
use worker::{
    async_trait, durable_object, wasm_bindgen, wasm_bindgen_futures, Date, Env, ListOptions,
    Method, Request, Response, Result, State, Stub,
};

use super::GcDurableObject;

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
                let durable_ref: DurableReference =
                    serde_json::from_slice(&req.bytes().await?).unwrap();
                match durable_ref.binding.as_ref() {
                    bindings::AggregateStore::BINDING => (),
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
        let time = Date::now().as_millis() / 1000;

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
    /// The DO binding, e.g., `DAP_REPORT_STORE`.
    pub(crate) binding: String,

    /// Unique ID assigned to the DO instance by the Workers runtime.
    pub(crate) id_hex: String,

    /// If applicable, the DAP task ID to which the DO instance is associated.
    pub(crate) task_id: Option<TaskId>,
}

/// Register a DO to be deleted by the [`TestStateCleaner`](test_state_cleaner::TestStateCleaner).
///
/// If, however, the request is a [`TestStateCleaner::DeleteAll`] request we also handle that
/// request. This consumes the request and returns `Continue::Break`, signaling that the durable
/// object should itself return from fetch.
///
/// If the request *wasn't* a [`TestStateCleaner::DeleteAll`] request, the `Request` is
/// returned through the `ControlFlow::Continue` variant.
///
/// # Note
/// This function is doing two things at once, which makes it confusing, but both things revolve
/// around keeping some state (`gc_delete_all_is_setup`) in sync and such it's less error prone for
/// callers if it's all done in one place.
pub(super) async fn setup_and_handle_test_cleaner_requests<T: GcDurableObject>(
    state: &State,
    env: &Env,
    req: Request,
) -> Result<ControlFlow<(), Request>> {
    // We first check if this was a delete all request. If it was then it means that the setup in
    // the else branch was already done before.
    if let Some(bindings::TestStateCleaner::DeleteAll) =
        bindings::TestStateCleaner::try_from_uri(&req.path())
    {
        state.storage().delete_all().await?;
        state.storage().put("delete_all_is_setup", &false).await?;
        Ok(ControlFlow::Break(()))
    } else {
        // if this wasn't a delete all request then we must ensure that we have registered
        // ourselves with the `TestStateCleaner` to delete us.
        let delete_all_is_setup =
            super::state_set_if_not_exists(state, "delete_all_is_setup", &true)
                .await?
                .unwrap_or(false);
        if !delete_all_is_setup {
            DurableConnector::new(env)
                .post(
                    bindings::TestStateCleaner::BINDING,
                    bindings::TestStateCleaner::Put.to_uri(),
                    bindings::TestStateCleaner::name(()).unwrap_from_name(),
                    &DurableReference {
                        binding: T::DurableMethod::BINDING.to_string(),
                        id_hex: state.id().to_string(),
                        task_id: None,
                    },
                )
                .await?;
        }
        Ok(ControlFlow::Continue(req))
    }
}

/// Used to send HTTP requests to a durable object (DO) instance.
pub(crate) struct DurableConnector<'srv> {
    env: &'srv Env,
}

impl<'srv> DurableConnector<'srv> {
    pub(crate) fn new(env: &'srv Env) -> Self {
        DurableConnector { env }
    }

    /// Send a POST request with the given path to the DO instance with the given binding and name.
    /// The body of the request is a JSON object. The response is expected to be a JSON object.
    pub(crate) async fn post<I: Serialize, O: for<'b> Deserialize<'b>>(
        &self,
        durable_binding: &str,
        durable_path: &'static str,
        durable_name: String,
        data: I,
    ) -> Result<O> {
        let stub = self
            .env
            .durable_object(durable_binding)?
            .id_from_name(&durable_name)?
            .get_stub()?;
        self.durable_request(stub, durable_path, Method::Post, Some(data))
            .await
            .map_err(|error| {
                worker::Error::RustError(format!(
                    "DO {durable_binding}: post {durable_path}: {error}"
                ))
            })
    }

    /// Send a POST request with the given path to the DO instance with the given binding and hex
    /// identifier. The body of the request is a JSON object. The response is expected to be a JSON
    /// object.
    pub(crate) async fn post_by_id_hex<I: Serialize, O: for<'b> Deserialize<'b>>(
        &self,
        durable_binding: &str,
        durable_path: &'static str,
        durable_id_hex: String,
        data: I,
    ) -> Result<O> {
        let namespace = self.env.durable_object(durable_binding)?;
        let stub = namespace.id_from_string(&durable_id_hex)?.get_stub()?;
        self.durable_request(stub, durable_path, Method::Post, Some(data))
            .await
            .map_err(|error| {
                worker::Error::RustError(format!(
                    "DO {durable_binding}: post {durable_path}: {error}"
                ))
            })
    }

    async fn durable_request<I, O>(
        &self,
        durable_stub: Stub,
        durable_path: &'static str,
        method: Method,
        data: Option<I>,
    ) -> Result<O>
    where
        I: Serialize,
        O: for<'a> Deserialize<'a>,
    {
        let req = match (&method, &data) {
            (Method::Post, Some(data)) => {
                let data = serde_json::to_vec(&data).map_err(|e| {
                    worker::Error::RustError(format!("failed to serialize data: {e:?}"))
                })?;
                let buffer =
                    worker::js_sys::Uint8Array::new_with_length(data.len().try_into().map_err(
                        |_| worker::Error::RustError(format!("buffer is too long {}", data.len())),
                    )?);
                buffer.copy_from(&data);
                Request::new_with_init(
                    &format!("https://fake-host{durable_path}"),
                    worker::RequestInit::new()
                        .with_method(Method::Post)
                        .with_body(Some(buffer.into())),
                )?
            }
            (Method::Get, None) => Request::new_with_init(
                &format!("https://fake-host{durable_path}"),
                worker::RequestInit::new().with_method(Method::Get),
            )?,
            _ => {
                return Err(worker::Error::RustError(format!(
                    "durable_request: Unrecognized method: {method:?}",
                )));
            }
        };

        durable_stub.fetch_with_request(req).await?.json().await
    }
}
