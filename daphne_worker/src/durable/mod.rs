// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub(crate) mod aggregate_store;
pub(crate) mod helper_state_store;
pub(crate) mod test_state_cleaner;

use crate::tracing_utils::{shorten_paths, DaphneSubscriber, JsonFields};
use daphne_service_utils::{
    config::DaphneWorkerDeployment,
    durable_requests::bindings::{self, DurableMethod, TestStateCleaner},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{ops::ControlFlow, sync::OnceLock, time::Duration};
use tracing::info_span;
use worker::{
    js_sys::Uint8Array, Delay, Env, Error, Headers, Method, Request, RequestInit, Response, Result,
    ScheduledTime, State, Stub,
};

const ERR_NO_VALUE: &str = "No such value in storage.";

const RETRY_DELAYS: &[Duration] = &[
    Duration::from_millis(100),
    Duration::from_millis(500),
    Duration::from_millis(1_000),
    Duration::from_millis(3_000),
];

/// Used to send HTTP requests to a durable object (DO) instance.
pub(crate) struct DurableConnector<'srv> {
    env: &'srv Env,
    retry: bool,
}

impl<'srv> DurableConnector<'srv> {
    pub(crate) fn new(env: &'srv Env) -> Self {
        DurableConnector { env, retry: false }
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
        self.post_with_handler(
            durable_binding,
            durable_path,
            durable_name,
            data,
            |output, _retried| output,
        )
        .await
    }

    /// Like `post()`, except `handler` is called on the result. The callback is given an
    /// indication of whether the request was retried.
    pub(crate) async fn post_with_handler<I, O1, O2, H>(
        &self,
        durable_binding: &str,
        durable_path: &'static str,
        durable_name: String,
        data: I,
        handler: H,
    ) -> Result<O2>
    where
        I: Serialize,
        O1: for<'b> Deserialize<'b>,
        H: FnOnce(O1, bool) -> O2 + Sized,
    {
        let namespace = self.env.durable_object(durable_binding)?;
        let stub = namespace.id_from_name(&durable_name)?.get_stub()?;
        self.durable_request(
            stub,
            durable_binding,
            durable_path,
            Method::Post,
            Some(data),
            handler,
        )
        .await
        .map_err(|error| {
            Error::RustError(format!(
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
        self.durable_request(
            stub,
            durable_binding,
            durable_path,
            Method::Post,
            Some(data),
            |output, _retried| output,
        )
        .await
        .map_err(|error| {
            Error::RustError(format!(
                "DO {durable_binding}: post {durable_path}: {error}"
            ))
        })
    }

    async fn durable_request<I, O1, O2, H>(
        &self,
        durable_stub: Stub,
        durable_binding: &str,
        durable_path: &'static str,
        method: Method,
        data: Option<I>,
        handler: H,
    ) -> Result<O2>
    where
        I: Serialize,
        O1: for<'a> Deserialize<'a>,
        H: FnOnce(O1, bool) -> O2 + Sized,
    {
        let attempts = if self.retry {
            RETRY_DELAYS.len() + 1
        } else {
            1
        };

        let tracing_headers = span_to_headers();

        let mut attempt = 1;
        loop {
            let req = match (&method, &data) {
                (Method::Post, Some(data)) => {
                    let data = bincode::serialize(&data).map_err(|e| {
                        Error::RustError(format!("failed to serialize data: {e:?}"))
                    })?;
                    let buffer =
                        Uint8Array::new_with_length(data.len().try_into().map_err(|_| {
                            worker::Error::RustError(format!("buffer is too long {}", data.len()))
                        })?);
                    buffer.copy_from(&data);
                    Request::new_with_init(
                        &format!("https://fake-host{durable_path}"),
                        RequestInit::new()
                            .with_method(Method::Post)
                            .with_body(Some(buffer.into()))
                            .with_headers(tracing_headers.clone()),
                    )?
                }
                (Method::Get, None) => Request::new_with_init(
                    &format!("https://fake-host{durable_path}"),
                    RequestInit::new()
                        .with_method(Method::Get)
                        .with_headers(tracing_headers.clone()),
                )?,
                _ => {
                    return Err(Error::RustError(format!(
                        "durable_request: Unrecognized method: {method:?}",
                    )));
                }
            };

            match durable_stub.fetch_with_request(req).await {
                Ok(mut resp) => return Ok(handler(resp.json().await?, attempt > 1)),
                Err(err) => {
                    if attempt < attempts {
                        tracing::warn!("DO {durable_binding}: post {durable_path}: attempt #{attempt} failed: {err}");
                        Delay::from(RETRY_DELAYS[attempt - 1]).await;
                        attempt += 1;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }
}

/// A durable object that is capable of garbage collecting itself.
trait GcDurableObject {
    type DurableMethod: DurableMethod;

    /// Instantiate the durable object from it's state and environment.
    fn with_state_and_env(state: State, env: Env) -> Self;

    /// Handle a durable object request.
    async fn handle(&mut self, req: Request) -> Result<Response>;

    /// When this durable object should self cleanup.
    ///
    /// Returning None signals that this DO should not be automatically cleaned up.
    fn should_cleanup_at(&self) -> Option<ScheduledTime>;
}

fn deployment(env: &Env) -> DaphneWorkerDeployment {
    static DEPLOYMENT: OnceLock<DaphneWorkerDeployment> = OnceLock::new();

    *DEPLOYMENT.get_or_init(|| {
        let deployment = match env.var("DAP_DEPLOYMENT").map(|x| x.to_string()).as_deref() {
            Ok("dev") => DaphneWorkerDeployment::Dev,
            Ok("prod") | Err(_) => DaphneWorkerDeployment::Prod,
            Ok(s) => {
                tracing::error!("Invalid value for DAP_DEPLOYMENT ({s}), defaulting to prod");
                DaphneWorkerDeployment::Prod
            }
        };
        if !matches!(deployment, DaphneWorkerDeployment::Prod) {
            tracing::trace!("DAP deployment override applied: {deployment:?}");
        }
        deployment
    })
}

/// Generate a durable object based on a `DapDurableObject`.
///
/// This object must hold the `State` and `Env`. Thus the macro forces it.
#[macro_export]
macro_rules! mk_durable_object {
    (struct $name:ident {
        state: State,
        env: Env,
        $($field:ident : $type:ty),*
        $(,)?
    }) => {
        #[worker::durable_object]
        struct $name {
            state: ::worker::State,
            env: ::worker::Env,
            $($field: $type),*
        }

        #[worker::durable_object]
        impl DurableObject for $name {
            fn new(state: ::worker::State, env: ::worker::Env) -> Self {
                $crate::tracing_utils::initialize_tracing(&env);
                <Self as $crate::durable::GcDurableObject>::with_state_and_env(state, env)
            }

            async fn fetch(
                &mut self,
                #[allow(unused_mut)] mut req: ::worker::Request
            ) -> ::worker::Result<::worker::Response> {
                use $crate::durable::{
                    deployment,
                    setup_and_handle_test_cleaner_requests,
                    create_span_from_request,
                    GcDurableObject,
                };
                use ::tracing::Instrument;
                use ::std::ops::ControlFlow;
                use ::daphne_service_utils::config::DaphneWorkerDeployment::Dev;

                if matches!(deployment(&self.env), Dev) {
                    // Try to handle a delete all request.
                    req = match setup_and_handle_test_cleaner_requests::<Self>(
                        &self.state,
                        &self.env,
                        req
                    ).await? {
                        ControlFlow::Continue(req) => req,
                        // This req was a DeleteAll request and as such we must return from this
                        // function.
                        ControlFlow::Break(()) => return ::worker::Response::from_json(&()),
                    };
                }

                // Ensure this DO instance is garbage collected eventually.
                if let Some(lifetime) = self.should_cleanup_at() {
                    self.state.storage().set_alarm(lifetime).await?;
                    ::tracing::trace!(instance = self.state.id().to_string(), "alarm set");
                };

                let span = create_span_from_request(&req);
                <$name as GcDurableObject>::handle(self, req).instrument(span).await
            }

            async fn alarm(&mut self) -> Result<Response> {
                self.state.storage().delete_all().await?;
                ::tracing::trace!(
                    instance = self.state.id().to_string(),
                    "{}: alarm triggered, deleting...",
                    ::std::stringify!($name),
                );
                ::worker::Response::from_json(&())
            }
        }

        #[allow(dead_code)]
        impl $name {
            async fn get<T>(&self, key: &str) -> ::worker::Result<Option<T>>
                where
                    T: ::serde::de::DeserializeOwned,
            {
                $crate::durable::state_get(&self.state, key).await
            }

            async fn get_or_default<T>(&self, key: &str) -> ::worker::Result<T>
                where
                    T: ::serde::de::DeserializeOwned + std::default::Default,
            {
                $crate::durable::state_get_or_default(&self.state, key).await
            }

            async fn set_if_not_exists<T>(&self, key: &str, val: &T) -> ::worker::Result<Option<T>>
                where
                    T: ::serde::de::DeserializeOwned + ::serde::Serialize,
            {
                $crate::durable::state_set_if_not_exists(&self.state, key, val).await
            }
        }
    };
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
async fn setup_and_handle_test_cleaner_requests<T: GcDurableObject>(
    state: &State,
    env: &Env,
    req: Request,
) -> Result<ControlFlow<(), Request>> {
    // We first check if this was a delete all request. If it was then it means that the setup in
    // the else branch was already done before.
    if let Some(TestStateCleaner::DeleteAll) = TestStateCleaner::try_from_uri(&req.path()) {
        state.storage().delete_all().await?;
        state.storage().put("delete_all_is_setup", &false).await?;
        Ok(ControlFlow::Break(()))
    } else {
        // if this wasn't a delete all request then we must ensure that we have registered
        // ourselves with the `TestStateCleaner` to delete us.
        let delete_all_is_setup = state_set_if_not_exists(state, "delete_all_is_setup", &true)
            .await?
            .unwrap_or(false);
        if !delete_all_is_setup {
            crate::durable::DurableConnector::new(env)
                .post(
                    bindings::TestStateCleaner::BINDING,
                    bindings::TestStateCleaner::Put.to_uri(),
                    bindings::TestStateCleaner::name(()).unwrap_from_name(),
                    &test_state_cleaner::DurableReference {
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

/// Fetch the value associated with the given key from durable storage. If the key/value pair does
/// not exist, then return the default value.
pub(crate) async fn state_get_or_default<T: Default + for<'a> Deserialize<'a>>(
    state: &State,
    key: &str,
) -> Result<T> {
    state.storage().get(key).await.or_else(|e| {
        if matches!(e, Error::JsError(ref s) if s == ERR_NO_VALUE) {
            Ok(T::default())
        } else {
            Err(e)
        }
    })
}

pub(crate) async fn state_get<T: for<'a> Deserialize<'a>>(
    state: &State,
    key: &str,
) -> Result<Option<T>> {
    state.storage().get(key).await.or_else(|e| {
        if matches!(e, Error::JsError(ref s) if s == ERR_NO_VALUE) {
            Ok(None)
        } else {
            Err(e)
        }
    })
}

/// Set a key/value pair unless the key already exists. If the key exists, then return the current
/// value. Otherwise return nothing.
pub(crate) async fn state_set_if_not_exists<T: for<'a> Deserialize<'a> + Serialize>(
    state: &State,
    key: &str,
    val: &T,
) -> Result<Option<T>> {
    let curr_val: Option<T> = state_get(state, key).await?;
    if curr_val.is_some() {
        return Ok(curr_val);
    }

    state.storage().put(key, val).await?;
    Ok(None)
}

fn span_to_headers() -> Headers {
    // get the current span.
    let span = tracing::Span::current();

    // get the current global subscriber
    tracing::dispatcher::get_default(|d| {
        use tracing_subscriber::registry::LookupSpan;

        // downcast it to our subscriber
        let Some(sub) = d.downcast_ref::<DaphneSubscriber>() else {
            return Default::default();
        };

        // get the span id, so we can ask the subscriber for the current span
        let Some(id) = span.id() else {
            return Default::default();
        };

        let mut headers = Headers::default();

        // loop over the stack of spans, starting with the current one and going up.
        for span_ref in std::iter::successors(sub.span(&id), |span| span.parent()) {
            // get the json fields extension provided by the [JsonFieldsLayer].
            let ext = span_ref.extensions();
            let Some(fields) = ext.get::<JsonFields>() else {
                continue;
            };

            for (k, v) in fields {
                let non_string_stack_slot: String;
                let (k, v) = (
                    // prepend "tracing-" to all the headers to avoid accidental collisions.
                    format!("tracing-{k}"),
                    match v {
                        serde_json::Value::String(s) => s,
                        v => {
                            non_string_stack_slot = v.to_string();
                            &non_string_stack_slot
                        }
                    },
                );
                if matches!(headers.has(&k), Ok(false)) {
                    if let Err(e) = headers.append(&k, v) {
                        tracing::warn!(
                            error = %e,
                            key = %k,
                            "invalid name passed to headers"
                        );
                    }
                }
            }
        }

        headers
    })
}

async fn req_parse<T: DeserializeOwned>(req: &mut Request) -> Result<T> {
    let bytes = req.bytes().await?;
    bincode::deserialize(&bytes)
        .map_err(|e| Error::RustError(format!("failed to deserialize bincode: {e:?}")))
}

fn create_span_from_request(req: &Request) -> tracing::Span {
    let path = req.path();
    let span = info_span!("DO span", p = %shorten_paths(path.split('/')).display());
    span.in_scope(|| tracing::info!("{}", path));
    span
}
