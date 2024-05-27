// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This module defines the durable object implementations needed to run the DAP service. It
//! doesn't however instantiate them. They must be instantiated by the user of the library using
//! the [`instantiate_durable_object`] macro.
//!
//! When deploying the `storage_proxy` the durable object `name` and `class_name` must be defined
//! in the wrangler toml.
//!
//! # Example
//! ```toml
//! [durable_objects]
//! bindings = [
//!     { name = "DAP_AGGREGATE_STORE", class_name = "AggregateStore" }
//! ]
//! ```
//!
//! To know what values to provide to the `name` and `class_name` fields see each type exported by
//! this module as well as the [`instantiate_durable_object`] macro, respectively.

pub(crate) mod aggregate_store;
pub(crate) mod helper_state_store;
#[cfg(feature = "test-utils")]
pub(crate) mod test_state_cleaner;

use crate::tracing_utils::shorten_paths;
use daphne_service_utils::durable_requests::bindings::DurableMethod;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::info_span;
use worker::{Env, Error, Request, Response, Result, ScheduledTime, State};

pub use aggregate_store::AggregateStore;
pub use helper_state_store::HelperStateStore;

const ERR_NO_VALUE: &str = "No such value in storage.";

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

/// Generate a durable object based on a `DapDurableObject`.
///
/// This object must hold the `State` and `Env`. Thus the macro forces it.
macro_rules! mk_durable_object {
    (
        $(#[$docs:meta])*
        struct $name:ident {
            state: State,
            env: Env,
            $($field:ident : $type:ty),*
            $(,)?
        }
    ) => {
        $(#[$docs])*
        pub struct $name {
            state: ::worker::State,
            env: ::worker::Env,
            $($field: $type),*
        }

        impl $name {
            #[doc(hidden)]
            pub fn new(state: ::worker::State, env: ::worker::Env) -> Self {
                <Self as $crate::durable::GcDurableObject>::with_state_and_env(state, env)
            }

            #[doc(hidden)]
            pub async fn fetch(
                &mut self,
                #[allow(unused_mut)] mut req: ::worker::Request
            ) -> ::worker::Result<::worker::Response> {
                use $crate::durable::{create_span_from_request, GcDurableObject};
                use ::tracing::Instrument;

                #[cfg(feature = "test-utils")]
                {
                    use $crate::durable::test_state_cleaner::setup_and_handle_test_cleaner_requests;
                    use ::std::{ops::ControlFlow};
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

            #[doc(hidden)]
            pub async fn alarm(&mut self) -> Result<Response> {
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

pub(crate) use mk_durable_object;

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

async fn req_parse<T: DeserializeOwned>(req: &mut Request) -> Result<T> {
    let bytes = req.bytes().await?;
    bincode::deserialize(&bytes)
        .map_err(|e| Error::RustError(format!("failed to deserialize bincode: {e:?}")))
}

fn create_span_from_request(req: &Request) -> tracing::Span {
    let path = req.path();
    let span = info_span!("DO span", p = %shorten_paths(path.split('/')).display());
    span.in_scope(|| tracing::info!(path, "DO handling new request"));
    span
}

/// Instantiate a durable object.
///
/// # Syntax
/// ```
/// use daphne_worker::durable::{self, instantiate_durable_object};
///
/// instantiate_durable_object!(MyAggregateStore < durable::AggregateStore);
/// ```
///
/// The `MyAggregateStore` name is the name that must be specified in the `class_name` field in the
/// wrangler toml.
/// ```toml
/// [durable_objects]
/// bindings = [
///     { name = "AGGREGATE_STORE", class_name = "MyAggregateStore" }
/// ]
/// ```
///
/// If you want to run some extra intialization logic before the durable object intializes, you can
/// provide it like so:
/// ```
/// use daphne_worker::durable::{self, instantiate_durable_object};
///
/// instantiate_durable_object!{
///     MyAggregateStore < durable::AggregateStore;
///
///     fn pre_init(_state, _env, name) {
///         worker::console_log!("durable object initialized: {name}");
///     }
/// }
/// ```
#[macro_export]
macro_rules! instantiate_durable_object {
    ($name:ident < $durable_object:ty) => {
        instantiate_durable_object!($name < $durable_object; fn pre_init(_state, _env, _name) {});
    };
    (
        $name:ident < $durable_object:ty;

        fn pre_init($state:pat, $env:pat, $do_name:pat) $new_block:block
    ) => {
        const _: () = {
            use worker::{wasm_bindgen, async_trait, wasm_bindgen_futures};
            #[worker::durable_object]
            struct $name {
                inner: $durable_object
            }

            #[worker::durable_object]
            impl DurableObject for $name {
                fn new(state: ::worker::State, env: ::worker::Env) -> Self {
                    {
                        let $state = &state;
                        let $env = &env;
                        let $do_name = ::std::stringify!($do_name);
                        $new_block
                    }
                    Self { inner: <$durable_object>::new(state, env) }
                }

                pub async fn fetch(
                    &mut self,
                    req: ::worker::Request
                ) -> ::worker::Result<::worker::Response> {
                    self.inner.fetch(req).await
                }

                pub async fn alarm(&mut self) -> ::worker::Result<::worker::Response> {
                    self.inner.alarm().await
                }
            }
        };
    };
}

pub use instantiate_durable_object;
