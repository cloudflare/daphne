// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This is a Worker that proxies requests to the storage that Workers has access to, i.e., KV and
//! Durable Objects.
//!
//! Comunication with this Worker is done via HTTP.
//!
//! # KV
//!
//! The prefix of all KV request URIs is [`KV_PATH_BASE`].
//!
//! ## Getting a key
//!
//! Make a `GET` request with uri `{KV_PATH_BASE}/path/to/key`.
//!
//! ## Putting a key
//!
//! Make a `POST` request with uri `{KV_PATH_BASE}/path/to/key`. The body of the request will be
//! stored in kv as is, without any processing.
//!
//! ## Putting a key if it doesn't exist
//!
//! Make a `PUT` request with uri `{KV_PATH_BASE}/path/to/key`. The body of the request will be
//! stored in kv as is, without any processing, if this key is not already present in KV.
//!
//! ## Deleting a key
//!
//! Make a `DELETE` request with uri `{KV_PATH_BASE}/path/to/key`.
//!
//!
//! # Durable Objects
//!
//! The prefix of all durable object request URIs is [`DO_PATH_BASE`].
//!
//! To interact with a durable object, create an instance of [`DurableRequest`], which will be the
//! body of a `POST` request to `{DO_PATH_BASE}/{DURABLE_OBJECT_METHOD}` where
//! `DURABLE_OBJECT_METHOD` is defined by the [`DurableMethod::to_uri`][to_uri] trait method of the
//! binding used to create the [`DurableRequest`].
//!
//! ```
//! use url::Url;
//! use daphne_service_utils::durable_requests::{
//!     DurableRequest,
//!     bindings::{self, DurableMethod}
//! };
//!
//! let (durable_request, uri) = DurableRequest::new(
//!     bindings::AggregateStore::Merge,
//!     // some mock data here
//!     (
//!         daphne::DapVersion::DraftLatest,
//!         "some-task-id-in-hex",
//!         &daphne::DapBatchBucket::TimeInterval { batch_window: 50 }
//!     ),
//! );
//!
//! let worker_url = Url::parse("https://example-worker.com")
//!     .unwrap()
//!     .join(uri)
//!     .unwrap();
//!
//!
//! let _send_future = reqwest::Client::new()
//!     .post(worker_url)
//!     .body(durable_request.into_bytes())
//!     .send();
//! ```
//!
//! [to_uri]: daphne_service_utils::durable_requests::bindings::DurableMethod::to_uri

use std::{sync::OnceLock, time::Duration};

use daphne::auth::BearerToken;
use daphne_service_utils::durable_requests::{
    DurableRequest, ObjectIdFrom, DO_PATH_PREFIX, KV_PATH_PREFIX,
};
use tracing::warn;
use url::Url;
use worker::{js_sys::Uint8Array, Delay, Env, Request, RequestInit, Response};

const KV_BINDING_DAP_CONFIG: &str = "DAP_CONFIG";

/// Check if the request's authorization. If unauthorized, return the reason why.
pub fn unauthorized_reason(req: &Request, env: &Env) -> Option<worker::Result<Response>> {
    static TRUSTED_TOKEN: OnceLock<Option<BearerToken>> = OnceLock::new();

    let access_denied = |reason| Response::error(format!("Unauthorized: {reason}"), 401);
    let auth = match req.headers().get("Authorization") {
        Ok(Some(auth)) => auth,
        Ok(None) => return Some(access_denied("missing Authorization header")),
        Err(e) => return Some(Err(e)),
    };
    let Some(provided_token) = auth.strip_prefix("Bearer ").map(BearerToken::from) else {
        return Some(access_denied("Authorization header has unexpected prefix"));
    };
    let Some(trusted_token) = TRUSTED_TOKEN.get_or_init(|| {
        env.var("DAPHNE_SERVER_AUTH_TOKEN")
            .ok()
            .map(|t| t.to_string())
            .map(BearerToken::from)
    }) else {
        tracing::warn!("trusted bearer token not configured");
        return Some(Response::error(
            "Authorization token for storage proxy is not configured",
            500,
        ));
    };
    if &provided_token != trusted_token {
        return Some(access_denied("Incorrect authorization token"));
    }

    None
}

/// Handle a proxy request. This is the entry point of the Worker.
#[allow(clippy::no_effect_underscore_binding)]
pub async fn handle_request(
    req: Request,
    env: Env,
    _ctx: worker::Context,
) -> worker::Result<Response> {
    if let Some(error_response) = unauthorized_reason(&req, &env) {
        return error_response;
    }

    let path = req.path();
    if let Some(uri) = path
        .strip_prefix(KV_PATH_PREFIX)
        .and_then(|s| s.strip_prefix('/'))
    {
        handle_kv_request(req, env, uri).await
    } else if let Some(uri) = path.strip_prefix(DO_PATH_PREFIX) {
        handle_do_request(req, env, uri).await
    } else {
        #[cfg(feature = "test-utils")]
        if let Some("") = path.strip_prefix(daphne_service_utils::durable_requests::PURGE_STORAGE) {
            return storage_purge(env).await;
        }
        tracing::error!("path {path:?} was invalid");
        Response::error("invalid base path", 400)
    }
}

#[cfg(feature = "test-utils")]
/// Clear all storage. Only available to tests
async fn storage_purge(env: Env) -> worker::Result<Response> {
    use daphne_service_utils::durable_requests::bindings::{DurableMethod, GarbageCollector};

    let kv_delete = async {
        let kv = env.kv(KV_BINDING_DAP_CONFIG)?;
        for key in kv.list().execute().await?.keys {
            kv.delete(&key.name).await?;
            tracing::trace!("deleted KV item {}", key.name);
        }
        Ok(())
    };

    let do_delete = async {
        let req = Request::new_with_init(
            &format!("https://fake-host{}", GarbageCollector::DeleteAll.to_uri(),),
            RequestInit::new().with_method(worker::Method::Post),
        )?;

        env.durable_object(GarbageCollector::BINDING)?
            .id_from_name(GarbageCollector::NAME_STR)?
            .get_stub()?
            .fetch_with_request(req)
            .await
    };

    futures::try_join!(kv_delete, do_delete)?;
    Response::empty()
}

/// Handle a kv request.
async fn handle_kv_request(mut req: Request, env: Env, key: &str) -> worker::Result<Response> {
    match req.method() {
        worker::Method::Get => {
            let bytes = env.kv(KV_BINDING_DAP_CONFIG)?.get(key).bytes().await?;

            match bytes {
                Some(bytes) => Response::from_bytes(bytes),
                None => Response::error("value not found", 404),
            }
        }
        worker::Method::Post => {
            env.kv(KV_BINDING_DAP_CONFIG)?
                .put_bytes(key, &req.bytes().await?)?
                .execute()
                .await?;

            Response::empty()
        }
        worker::Method::Put => {
            let kv = env.kv(KV_BINDING_DAP_CONFIG)?;
            if kv
                .list()
                .prefix(key.into())
                .execute()
                .await?
                .keys
                .into_iter()
                .any(|k| k.name == key)
            {
                Response::error(String::new(), 409 /* Conflict */)
            } else {
                kv.put_bytes(key, &req.bytes().await?)?.execute().await?;

                Response::empty()
            }
        }
        worker::Method::Delete => {
            env.kv(KV_BINDING_DAP_CONFIG)?.delete(key).await?;

            Response::empty()
        }
        _ => Response::error(String::new(), 405 /* Method not allowed */),
    }
}

/// Handle a durable object request
async fn handle_do_request(mut req: Request, env: Env, uri: &str) -> worker::Result<Response> {
    const RETRY_DELAYS: &[Duration] = &[
        Duration::from_millis(100),
        Duration::from_millis(500),
        Duration::from_millis(1_000),
        Duration::from_millis(3_000),
    ];

    let buf = req.bytes().await.map_err(|e| {
        tracing::error!(error = ?e, "failed to get bytes");
        e
    })?;
    tracing::debug!(len = buf.len(), "deserializing do request");
    let parsed_req = DurableRequest::try_from(&buf)
        .map_err(|e| worker::Error::RustError(format!("invalid format: {e:?}")))?;

    let binding = env.durable_object(&parsed_req.binding)?;
    let obj = match &parsed_req.id {
        ObjectIdFrom::Name(name) => binding.id_from_name(name)?,
        ObjectIdFrom::Hex(hex) => binding.id_from_string(hex)?,
    };

    let mut do_req = RequestInit::new();
    do_req.with_method(worker::Method::Post);
    do_req.with_headers(req.headers().clone());
    if let body @ [_a, ..] = parsed_req.body() {
        let buffer =
            Uint8Array::new_with_length(body.len().try_into().map_err(|_| {
                worker::Error::RustError(format!("buffer is too long {}", body.len()))
            })?);
        buffer.copy_from(body);
        do_req.with_body(Some(buffer.into()));
    }
    let url = Url::parse("https://fake-host/").unwrap().join(uri).unwrap();
    let do_req = Request::new_with_init(url.as_str(), &do_req)?;

    let stub = obj.get_stub()?;

    let attempts = if parsed_req.retry {
        RETRY_DELAYS.len() + 1
    } else {
        1
    };
    let mut attempt = 1;
    loop {
        match stub.fetch_with_request(do_req.clone()?).await {
            Ok(ok) => return Ok(ok),
            Err(error) => {
                if attempt < attempts {
                    warn!(
                        binding = parsed_req.binding,
                        path = uri,
                        attempt,
                        error = ?error,
                        "DO request failed"
                    );
                    Delay::from(RETRY_DELAYS[attempt - 1]).await;
                    attempt += 1;
                } else {
                    return Err(error);
                }
            }
        }
    }
}
