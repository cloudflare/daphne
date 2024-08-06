// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This is a Worker that proxies requests to the storage that Workers has access to, i.e., KV and
//! Durable Objects.
//!
//! Comunication with this Worker is done via HTTP.
//!
//! # KV
//!
//! The prefix of all KV request URIs is [`KV_PATH_PREFIX`].
//!
//! ## Getting a key
//!
//! Make a `GET` request with uri `{KV_PATH_PREFIX}/path/to/key`.
//!
//! ## Putting a key
//!
//! Make a `POST` request with uri `{KV_PATH_PREFIX}/path/to/key`. The body of the request will be
//! stored in kv as is, without any processing.
//!
//! ## Putting a key if it doesn't exist
//!
//! Make a `PUT` request with uri `{KV_PATH_PREFIX}/path/to/key`. The body of the request will be
//! stored in kv as is, without any processing, if this key is not already present in KV.
//!
//! ## Deleting a key
//!
//! Make a `DELETE` request with uri `{KV_PATH_PREFIX}/path/to/key`.
//!
//!
//! # Durable Objects
//!
//! The prefix of all durable object request URIs is [`DO_PATH_PREFIX`].
//!
//! To interact with a durable object, create an instance of [`DurableRequest`], which will be the
//! body of a `POST` request to `{DO_PATH_PREFIX}/{DURABLE_OBJECT_METHOD}` where
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
//!         daphne::DapVersion::Draft09,
//!         "some-task-id-in-hex",
//!         &daphne::DapBatchBucket::TimeInterval { batch_window: 50, shard: 0 }
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

mod metrics;

use std::{sync::OnceLock, time::Duration};

pub use self::metrics::Metrics;
use daphne::auth::BearerToken;
use daphne::messages::Time;
use daphne_service_utils::durable_requests::{
    DurableRequest, ObjectIdFrom, DO_PATH_PREFIX, KV_PATH_PREFIX,
};
use daphne_service_utils::http_headers::STORAGE_PROXY_PUT_KV_EXPIRATION;
use prometheus::Registry;
use tracing::warn;
use url::Url;
use worker::{js_sys::Uint8Array, Delay, Env, Request, RequestInit, Response};
const KV_BINDING_DAP_CONFIG: &str = "DAP_CONFIG";

struct RequestContext<'e> {
    req: Request,
    env: &'e Env,
    metrics: Metrics,
}

/// Check if the request's authorization. If unauthorized, return the reason why.
fn unauthorized_reason(ctx: &RequestContext) -> Option<worker::Result<Response>> {
    static TRUSTED_TOKEN: OnceLock<Option<BearerToken>> = OnceLock::new();

    let access_denied = |reason| Response::error(format!("Unauthorized: {reason}"), 401);
    let auth = match ctx.req.headers().get("Authorization") {
        Ok(Some(auth)) => auth,
        Ok(None) => return Some(access_denied("missing Authorization header")),
        Err(e) => return Some(Err(e)),
    };
    let Some(provided_token) = auth.strip_prefix("Bearer ").map(BearerToken::from) else {
        return Some(access_denied("Authorization header has unexpected prefix"));
    };
    let Some(trusted_token) = TRUSTED_TOKEN.get_or_init(|| {
        ctx.env
            .var("DAPHNE_SERVER_AUTH_TOKEN")
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
    env: &Env,
    registry: &Registry,
) -> worker::Result<Response> {
    let mut ctx = RequestContext {
        metrics: Metrics::new(registry),
        req,
        env,
    };

    if let Some(error_response) = unauthorized_reason(&ctx) {
        return error_response;
    }

    let path = ctx.req.path();
    if let Some(uri) = path
        .strip_prefix(KV_PATH_PREFIX)
        .and_then(|s| s.strip_prefix('/'))
    {
        handle_kv_request(&mut ctx, uri).await
    } else if let Some(uri) = path.strip_prefix(DO_PATH_PREFIX) {
        handle_do_request(&mut ctx, uri).await
    } else {
        #[cfg(feature = "test-utils")]
        if let Some("") = path.strip_prefix(daphne_service_utils::durable_requests::PURGE_STORAGE) {
            return storage_purge(&ctx).await;
        } else if let Some("") =
            path.strip_prefix(daphne_service_utils::durable_requests::STORAGE_READY)
        {
            return Response::ok("");
        }

        tracing::error!("path {path:?} was invalid");
        Response::error("invalid base path", 400)
    }
}

#[cfg(feature = "test-utils")]
/// Clear all storage. Only available to tests
async fn storage_purge(ctx: &RequestContext<'_>) -> worker::Result<Response> {
    use daphne_service_utils::durable_requests::bindings::{DurableMethod, TestStateCleaner};

    let kv_delete = async {
        let kv = ctx.env.kv(KV_BINDING_DAP_CONFIG)?;
        for key in kv.list().execute().await?.keys {
            kv.delete(&key.name).await?;
            tracing::trace!("deleted KV item {}", key.name);
        }
        Ok(())
    };

    let do_delete = async {
        let req = Request::new_with_init(
            &format!("https://fake-host{}", TestStateCleaner::DeleteAll.to_uri(),),
            RequestInit::new().with_method(worker::Method::Post),
        )?;

        ctx.env
            .durable_object(TestStateCleaner::BINDING)?
            .id_from_name(TestStateCleaner::NAME_STR)?
            .get_stub()?
            .fetch_with_request(req)
            .await
    };

    futures::try_join!(kv_delete, do_delete)?;
    Response::empty()
}

fn parse_expiration_header(ctx: &RequestContext) -> Result<Option<Time>, worker::Error> {
    let expiration_header = ctx.req.headers().get(STORAGE_PROXY_PUT_KV_EXPIRATION)?;
    expiration_header
        .map(|expiration| {
            expiration.parse::<Time>().map_err(|e| {
                worker::Error::RustError(format!("Failed to parse expiration header: {e:?}"))
            })
        })
        .transpose()
}

/// Handle a kv request.
async fn handle_kv_request(ctx: &mut RequestContext<'_>, key: &str) -> worker::Result<Response> {
    let start = std::time::Instant::now();

    match ctx.req.method() {
        worker::Method::Get => {
            let bytes = ctx
                .env
                .kv(KV_BINDING_DAP_CONFIG)
                .inspect_err(|_| {
                    ctx.metrics
                        .kv_request_time_seconds_observe("read", "error", start.elapsed())
                })?
                .get(key)
                .bytes()
                .await?;

            let elapsed = start.elapsed();

            if let Some(bytes) = bytes {
                ctx.metrics
                    .kv_request_time_seconds_observe("read", "success", elapsed);

                Response::from_bytes(bytes)
            } else {
                ctx.metrics
                    .kv_request_time_seconds_observe("read", "not_found", elapsed);

                Response::error("value not found", 404)
            }
        }
        worker::Method::Post => {
            let expiration_unix_timestamp = parse_expiration_header(ctx)?;

            match ctx
                .env
                .kv(KV_BINDING_DAP_CONFIG)?
                .put_bytes(key, &ctx.req.bytes().await?)
            {
                Ok(mut put) => {
                    if let Some(expiration_unix_timestamp) = expiration_unix_timestamp {
                        ctx.metrics.kv_request_time_seconds_observe(
                            "post",
                            "success",
                            start.elapsed(),
                        );

                        put = put.expiration(expiration_unix_timestamp);
                    }
                    if let Err(error) = put.execute().await {
                        ctx.metrics.kv_request_time_seconds_observe(
                            "post",
                            "error_execute_post",
                            start.elapsed(),
                        );

                        tracing::warn!(
                            ?error,
                            "Swallowed error from KV POST, this will hopefully retry later"
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "Swallowed error from KV POST creation, this will hopefully retry later"
                    );
                }
            }

            Response::empty()
        }

        worker::Method::Put => {
            let expiration_unix_timestamp = parse_expiration_header(ctx)?;

            let kv = ctx.env.kv(KV_BINDING_DAP_CONFIG)?;
            if kv
                .list()
                .prefix(key.into())
                .execute()
                .await?
                .keys
                .into_iter()
                .any(|k| k.name == key)
            {
                ctx.metrics.kv_request_time_seconds_observe(
                    "put",
                    "error_conflict",
                    start.elapsed(),
                );

                Response::error(String::new(), 409 /* Conflict */)
            } else {
                match kv.put_bytes(key, &ctx.req.bytes().await?) {
                    Ok(mut put) => {
                        if let Some(expiration_unix_timestamp) = expiration_unix_timestamp {
                            ctx.metrics.kv_request_time_seconds_observe(
                                "put",
                                "success",
                                start.elapsed(),
                            );

                            put = put.expiration(expiration_unix_timestamp);
                        }
                        if let Err(error) = put.execute().await {
                            ctx.metrics.kv_request_time_seconds_observe(
                                "put",
                                "error_execute_put",
                                start.elapsed(),
                            );

                            tracing::warn!(
                                ?error,
                                "Swallowed error from KV PUT, this will hopefully retry later"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            "Swallowed error from KV PUT creation, this will hopefully retry later"
                        );
                    }
                }

                Response::empty()
            }
        }
        worker::Method::Delete => {
            ctx.env.kv(KV_BINDING_DAP_CONFIG)?.delete(key).await?;

            ctx.metrics
                .kv_request_time_seconds_observe("delete", "success", start.elapsed());

            Response::empty()
        }
        _ => Response::error(String::new(), 405 /* Method not allowed */),
    }
}

/// Handle a durable object request
async fn handle_do_request(ctx: &mut RequestContext<'_>, uri: &str) -> worker::Result<Response> {
    const RETRY_DELAYS: &[Duration] = &[
        Duration::from_millis(100),
        Duration::from_millis(500),
        Duration::from_millis(1_000),
        Duration::from_millis(3_000),
    ];

    let buf = ctx.req.bytes().await.map_err(|e| {
        tracing::error!(error = ?e, "failed to get bytes");
        e
    })?;
    tracing::debug!(len = buf.len(), "deserializing do request");
    let parsed_req = DurableRequest::try_from(&buf)
        .map_err(|e| worker::Error::RustError(format!("invalid format: {e:?}")))?;

    let binding = ctx.env.durable_object(&parsed_req.binding)?;

    let mut do_req = RequestInit::new();
    do_req.with_method(worker::Method::Post);
    do_req.with_headers(ctx.req.headers().clone());
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

    let obj = match &parsed_req.id {
        ObjectIdFrom::Name(name) => binding.id_from_name(name)?,
        ObjectIdFrom::Hex(hex) => binding.id_from_string(hex)?,
    };
    let attempts = if parsed_req.retry {
        RETRY_DELAYS.len() + 1
    } else {
        1
    };
    let mut attempt = 1;
    loop {
        tracing::warn!(id = obj.to_string(), "Getting DO stub");

        let stub = if let Some(loc) = option_env!("DAPHNE_DO_REGION") {
            obj.get_stub_with_location_hint(loc)
        } else {
            obj.get_stub()
        }?;

        let start = std::time::Instant::now();

        match stub.fetch_with_request(do_req.clone()?).await {
            Ok(ok) => {
                let elapsed = start.elapsed();

                ctx.metrics
                    .durable_request_time_seconds_observe(uri, "success", elapsed);

                ctx.metrics.durable_request_retry_count_inc(
                    (attempt - 1).try_into().unwrap(),
                    &parsed_req.binding,
                    uri,
                );
                return Ok(ok);
            }
            Err(error) => {
                let elapsed = start.elapsed();

                ctx.metrics
                    .durable_request_time_seconds_observe(uri, "error", elapsed);

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
                    ctx.metrics
                        .durable_request_retry_count_inc(-1, &parsed_req.binding, uri);
                    return Err(error);
                }
            }
        }
    }
}
