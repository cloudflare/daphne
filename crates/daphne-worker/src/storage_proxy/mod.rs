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

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

pub use self::metrics::Metrics;
use axum::{
    extract::{Path, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use bytes::Bytes;
use daphne::messages::{constant_time_eq, Time};
use daphne_service_utils::durable_requests::{
    DurableRequest, ObjectIdFrom, DO_PATH_PREFIX, KV_PATH_PREFIX,
};
use daphne_service_utils::http_headers::STORAGE_PROXY_PUT_KV_EXPIRATION;
use http::{HeaderMap, Method, StatusCode};
use opentelemetry_http::HeaderExtractor;
use prometheus::Registry;
use tower_service::Service;
use tracing::{info_span, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;
use worker::HttpRequest;
use worker::{
    js_sys::Uint8Array, send::SendFuture, Delay, Env, HttpResponse, Request, RequestInit,
};

const KV_BINDING_DAP_CONFIG: &str = "DAP_CONFIG";

struct RequestContext {
    env: Env,
    metrics: Metrics,
}

struct Error(worker::Error);

impl From<worker::kv::KvError> for Error {
    fn from(value: worker::kv::KvError) -> Self {
        Self(worker::Error::from(value))
    }
}

impl From<worker::Error> for Error {
    fn from(value: worker::Error) -> Self {
        Self(value)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
    }
}

/// Check if the request's authorization. If unauthorized, return the reason why.
async fn unauthorized_reason(
    ctx: State<Arc<RequestContext>>,
    bearer: TypedHeader<Authorization<Bearer>>,
    request: axum::extract::Request,
    mut next: Next,
) -> axum::response::Response {
    static TRUSTED_TOKEN: OnceLock<Option<String>> = OnceLock::new();

    let Some(trusted_token) = TRUSTED_TOKEN.get_or_init(|| {
        ctx.env
            .var("DAPHNE_SERVER_AUTH_TOKEN")
            .ok()
            .map(|t| t.to_string())
    }) else {
        tracing::warn!("trusted bearer token not configured");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Authorization token for storage proxy is not configured",
        )
            .into_response();
    };

    if !constant_time_eq(bearer.token().as_bytes(), trusted_token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "Incorrect authorization token").into_response();
    }

    next.call(request.map(axum::body::Body::new)).await.unwrap()
}

/// Handle a proxy request. This is the entry point of the Worker.
pub async fn handle_request(req: HttpRequest, env: Env, registry: &Registry) -> Response {
    let span = info_span!("handle_request", path = req.uri().path(), method = ?req.method());
    {
        let extractor = HeaderExtractor(req.headers());
        let remote_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&extractor)
        });
        span.set_parent(remote_context);
    }

    let ctx = Arc::new(RequestContext {
        metrics: Metrics::new(registry),
        env,
    });

    let router = axum::Router::new()
        .route(
            constcat::concat!(KV_PATH_PREFIX, "/:path"),
            routing::any(handle_kv_request),
        )
        .route(
            constcat::concat!(DO_PATH_PREFIX, "/:path"),
            routing::any(handle_do_request),
        );

    #[cfg(feature = "test-utils")]
    let router = router
        .route(
            daphne_service_utils::durable_requests::PURGE_STORAGE,
            routing::any(storage_purge),
        )
        .route(
            daphne_service_utils::durable_requests::STORAGE_READY,
            routing::any(StatusCode::OK),
        );

    let mut router = router
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            unauthorized_reason,
        ))
        .with_state(ctx);
    router.call(req).await.unwrap()
}

#[cfg(feature = "test-utils")]
async fn storage_purge(ctx: State<Arc<RequestContext>>) -> impl IntoResponse + 'static {
    use daphne_service_utils::durable_requests::bindings::{DurableMethod, TestStateCleaner};
    use worker::send::SendFuture;

    let kv_delete = async {
        let kv = ctx.env.kv(KV_BINDING_DAP_CONFIG)?;
        for key in kv.list().execute().await?.keys {
            kv.delete(&key.name).await?;
            tracing::trace!("deleted KV item {}", key.name);
        }
        Ok(())
    };

    let do_delete = async {
        let mut req = Request::new_with_init(
            &format!("https://fake-host{}", TestStateCleaner::DeleteAll.to_uri()),
            RequestInit::new().with_method(worker::Method::Post),
        )?;

        crate::tracing_utils::add_tracing_headers(&mut req);

        ctx.env
            .durable_object(TestStateCleaner::BINDING)?
            .id_from_name(TestStateCleaner::NAME_STR)?
            .get_stub()?
            .fetch_with_request(req)
            .await
    };

    SendFuture::new(async { futures::try_join!(kv_delete, do_delete) })
        .await
        .map(|_| ())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

fn parse_expiration_header(headers: &HeaderMap) -> Result<Option<Time>, worker::Error> {
    let expiration_header = headers
        .get(STORAGE_PROXY_PUT_KV_EXPIRATION)
        .map(|h| h.to_str())
        .transpose()
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    expiration_header
        .map(|expiration| {
            expiration.parse::<Time>().map_err(|e| {
                worker::Error::RustError(format!("Failed to parse expiration header: {e:?}"))
            })
        })
        .transpose()
}

/// Handle a kv request.
#[axum_macros::debug_handler]
async fn handle_kv_request(
    ctx: State<Arc<RequestContext>>,
    headers: HeaderMap,
    method: Method,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, Error> {
    SendFuture::new(async move {
        match method {
            Method::GET => {
                let bytes = ctx.env.kv(KV_BINDING_DAP_CONFIG)?.get(&key).bytes().await?;

                match bytes {
                    Some(bytes) => Ok((StatusCode::OK, bytes).into_response()),
                    None => Ok((StatusCode::NOT_FOUND, "value not found").into_response()),
                }
            }
            Method::POST => {
                let expiration_unix_timestamp = parse_expiration_header(&headers)?;

                match ctx.env.kv(KV_BINDING_DAP_CONFIG)?.put_bytes(&key, &body) {
                    Ok(mut put) => {
                        if let Some(expiration_unix_timestamp) = expiration_unix_timestamp {
                            put = put.expiration(expiration_unix_timestamp);
                        }
                        if let Err(error) = put.execute().await {
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

                Ok(StatusCode::OK.into_response())
            }

            Method::PUT => {
                let expiration_unix_timestamp = parse_expiration_header(&headers)?;

                let kv = ctx.env.kv(KV_BINDING_DAP_CONFIG)?;
                if kv
                    .list()
                    .prefix(key.clone())
                    .execute()
                    .await?
                    .keys
                    .into_iter()
                    .any(|k| k.name == key)
                {
                    Ok(StatusCode::CONFLICT.into_response())
                } else {
                    match kv.put_bytes(&key, &body) {
                        Ok(mut put) => {
                            if let Some(expiration_unix_timestamp) = expiration_unix_timestamp {
                                put = put.expiration(expiration_unix_timestamp);
                            }
                            if let Err(error) = put.execute().await {
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

                    Ok(StatusCode::OK.into_response())
                }
            }
            Method::DELETE => {
                ctx.env.kv(KV_BINDING_DAP_CONFIG)?.delete(&key).await?;

                Ok(StatusCode::OK.into_response())
            }
            _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        }
    })
    .await
}

/// Handle a durable object request
#[axum_macros::debug_handler]
async fn handle_do_request(
    ctx: State<Arc<RequestContext>>,
    headers: HeaderMap,
    Path(uri): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, Error> {
    const RETRY_DELAYS: &[Duration] = &[
        Duration::from_millis(100),
        Duration::from_millis(500),
        Duration::from_millis(1_000),
        Duration::from_millis(3_000),
    ];

    SendFuture::new(async move {
        let mut do_req = RequestInit::new();
        do_req.with_method(worker::Method::Post);
        do_req.with_headers(headers.into());
        tracing::debug!(len = body.len(), "deserializing do request");
        let parsed_req = DurableRequest::try_from(body.as_ref())
            .map_err(|e| worker::Error::RustError(format!("invalid format: {e:?}")))?;

        let binding = ctx.env.durable_object(&parsed_req.binding)?;

        if let body @ [_a, ..] = parsed_req.body() {
            let buffer = Uint8Array::new_with_length(body.len().try_into().map_err(|_| {
                worker::Error::RustError(format!("buffer is too long {}", body.len()))
            })?);
            buffer.copy_from(body);
            do_req.with_body(Some(buffer.into()));
        }
        let url = Url::parse("https://fake-host/")
            .unwrap()
            .join(&uri)
            .unwrap();
        let mut do_req = Request::new_with_init(url.as_str(), &do_req)?;

        crate::tracing_utils::add_tracing_headers(&mut do_req);

        let obj = match &parsed_req.id {
            ObjectIdFrom::Name(name) => binding.id_from_name(name.as_str())?,
            ObjectIdFrom::Hex(hex) => binding.id_from_string(hex.as_str())?,
        };
        let attempts = if parsed_req.retry {
            RETRY_DELAYS.len() + 1
        } else {
            1
        };
        let mut attempt = 1;
        loop {
            tracing::warn!(id = obj.to_string(), "Getting DO stub");

            match obj.get_stub()?.fetch_with_request(do_req.clone()?).await {
                Ok(ok) => {
                    ctx.metrics.durable_request_retry_count_inc(
                        (attempt - 1).try_into().unwrap(),
                        &parsed_req.binding,
                        &uri,
                    );
                    return Ok(HttpResponse::try_from(ok).unwrap());
                }
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
                        ctx.metrics
                            .durable_request_retry_count_inc(-1, &parsed_req.binding, &uri);
                        return Err(error.into());
                    }
                }
            }
        }
    })
    .await
}
