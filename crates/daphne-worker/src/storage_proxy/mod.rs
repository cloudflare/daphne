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
mod middleware;

use std::{sync::Arc, time::Duration};

pub use self::metrics::Metrics;
use axum::{
    extract::{Path, State},
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing,
};
use axum_extra::TypedHeader;
use bytes::Bytes;
use daphne::messages::Time;
use daphne_service_utils::durable_requests::{
    DurableRequest, ObjectIdFrom, DO_PATH_PREFIX, KV_PATH_PREFIX,
};
use daphne_service_utils::http_headers::STORAGE_PROXY_PUT_KV_EXPIRATION;
use headers::Header;
use http::{HeaderMap, StatusCode};
use prometheus::Registry;
use tower_service::Service;
use tracing::warn;
use url::Url;
use worker::{js_sys::Uint8Array, Delay, Env, HttpRequest, HttpResponse, Request, RequestInit};

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

/// Handle a proxy request. This is the entry point of the Worker.
pub async fn handle_request(req: HttpRequest, env: Env, registry: &Registry) -> Response {
    let ctx = Arc::new(RequestContext {
        metrics: Metrics::new(registry),
        env,
    });

    let router = axum::Router::new()
        .route(
            constcat::concat!(KV_PATH_PREFIX, "/*path"),
            routing::get(kv_get)
                .post(kv_put)
                .put(kv_put_if_not_exists)
                .delete(kv_delete)
                .route_layer(from_fn_with_state(
                    ctx.clone(),
                    middleware::time_kv_requests,
                )),
        )
        .route(
            constcat::concat!(DO_PATH_PREFIX, "/*path"),
            routing::any(handle_do_request).layer(from_fn_with_state(
                ctx.clone(),
                middleware::time_do_requests,
            )),
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
        .layer(from_fn_with_state(
            ctx.clone(),
            middleware::unauthorized_reason,
        ))
        .with_state(ctx);
    router.call(req).await.unwrap()
}

/// Clear all storage. Only available to tests
#[cfg(feature = "test-utils")]
#[tracing::instrument(skip(ctx))]
#[worker::send]
async fn storage_purge(ctx: State<Arc<RequestContext>>) -> impl IntoResponse + 'static {
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
            &format!("https://fake-host{}", TestStateCleaner::DeleteAll.to_uri()),
            RequestInit::new().with_method(worker::Method::Post),
        )?;

        ctx.env
            .durable_object(TestStateCleaner::BINDING)?
            .id_from_name(TestStateCleaner::NAME_STR)?
            .get_stub()?
            .fetch_with_request(req)
            .await
    };

    futures::try_join!(kv_delete, do_delete)
        .map(|_| ())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

#[derive(Debug)]
struct ExpirationHeader(Time);

impl Header for ExpirationHeader {
    fn name() -> &'static http::HeaderName {
        static HEADER_NAME: http::HeaderName =
            http::HeaderName::from_static(STORAGE_PROXY_PUT_KV_EXPIRATION);

        &HEADER_NAME
    }

    fn encode<E: Extend<http::HeaderValue>>(&self, values: &mut E) {
        values.extend(http::HeaderValue::from_str(&self.0.to_string()))
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .map(Self)
            .ok_or_else(headers::Error::invalid)
    }
}

#[tracing::instrument(skip(ctx))]
#[worker::send]
async fn kv_get(
    ctx: State<Arc<RequestContext>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let bytes = ctx.env.kv(KV_BINDING_DAP_CONFIG)?.get(&key).bytes().await?;

    if let Some(bytes) = bytes {
        Ok((StatusCode::OK, bytes).into_response())
    } else {
        Ok((StatusCode::NOT_FOUND, "value not found").into_response())
    }
}

#[tracing::instrument(skip(ctx, body))]
#[worker::send]
async fn kv_put(
    ctx: State<Arc<RequestContext>>,
    expiration: Option<TypedHeader<ExpirationHeader>>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, Error> {
    let expiration_unix_timestamp = expiration.map(|TypedHeader(header)| header.0);

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

#[tracing::instrument(skip(ctx, body))]
#[worker::send]
async fn kv_put_if_not_exists(
    ctx: State<Arc<RequestContext>>,
    expiration: Option<TypedHeader<ExpirationHeader>>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, Error> {
    let expiration_unix_timestamp = expiration.map(|TypedHeader(header)| header.0);

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

#[tracing::instrument(skip(ctx))]
#[worker::send]
async fn kv_delete(
    ctx: State<Arc<RequestContext>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    ctx.env.kv(KV_BINDING_DAP_CONFIG)?.delete(&key).await?;

    Ok(StatusCode::OK.into_response())
}

/// Handle a durable object request
#[tracing::instrument(skip(ctx, headers, body))]
#[worker::send]
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

    let durable_request = DurableRequest::try_from(body.as_ref())
        .map_err(|e| worker::Error::RustError(format!("invalid format: {e:?}")))?;

    let http_request = {
        let mut do_req = RequestInit::new();
        do_req.with_method(worker::Method::Post);
        do_req.with_headers(headers.into());
        tracing::debug!(len = body.len(), "deserializing do request");

        {
            let body = durable_request.body();
            let buffer = Uint8Array::new_with_length(body.len().try_into().map_err(|_| {
                worker::Error::RustError(format!("buffer is too long {}", body.len()))
            })?);
            // TODO: avoid this copy
            buffer.copy_from(body);
            do_req.with_body(Some(buffer.into()));
        }
        let url = Url::parse("https://fake-host/")
            .unwrap()
            .join(&uri)
            .unwrap();
        Request::new_with_init(url.as_str(), &do_req)?
    };

    let binding = ctx.env.durable_object(&durable_request.binding)?;
    let obj = match &durable_request.id {
        ObjectIdFrom::Name(name) => binding.id_from_name(name.as_str())?,
        ObjectIdFrom::Hex(hex) => binding.id_from_string(hex.as_str())?,
    };
    let attempts = if durable_request.retry {
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

        match stub.fetch_with_request(http_request.clone()?).await {
            Ok(ok) => {
                ctx.metrics.durable_request_retry_count_inc(
                    (attempt - 1).try_into().unwrap(),
                    &durable_request.binding,
                    &uri,
                );
                return Ok(HttpResponse::try_from(ok).unwrap());
            }
            Err(error) => {
                if attempt < attempts {
                    warn!(
                        binding = durable_request.binding,
                        path = uri,
                        attempt,
                        error = ?error,
                        "DO request failed"
                    );
                    Delay::from(RETRY_DELAYS[attempt - 1]).await;
                    attempt += 1;
                } else {
                    ctx.metrics
                        .durable_request_retry_count_inc(-1, &durable_request.binding, &uri);
                    return Err(error.into());
                }
            }
        }
    }
}
