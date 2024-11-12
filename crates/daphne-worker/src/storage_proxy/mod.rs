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
//! use daphne::messages::TaskId;
//!
//! let (durable_request, uri) = DurableRequest::new(
//!     bindings::AggregateStore::Merge,
//!     // some mock data here
//!     (
//!         daphne::DapVersion::Draft09,
//!         &TaskId([13; 32]),
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

use std::{future::Future, sync::Arc, time::Duration};

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
use worker::{
    js_sys::Uint8Array, Date, Delay, Env, HttpRequest, HttpResponse, Request, RequestInit,
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
        .layer(from_fn_with_state(ctx.clone(), middleware::bearer_auth))
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

impl ExpirationHeader {
    fn at_least_60s_from_now(self) -> Self {
        // KV wont let you request an expiration that isn't at least 60 seconds into the
        // future. If you try to do so, it will return a 400. The problem is, the only error
        // the worker API returns is a JsValue that might contain a string that might
        // explain that.
        //
        // In order to avoid parsing the error message we opt to just "hardcode" the
        // expiration to be, at least 65 seconds from now. Effectively expiring the value as soon
        // as possible. The extra 5 seconds are just in case we take a really long time from here to
        // the request.
        let now_plus_65_seconds = (Date::now().as_millis() / 1000) + 65;
        Self(u64::max(self.0, now_plus_65_seconds))
    }
}

async fn retry<F, T, E, Fut>(mut f: F) -> Result<T, E>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    const RETRY_DELAYS: &[Duration] = &[
        Duration::from_millis(1_000),
        Duration::from_millis(2_000),
        Duration::from_millis(4_000),
        Duration::from_millis(8_000),
    ];
    let attempts = RETRY_DELAYS.len() + 1;
    let mut attempt = 1;
    loop {
        match f(attempt).await {
            Ok(ok) => return Ok(ok),
            Err(error) => {
                if attempt < attempts {
                    Delay::from(RETRY_DELAYS[attempt - 1]).await;
                    attempt += 1;
                } else {
                    return Err(error);
                }
            }
        }
    }
}

#[tracing::instrument(skip(ctx))]
#[worker::send]
async fn kv_get(
    ctx: State<Arc<RequestContext>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let get = ctx.env.kv(KV_BINDING_DAP_CONFIG)?.get(&key);

    if let Some(bytes) = retry(|_| get.clone().bytes()).await? {
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
    let expiration = expiration.map(|TypedHeader(header)| header);

    match ctx.env.kv(KV_BINDING_DAP_CONFIG)?.put_bytes(&key, &body) {
        Ok(mut put) => {
            if let Some(expiration_unix_timestamp) = expiration {
                put = put.expiration(expiration_unix_timestamp.at_least_60s_from_now().0);
            };
            if let Err(error) = retry(|_| put.clone().execute()).await {
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
    let expiration = expiration.map(|TypedHeader(header)| header);

    let kv = ctx.env.kv(KV_BINDING_DAP_CONFIG)?;
    let listing = kv.list().prefix(key.clone());
    if retry(|_| listing.clone().execute())
        .await?
        .keys
        .into_iter()
        .any(|k| k.name == key)
    {
        Ok(StatusCode::CONFLICT.into_response())
    } else {
        match kv.put_bytes(&key, &body) {
            Ok(mut put) => {
                if let Some(expiration_unix_timestamp) = expiration {
                    put = put.expiration(expiration_unix_timestamp.at_least_60s_from_now().0);
                }
                if let Err(error) = retry(|_| put.clone().execute()).await {
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
    let kv = ctx.env.kv(KV_BINDING_DAP_CONFIG)?;
    retry(|_| kv.delete(&key)).await?;

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
    retry(|attempt| {
        let ctx = &ctx;
        let obj = &obj;
        let binding = &durable_request.binding;
        let uri = &uri;
        let http_request = http_request.clone();
        async move {
            tracing::debug!(id = obj.to_string(), "Getting DO stub");

            let stub = if let Some(loc) = option_env!("DAPHNE_DO_REGION") {
                obj.get_stub_with_location_hint(loc)
            } else {
                obj.get_stub()
            }?;

            match stub.fetch_with_request(http_request?).await {
                Ok(ok) => {
                    ctx.metrics.durable_request_retry_count_inc(
                        (attempt - 1).try_into().unwrap(),
                        binding,
                        uri,
                    );
                    Ok(HttpResponse::try_from(ok).unwrap())
                }
                Err(error) => {
                    warn!(
                        id = obj.to_string(),
                        binding = &binding,
                        path = uri,
                        attempt,
                        error = ?error,
                        "DO request failed"
                    );
                    ctx.metrics
                        .durable_request_retry_count_inc(-1, binding, uri);
                    Err(error.into())
                }
            }
        }
    })
    .await
}
