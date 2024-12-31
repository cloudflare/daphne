// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
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
use daphne::messages::{self, Time};
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
            routing::get(kv_get_handler)
                .post(kv_put_handler)
                .put(kv_put_if_not_exists_handler)
                .delete(kv_delete_handler)
                .route_layer(from_fn_with_state(
                    ctx.clone(),
                    middleware::time_kv_requests,
                )),
        )
        .route(
            constcat::concat!(DO_PATH_PREFIX, "/*path"),
            routing::any(handle_do_request_handler).layer(from_fn_with_state(
                ctx.clone(),
                middleware::time_do_requests,
            )),
        );

    #[cfg(feature = "test-utils")]
    let router = router
        .route(
            daphne_service_utils::durable_requests::PURGE_STORAGE,
            routing::any(storage_purge_handler),
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
#[worker::send]
async fn storage_purge_handler(ctx: State<Arc<RequestContext>>) -> impl IntoResponse + 'static {
    storage_purge(&ctx.env)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

#[cfg(feature = "test-utils")]
#[tracing::instrument(skip_all)]
#[worker::send]
pub async fn storage_purge(env: &Env) -> Result<(), worker::Error> {
    use daphne_service_utils::durable_requests::bindings::{DurableMethod, TestStateCleaner};

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
            &format!("https://fake-host{}", TestStateCleaner::DeleteAll.to_uri()),
            RequestInit::new().with_method(worker::Method::Post),
        )?;

        env.durable_object(TestStateCleaner::BINDING)?
            .id_from_name(TestStateCleaner::NAME_STR)?
            .get_stub()?
            .fetch_with_request(req)
            .await
    };

    futures::try_join!(kv_delete, do_delete).map(|_| ())
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

fn at_least_60s_from_now(time: messages::Time) -> messages::Time {
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
    messages::Time::max(time, now_plus_65_seconds)
}

async fn retry<F, T, E, Fut>(mut f: F) -> Result<T, E>
where
    F: FnMut(u8) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    const RETRY_DELAYS: &[Duration] = &[
        Duration::from_millis(1_000),
        Duration::from_millis(2_000),
        Duration::from_millis(4_000),
        Duration::from_millis(8_000),
    ];
    let attempts = u8::try_from(RETRY_DELAYS.len() + 1).unwrap();
    let mut attempt = 1;
    loop {
        match f(attempt).await {
            Ok(ok) => return Ok(ok),
            Err(error) => {
                if attempt < attempts {
                    Delay::from(RETRY_DELAYS[usize::from(attempt - 1)]).await;
                    tracing::warn!(attempt, error = ?error, "failed, retrying...");
                    attempt += 1;
                } else {
                    tracing::error!(attempt, error = ?error, "failed, aborting...");
                    return Err(error);
                }
            }
        }
    }
}

#[worker::send]
async fn kv_get_handler(
    ctx: State<Arc<RequestContext>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    if let Some(bytes) = kv_get(&ctx.env, &key).await? {
        Ok((StatusCode::OK, bytes).into_response())
    } else {
        Ok((StatusCode::NOT_FOUND, "value not found").into_response())
    }
}

#[tracing::instrument(skip(env))]
#[worker::send]
pub async fn kv_get(env: &Env, key: &str) -> Result<Option<Vec<u8>>, worker::Error> {
    let get = env.kv(KV_BINDING_DAP_CONFIG)?.get(key);
    Ok(retry(|_| get.clone().bytes()).await?)
}

#[worker::send]
async fn kv_put_handler(
    ctx: State<Arc<RequestContext>>,
    expiration: Option<TypedHeader<ExpirationHeader>>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, Error> {
    let expiration = expiration.map(|TypedHeader(header)| header.0);

    kv_put(&ctx.env, expiration, &key, &body).await?;

    Ok(StatusCode::OK.into_response())
}

#[tracing::instrument(skip(env, body))]
pub async fn kv_put(
    env: &Env,
    expiration: Option<messages::Time>,
    key: &str,
    body: &[u8],
) -> Result<(), worker::Error> {
    match env.kv(KV_BINDING_DAP_CONFIG)?.put_bytes(key, body) {
        Ok(mut put) => {
            if let Some(expiration_unix_timestamp) = expiration {
                put = put.expiration(at_least_60s_from_now(expiration_unix_timestamp));
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
    Ok(())
}

#[worker::send]
async fn kv_put_if_not_exists_handler(
    ctx: State<Arc<RequestContext>>,
    expiration: Option<TypedHeader<ExpirationHeader>>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, Error> {
    let expiration = expiration.map(|TypedHeader(header)| header.0);

    if kv_put_if_not_exists(&ctx.env, expiration, &key, &body).await? {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::CONFLICT)
    }
}

#[tracing::instrument(skip(env, body))]
#[worker::send]
pub async fn kv_put_if_not_exists(
    env: &Env,
    expiration: Option<messages::Time>,
    key: &str,
    body: &[u8],
) -> Result<bool, worker::Error> {
    let kv = env.kv(KV_BINDING_DAP_CONFIG)?;
    let listing = kv.list().prefix(key.to_string());
    if retry(|_| listing.clone().execute())
        .await?
        .keys
        .into_iter()
        .any(|k| k.name == key)
    {
        Ok(false)
    } else {
        match kv.put_bytes(key, body) {
            Ok(mut put) => {
                if let Some(expiration_unix_timestamp) = expiration {
                    put = put.expiration(at_least_60s_from_now(expiration_unix_timestamp));
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

        Ok(true)
    }
}

#[worker::send]
async fn kv_delete_handler(
    ctx: State<Arc<RequestContext>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    kv_delete(&ctx.env, &key).await?;

    Ok(StatusCode::OK.into_response())
}

#[tracing::instrument(skip(env))]
pub async fn kv_delete(env: &Env, key: &str) -> Result<(), worker::Error> {
    let kv = env.kv(KV_BINDING_DAP_CONFIG)?;
    retry(|_| kv.delete(key)).await?;
    Ok(())
}

/// Handle a durable object request
#[worker::send]
async fn handle_do_request_handler(
    ctx: State<Arc<RequestContext>>,
    headers: HeaderMap,
    Path(uri): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, Error> {
    let durable_request = DurableRequest::try_from(body.as_ref())
        .map_err(|e| worker::Error::RustError(format!("invalid format: {e:?}")))?;

    Ok(handle_do_request(
        &ctx.env,
        headers,
        &uri,
        durable_request,
        |attempt, binding, uri| match attempt {
            Some(attempt) => ctx.metrics.durable_request_retry_count_inc(
                attempt.try_into().unwrap(),
                binding,
                uri,
            ),
            None => ctx
                .metrics
                .durable_request_retry_count_inc(-1, binding, uri),
        },
    )
    .await?)
}

#[tracing::instrument(skip(env, headers, durable_request, retry_metric))]
#[worker::send]
pub async fn handle_do_request<P: AsRef<[u8]>>(
    env: &Env,
    headers: HeaderMap,
    uri: &str,
    durable_request: DurableRequest<P>,
    retry_metric: impl Fn(Option<u8>, &str, &str),
) -> Result<HttpResponse, worker::Error> {
    let http_request = {
        let mut do_req = RequestInit::new();
        do_req.with_method(worker::Method::Post);
        do_req.with_headers(headers.into());
        tracing::trace!(
            len = durable_request.body().len(),
            "deserializing do request"
        );

        {
            let body = durable_request.body();
            let buffer = Uint8Array::new_with_length(body.len().try_into().map_err(|_| {
                worker::Error::RustError(format!("buffer is too long {}", body.len()))
            })?);
            // TODO: avoid this copy
            buffer.copy_from(body);
            do_req.with_body(Some(buffer.into()));
        }
        let url = Url::parse("https://fake-host/").unwrap().join(uri).unwrap();
        Request::new_with_init(url.as_str(), &do_req)?
    };

    let binding = env.durable_object(&durable_request.binding)?;
    let obj = match &durable_request.id {
        ObjectIdFrom::Name(name) => binding.id_from_name(name.as_str())?,
        ObjectIdFrom::Hex(hex) => binding.id_from_string(hex.as_str())?,
    };
    retry(|attempt| {
        let obj = &obj;
        let binding = &durable_request.binding;
        let uri = &uri;
        let http_request = http_request.clone();
        let retry_metric = &retry_metric;
        async move {
            tracing::debug!(id = obj.to_string(), "Getting DO stub");

            let stub = if let Some(loc) = option_env!("DAPHNE_DO_REGION") {
                obj.get_stub_with_location_hint(loc)
            } else {
                obj.get_stub()
            }?;

            match stub.fetch_with_request(http_request?).await {
                Ok(ok) => {
                    retry_metric(Some(attempt - 1), binding, uri);
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
                    retry_metric(None, binding, uri);
                    Err(error)
                }
            }
        }
    })
    .await
}
