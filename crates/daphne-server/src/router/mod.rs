// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod aggregator;
mod helper;
mod leader;
#[cfg(feature = "test-utils")]
pub mod test_routes;

use std::sync::Arc;

use axum::{
    async_trait,
    body::HttpBody,
    extract::{FromRequest, FromRequestParts, Path, State},
    http::{header::CONTENT_TYPE, HeaderValue, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use daphne::{
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{AggregationJobId, CollectionJobId, TaskId},
    DapError, DapRequest, DapResource, DapResponse, DapSender, DapVersion,
};
use daphne_service_utils::{
    bearer_token::BearerToken,
    http_headers,
    metrics::{self, DaphneServiceMetrics},
    DapRole,
};
use either::Either;
use http::{HeaderMap, Request};
use serde::Deserialize;

use crate::App;

type Router<A, B> = axum::Router<Arc<A>, B>;

/// Capabilities necessary when running a native daphne service.
#[async_trait]
pub trait DaphneService {
    /// The service metrics
    fn server_metrics(&self) -> &dyn DaphneServiceMetrics;

    fn signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
        None
    }

    /// Checks if a bearer token is accepted.
    ///
    /// # Errors
    ///
    /// Returns an either:
    /// - left: error message with the reason why the token wasn't accepted.
    /// - right: an internal error that made checking the token impossible.
    async fn check_bearer_token(
        &self,
        presented_token: &BearerToken,
        sender: DapSender,
        task_id: TaskId,
        is_taskprov: bool,
    ) -> Result<(), Either<String, DapError>>;

    /// Checks if this request intends to use taskprov.
    async fn is_using_taskprov(&self, req: &DapRequest) -> Result<bool, DapError>;
}

#[async_trait]
impl<S> DaphneService for Arc<S>
where
    S: DaphneService + Send + Sync,
{
    fn server_metrics(&self) -> &dyn DaphneServiceMetrics {
        S::server_metrics(&**self)
    }

    fn signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
        S::signing_key(&**self)
    }

    async fn check_bearer_token(
        &self,
        presented_token: &BearerToken,
        sender: DapSender,
        task_id: TaskId,
        is_taskprov: bool,
    ) -> Result<(), Either<String, DapError>> {
        S::check_bearer_token(&**self, presented_token, sender, task_id, is_taskprov).await
    }

    async fn is_using_taskprov(&self, req: &DapRequest) -> Result<bool, DapError> {
        S::is_using_taskprov(&**self, req).await
    }
}

pub fn new<B>(role: DapRole, aggregator: App) -> axum::Router<(), B>
where
    B: Send + HttpBody + 'static,
    B::Data: Send,
    B::Error: Send + Sync + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let router = axum::Router::new();

    let router = aggregator::add_aggregator_routes(router);

    let router = match role {
        DapRole::Leader => leader::add_leader_routes(router),
        DapRole::Helper => helper::add_helper_routes(router),
    };

    #[cfg(feature = "test-utils")]
    let router = test_routes::add_test_routes(router, role);

    async fn request_metrics<B>(
        State(app): State<Arc<App>>,
        req: Request<B>,
        next: Next<B>,
    ) -> impl IntoResponse {
        tracing::info!(
            method = %req.method(),
            uri = %req.uri(),
            headers = ?req.headers(),
            "received request",
        );
        let resp = next.run(req).await;
        app.server_metrics()
            .count_http_status_code(resp.status().as_u16());
        tracing::info!(
            status_code = %resp.status(),
            headers = ?resp.headers(),
            "request finished"
        );
        resp
    }

    let app = Arc::new(aggregator);
    router
        .with_state(app.clone())
        .layer(
            tower::ServiceBuilder::new().layer(axum::middleware::from_fn_with_state(
                app.clone(),
                request_metrics,
            )),
        )
}

struct AxumDapResponse(axum::response::Response);

impl AxumDapResponse {
    pub fn new_success(response: DapResponse, metrics: &dyn DaphneServiceMetrics) -> Self {
        Self::new_success_with_code(response, metrics, StatusCode::OK)
    }

    pub fn new_success_with_code(
        response: DapResponse,
        metrics: &dyn DaphneServiceMetrics,
        status_code: StatusCode,
    ) -> Self {
        let Some(media_type) = response.media_type.as_str_for_version(response.version) else {
            return AxumDapResponse::new_error(
                fatal_error!(err = "invalid content-type for DAP version"),
                metrics,
            );
        };
        let media_type = match HeaderValue::from_str(media_type) {
            Ok(media_type) => media_type,
            Err(e) => {
                return AxumDapResponse::new_error(
                    fatal_error!(err = ?e, "content-type contained invalid bytes {media_type:?}"),
                    metrics,
                )
            }
        };

        let headers = [(CONTENT_TYPE, media_type)];

        Self((status_code, headers, response.payload).into_response())
    }

    pub fn new_error<E: Into<DapError>>(error: E, metrics: &dyn DaphneServiceMetrics) -> Self {
        // trigger abort if transition failures reach this point.
        let error = match error.into() {
            DapError::Transition(failure) => DapAbort::report_rejected(failure),
            DapError::Fatal(e) => Err(e),
            DapError::Abort(abort) => Ok(abort),
        };
        let status = if let Err(_e) = &error {
            // TODO(mendess) uncomment the line below
            // self.error_reporter.report_abort(&e);
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::BAD_REQUEST
        };
        let problem_details = match error {
            Ok(error) => {
                tracing::error!(?error, "request aborted due to protocol abort");
                error.into_problem_details()
            }
            Err(error) => {
                tracing::error!(?error, "request aborted due to fatal error");
                DapError::Fatal(error).into_problem_details()
            }
        };
        // this to string is bounded by the
        // number of variants in the enum
        metrics.abort_count_inc(&problem_details.title);
        let headers = [(CONTENT_TYPE, "application/problem+json")];

        Self((status, headers, Json(problem_details)).into_response())
    }

    pub fn from_result<E>(
        result: Result<DapResponse, E>,
        metrics: &dyn DaphneServiceMetrics,
    ) -> Self
    where
        E: Into<DapError>,
    {
        Self::from_result_with_success_code(result, metrics, StatusCode::OK)
    }

    pub fn from_result_with_success_code<E>(
        result: Result<DapResponse, E>,
        metrics: &dyn DaphneServiceMetrics,
        status_code: StatusCode,
    ) -> Self
    where
        E: Into<DapError>,
    {
        match result {
            Ok(o) => Self::new_success_with_code(o, metrics, status_code),
            Err(e) => Self::new_error(e, metrics),
        }
    }
}

impl IntoResponse for AxumDapResponse {
    fn into_response(self) -> axum::response::Response {
        self.0
    }
}

/// An axum extractor capable of parsing a [`DapRequest`].
#[derive(Debug)]
struct UnauthenticatedDapRequestExtractor(pub DapRequest);

#[async_trait]
impl<S, B> FromRequest<S, B> for UnauthenticatedDapRequestExtractor
where
    S: DaphneService + Send + Sync,
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PathParams {
            version: DapVersion,
            #[serde(default, with = "daphne::messages::base64url_option")]
            task_id: Option<TaskId>,
            #[serde(default, with = "daphne::messages::base64url_option")]
            agg_job_id: Option<AggregationJobId>,
            #[serde(default, with = "daphne::messages::base64url_option")]
            collect_job_id: Option<CollectionJobId>,
        }

        let (mut parts, body) = req.into_parts();
        let Path(PathParams {
            version,
            task_id,
            agg_job_id,
            collect_job_id,
        }) = Path::from_request_parts(&mut parts, state)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        let media_type = if let Some(content_type) = parts.headers.get(CONTENT_TYPE) {
            let content_type = content_type.to_str().map_err(|_| {
                let msg = "header value contains non ascii or invisible characters".into();
                (StatusCode::BAD_REQUEST, msg)
            })?;
            let mt = DapMediaType::from_str_for_version(version, content_type)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid media type".into()))?;
            Some(mt)
        } else {
            None
        };

        let taskprov = extract_header_as_string(&parts.headers, http_headers::DAP_TASKPROV);

        // TODO(mendess): this is very eager, we could redesign DapResponse later to allow for
        // streaming of data.
        let payload = hyper::body::to_bytes(body).await;

        let Ok(payload) = payload else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to get payload".into(),
            ));
        };

        let (task_id, resource) = {
            let resource = match media_type {
                Some(DapMediaType::AggregationJobInitReq) => {
                    if let Some(agg_job_id) = agg_job_id {
                        DapResource::AggregationJob(agg_job_id)
                    } else {
                        // Missing or invalid agg job ID. This should be handled as a bad
                        // request (undefined resource) by the caller.
                        DapResource::Undefined
                    }
                }
                Some(DapMediaType::CollectReq) => {
                    if let Some(collect_job_id) = collect_job_id {
                        DapResource::CollectionJob(collect_job_id)
                    } else {
                        // Missing or invalid agg job ID. This should be handled as a bad
                        // request (undefined resource) by the caller.
                        DapResource::Undefined
                    }
                }
                _ => DapResource::Undefined,
            };

            (task_id, resource)
        };

        let request = DapRequest {
            version,
            task_id,
            resource,
            payload: payload.to_vec(),
            media_type,
            taskprov,
        };

        Ok(UnauthenticatedDapRequestExtractor(request))
    }
}

/// An axum extractor capable of parsing a [`DapRequest`].
///
/// This extractor asserts that the request is authenticated.
#[derive(Debug)]
struct DapRequestExtractor(pub DapRequest);

#[async_trait]
impl<S, B> FromRequest<S, B> for DapRequestExtractor
where
    S: DaphneService + Send + Sync,
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let bearer_token = extract_header_as_string(req.headers(), http_headers::DAP_AUTH_TOKEN)
            .map(BearerToken::from);
        let cf_tls_client_auth = extract_header_as_string(req.headers(), "X-Client-Cert-Verified");

        let request = UnauthenticatedDapRequestExtractor::from_request(req, state)
            .await?
            .0;

        let is_taskprov = state
            .is_using_taskprov(&request)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()))?;

        let bearer_authed = if let Some((token, sender)) =
            bearer_token.zip(request.media_type.map(|m| m.sender()))
        {
            state
                .server_metrics()
                .auth_method_inc(metrics::AuthMethod::BearerToken);
            state
                .check_bearer_token(
                    &token,
                    sender,
                    request.task_id.unwrap(), // task ids are mandatory
                    is_taskprov,
                )
                .await
                .map_err(|reason| {
                    reason.either(
                        |reason| (StatusCode::UNAUTHORIZED, reason),
                        |_| (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
                    )
                })?;
            true
        } else {
            false
        };
        let mtls_authed = if let Some(verification_result) = cf_tls_client_auth {
            state
                .server_metrics()
                .auth_method_inc(metrics::AuthMethod::TlsClientAuth);
            // we always check if mtls succedded even if ...
            if verification_result != "SUCCESS" {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid TLS certificate ({verification_result})"),
                ));
            }
            // ... we only allow mtls auth for taskprov tasks
            is_taskprov
        } else {
            false
        };

        if bearer_authed || mtls_authed {
            Ok(Self(request))
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                "No suitable authorization method was found".into(),
            ))
        }
    }
}

fn extract_header_as_string(headers: &HeaderMap, header: &'static str) -> Option<String> {
    headers.get(header)?.to_str().ok().map(ToString::to_string)
}

#[cfg(test)]
mod test {
    use std::{
        sync::{Arc, OnceLock},
        time::Duration,
    };

    use axum::{
        body::{Body, HttpBody},
        extract::State,
        http::{header::CONTENT_TYPE, Request, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use daphne::{
        async_test_versions,
        messages::{AggregationJobId, Base64Encode, TaskId},
        DapError, DapRequest, DapResource, DapSender, DapVersion,
    };
    use daphne_service_utils::{
        bearer_token::BearerToken, http_headers, metrics::DaphnePromServiceMetrics,
    };
    use either::Either::{self, Left};
    use futures::{future::BoxFuture, FutureExt};
    use rand::{thread_rng, Rng};
    use tokio::{
        sync::mpsc::{self, Sender},
        time::timeout,
    };
    use tower::ServiceExt;

    use crate::router::DapRequestExtractor;

    use super::UnauthenticatedDapRequestExtractor;

    const BEARER_TOKEN: &str = "test-token";

    /// Return a function that will parse a request using the [`DapRequestExtractor`] or
    /// [`UnauthenticatedDapRequestExtractor`] and return the parsed request.
    ///
    /// The possible request URIs that are supported by this parser are:
    ///  - `/:version/:task_id/auth` uses the [`DapRequestExtractor`]
    ///  - `/:version/:task_id/parse-mandatory-fields` uses the [`UnauthenticatedDapRequestExtractor`]
    ///  - `/:version/:agg_job_id/parse-agg-job-id` uses the [`UnauthenticatedDapRequestExtractor`]
    ///  - `/:version/:collect_job_id/parse-collect-job-id` uses the [`UnauthenticatedDapRequestExtractor`]
    fn test_router<B>(
    ) -> impl FnOnce(Request<B>) -> BoxFuture<'static, Result<DapRequest, StatusCode>>
    where
        B: Send + Sync + 'static + HttpBody,
        B::Data: Send,
        B::Error: Send + Sync + std::error::Error,
    {
        type Channel = Sender<DapRequest>;

        #[axum::async_trait]
        impl super::DaphneService for Channel {
            fn server_metrics(&self) -> &dyn daphne_service_utils::metrics::DaphneServiceMetrics {
                // These tests don't care about metrics so we just store a static instance here so I
                // can implement the DaphneService trait for Channel.
                static METRICS: OnceLock<DaphnePromServiceMetrics> = OnceLock::new();
                METRICS.get_or_init(|| {
                    DaphnePromServiceMetrics::register(prometheus::default_registry()).unwrap()
                })
            }

            fn signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
                None
            }

            async fn check_bearer_token(
                &self,
                token: &BearerToken,
                _sender: DapSender,
                _task_id: TaskId,
                _is_taskprov: bool,
            ) -> Result<(), Either<String, DapError>> {
                (token.as_str() == BEARER_TOKEN)
                    .then_some(())
                    .ok_or_else(|| Left("invalid token".into()))
            }

            async fn is_using_taskprov(&self, req: &DapRequest) -> Result<bool, DapError> {
                Ok(req.taskprov.is_some())
            }
        }

        // setup a channel to "smuggle" the parsed request out of a handler
        let (tx, mut rx) = mpsc::channel(1);

        // create a router that takes the send end of the channel as state
        let router = Router::new()
            .route("/:version/:task_id/auth", get(auth_handler))
            .route("/:version/:task_id/parse-mandatory-fields", get(handler))
            .route(
                "/:version/:task_id/:agg_job_id/parse-agg-job-id",
                get(handler),
            )
            .route(
                "/:version/:task_id/:collect_job_id/parse-collect-job-id",
                get(handler),
            )
            .with_state(Arc::new(tx));

        // unauthenticated handler that simply sends the received request through the channel
        async fn handler(
            State(ch): State<Arc<Channel>>,
            UnauthenticatedDapRequestExtractor(req): UnauthenticatedDapRequestExtractor,
        ) -> impl IntoResponse {
            ch.send(req).await.unwrap();
        }

        // unauthenticated handler that simply sends the received request through the channel
        async fn auth_handler(
            State(ch): State<Arc<Channel>>,
            DapRequestExtractor(req): DapRequestExtractor,
        ) -> impl IntoResponse {
            ch.send(req).await.unwrap();
        }

        move |req| {
            Box::pin(async move {
                let resp = match timeout(Duration::from_secs(1), router.oneshot(req))
                    .await
                    .unwrap()
                {
                    Ok(resp) => resp,
                    Err(i) => match i {},
                };

                match resp.status() {
                    StatusCode::NOT_FOUND => panic!("unsuported uri"),
                    StatusCode::BAD_REQUEST => {
                        panic!(
                            "parsing failed: {}",
                            String::from_utf8_lossy(
                                &hyper::body::to_bytes(resp.into_body()).await.unwrap()
                            )
                        )
                    }
                    // get the request sent through the channel in the handler
                    StatusCode::OK => Ok(rx.recv().now_or_never().unwrap().unwrap()),
                    code => Err(code),
                }
            })
        }
    }

    fn mk_task_id() -> TaskId {
        TaskId(thread_rng().gen())
    }

    async fn parse_mandatory_fields(version: DapVersion) {
        let test = test_router();

        let task_id = mk_task_id();
        let req = test(
            Request::builder()
                .uri(format!(
                    "/{version}/{}/parse-mandatory-fields",
                    task_id.to_base64url()
                ))
                .header(CONTENT_TYPE, "application/dap-aggregation-job-init-req")
                .header(http_headers::DAP_AUTH_TOKEN, BEARER_TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(req.version, version);
        assert_eq!(req.task_id.unwrap(), task_id);
    }

    async_test_versions! { parse_mandatory_fields }

    async fn parse_agg_job_id(version: DapVersion) {
        let test = test_router();

        let task_id = mk_task_id();
        let agg_job_id = AggregationJobId(thread_rng().gen());

        let req = test(
            Request::builder()
                .uri(format!(
                    "/{version}/{}/{}/parse-agg-job-id",
                    task_id.to_base64url(),
                    agg_job_id.to_base64url(),
                ))
                .header(CONTENT_TYPE, "application/dap-aggregation-job-init-req")
                .header(http_headers::DAP_AUTH_TOKEN, BEARER_TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(req.resource, DapResource::AggregationJob(agg_job_id));
        assert_eq!(req.task_id.unwrap(), task_id);
    }

    async_test_versions! { parse_agg_job_id }

    async fn incorrect_bearer_tokens_are_rejected(version: DapVersion) {
        let test = test_router();

        let status_code = test(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header(CONTENT_TYPE, "application/dap-aggregation-job-init-req")
                .header(http_headers::DAP_AUTH_TOKEN, "something incorrect")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        assert_eq!(status_code, StatusCode::UNAUTHORIZED);
    }

    async_test_versions! { incorrect_bearer_tokens_are_rejected }

    async fn missing_auth_is_rejected(version: DapVersion) {
        let test = test_router();

        let status_code = test(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header(CONTENT_TYPE, "application/dap-aggregation-job-init-req")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        assert_eq!(status_code, StatusCode::UNAUTHORIZED);
    }

    async_test_versions! { missing_auth_is_rejected }

    async fn mtls_auth_is_enough(version: DapVersion) {
        let test = test_router();

        let req = test(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header(CONTENT_TYPE, "application/dap-aggregation-job-init-req")
                .header("X-Client-Cert-Verified", "SUCCESS")
                .header(http_headers::DAP_TASKPROV, "some-taskprov-string")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        req.unwrap();
    }

    async_test_versions! { mtls_auth_is_enough }

    async fn incorrect_bearer_tokens_are_rejected_even_with_mtls_auth(version: DapVersion) {
        let test = test_router();

        let code = test(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header(CONTENT_TYPE, "application/dap-aggregation-job-init-req")
                .header(http_headers::DAP_AUTH_TOKEN, "something incorrect")
                .header("X-Client-Cert-Verified", "SUCCESS")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    async_test_versions! { incorrect_bearer_tokens_are_rejected_even_with_mtls_auth }

    async fn invalid_mtls_auth_is_rejected_despite_correct_bearer_token(version: DapVersion) {
        let test = test_router();

        let code = test(
            Request::builder()
                .uri(format!("/{version}/{}/auth", mk_task_id().to_base64url()))
                .header(CONTENT_TYPE, "application/dap-aggregation-job-init-req")
                .header(http_headers::DAP_AUTH_TOKEN, BEARER_TOKEN)
                .header("X-Client-Cert-Verified", "FAILED")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    async_test_versions! { invalid_mtls_auth_is_rejected_despite_correct_bearer_token }
}
