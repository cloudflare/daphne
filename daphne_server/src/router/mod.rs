// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod aggregator;
mod helper;
mod leader;
#[cfg(feature = "test-utils")]
pub mod test_routes;

use std::{io::Cursor, sync::Arc};

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
    auth::BearerToken,
    constants::DapMediaType,
    error::DapAbort,
    fatal_error,
    messages::{AggregationJobId, CollectionJobId, TaskId},
    DapError, DapRequest, DapResource, DapResponse, DapVersion,
};
use daphne_service_utils::{
    auth::{DaphneAuth, TlsClientAuth},
    metrics::{self, DaphneServiceMetrics},
    DapRole,
};
use http::Request;
use prio::codec::Decode;
use serde::Deserialize;

use crate::App;

type Router<A, B> = axum::Router<Arc<A>, B>;

/// Capabilities necessary when running a native daphne service.
pub trait DaphneService {
    /// The service metrics
    fn server_metrics(&self) -> &dyn DaphneServiceMetrics;

    fn signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
        None
    }
}

impl<S> DaphneService for Arc<S>
where
    S: DaphneService,
{
    fn server_metrics(&self) -> &dyn DaphneServiceMetrics {
        S::server_metrics(&**self)
    }

    fn signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
        S::signing_key(&**self)
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
                fatal_error!(err = "failed to construct content-type",
                    ?response.media_type,
                    ?response.version
                ),
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
struct DapRequestExtractor(pub DapRequest<DaphneAuth>);

#[async_trait]
impl<S, B> FromRequest<S, B> for DapRequestExtractor
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
            #[serde(
                default,
                deserialize_with = "daphne::messages::base64url::deserialize_opt"
            )]
            task_id: Option<TaskId>,
            #[serde(
                default,
                deserialize_with = "daphne::messages::base64url::deserialize_opt"
            )]
            agg_job_id: Option<AggregationJobId>,
            #[serde(
                default,
                deserialize_with = "daphne::messages::base64url::deserialize_opt"
            )]
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

        let extract_header_as_string = |header: &'static str| -> Option<String> {
            parts
                .headers
                .get(header)?
                .to_str()
                .ok()
                .map(ToString::to_string)
        };

        let sender_auth = DaphneAuth {
            bearer_token: extract_header_as_string("DAP-Auth-Token").map(BearerToken::from),
            cf_tls_client_auth: (|| {
                // Whatever service ends up fronting this one and terminating mTLS must pass through
                // these headers.
                Some(TlsClientAuth {
                    verified: extract_header_as_string("X-Client-Cert-Verified")?,
                    issuer: extract_header_as_string("X-Client-Cert-Issuer-Dn-Rfc2253")?,
                    subject: extract_header_as_string("X-Client-Cert-Subject-Dn-Rfc2253")?,
                })
            })(),
        };

        if sender_auth.bearer_token.is_some() {
            state
                .server_metrics()
                .auth_method_inc(metrics::AuthMethod::BearerToken);
        }
        if sender_auth.cf_tls_client_auth.is_some() {
            state
                .server_metrics()
                .auth_method_inc(metrics::AuthMethod::TlsClientAuth);
        }

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

        let taskprov = extract_header_as_string("dap-taskprov");

        // TODO(mendess): this is very eager, we could redesign DapResponse later to allow for
        // streaming of data.
        let payload = hyper::body::to_bytes(body).await;

        let Ok(payload) = payload else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to get payload".into(),
            ));
        };

        let (task_id, resource) = match version {
            DapVersion::Draft02 => {
                let mut r = Cursor::new(payload.as_ref());
                let task_id = task_id.or_else(|| TaskId::decode(&mut r).ok());

                // If the collection job ID was found in the request path, then this must be a
                // request for a collection job result from the Collector.
                let resource =
                    collect_job_id.map_or(DapResource::Undefined, DapResource::CollectionJob);
                (task_id, resource)
            }
            DapVersion::Draft09 | DapVersion::Latest => {
                let resource = match media_type {
                    Some(
                        DapMediaType::AggregationJobInitReq
                        | DapMediaType::AggregationJobContinueReq,
                    ) => {
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
            }
        };

        Ok(DapRequestExtractor(DapRequest {
            version,
            task_id,
            resource,
            payload: payload.to_vec(),
            media_type,
            sender_auth: Some(sender_auth),
            taskprov,
        }))
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, OnceLock};

    use axum::{
        body::{Body, HttpBody},
        extract::State,
        http::{header::CONTENT_TYPE, Request, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use daphne::{
        async_test_version, async_test_versions,
        messages::{AggregationJobId, Base64Encode, TaskId},
        DapRequest, DapResource, DapVersion,
    };
    use daphne_service_utils::{auth::DaphneAuth, metrics::DaphnePromServiceMetrics};
    use futures::future::BoxFuture;
    use rand::{thread_rng, Rng};
    use tokio::sync::mpsc::{self, Sender};
    use tower::ServiceExt;

    use super::DapRequestExtractor;

    /// Return a function that will parse a request using the [`DapRequestExtractor`] and return
    /// the parsed request.
    ///
    /// The possible request URIs that are supported by this parser are:
    ///  - `/:version/parse-version`
    ///  - `/:version/:task_id/parse-task-id`
    ///  - `/:version/:agg_job_id/parse-agg-job-id`
    ///  - `/:version/:collect_job_id/parse-collect-job-id`
    fn test_router<B>() -> impl FnOnce(Request<B>) -> BoxFuture<'static, DapRequest<DaphneAuth>>
    where
        B: Send + Sync + 'static + HttpBody,
        B::Data: Send,
        B::Error: Send + Sync + std::error::Error,
    {
        type Channel = Sender<DapRequest<DaphneAuth>>;

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
        }

        async fn handler(
            State(ch): State<Arc<Channel>>,
            DapRequestExtractor(req): DapRequestExtractor,
        ) -> impl IntoResponse {
            ch.send(req).await.unwrap();
        }

        let (tx, mut rx) = mpsc::channel(1);

        let router = Router::new()
            .route("/:version/parse-version", get(handler))
            .route("/:version/:task_id/parse-task-id", get(handler))
            .route("/:version/:agg_job_id/parse-agg-job-id", get(handler))
            .route(
                "/:version/:collect_job_id/parse-collect-job-id",
                get(handler),
            )
            .with_state(Arc::new(tx));

        move |req| {
            Box::pin(async move {
                let resp = match router.oneshot(req).await {
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
                    code => assert_eq!(code, StatusCode::OK),
                }

                rx.recv().await.unwrap()
            })
        }
    }

    async fn parse_version(version: DapVersion) {
        let test = test_router();

        let req = test(
            Request::builder()
                .uri(format!("/{version}/parse-version"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(req.version, version);
    }

    async_test_versions! { parse_version }

    async fn parse_task_id(version: DapVersion) {
        let test = test_router();

        let task_id = TaskId(thread_rng().gen());

        let req = test(
            Request::builder()
                .uri(format!(
                    "/{version}/{}/parse-task-id",
                    task_id.to_base64url()
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(req.task_id, Some(task_id));
    }

    async_test_versions! { parse_task_id }

    async fn parse_agg_job_id(version: DapVersion) {
        let test = test_router();

        let agg_job_id = AggregationJobId(thread_rng().gen());

        let req = test(
            Request::builder()
                .uri(format!(
                    "/{version}/{}/parse-agg-job-id",
                    agg_job_id.to_base64url()
                ))
                .header(CONTENT_TYPE, "application/dap-aggregation-job-init-req")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(req.resource, DapResource::AggregationJob(agg_job_id));
    }

    async_test_version! { parse_agg_job_id, Draft09 }
    async_test_version! { parse_agg_job_id, Latest }
}
