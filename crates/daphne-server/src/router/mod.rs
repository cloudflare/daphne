// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod aggregator;
mod extractor;
mod helper;
mod leader;
#[cfg(feature = "test-utils")]
pub mod test_routes;

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header::CONTENT_TYPE, HeaderValue, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use daphne::{
    error::DapAbort, fatal_error, messages::TaskId, DapError, DapRequestMeta, DapResponse,
    DapSender,
};
use daphne_service_utils::{bearer_token::BearerToken, DapRole};
use either::Either;

use crate::{metrics::DaphneServiceMetrics, App};
use extractor::{DapRequestExtractor, UnauthenticatedDapRequestExtractor};

type Router<A> = axum::Router<Arc<A>>;

/// Capabilities necessary when running a native daphne service.
#[axum::async_trait]
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
    async fn is_using_taskprov(&self, req: &DapRequestMeta) -> Result<bool, DapError>;
}

#[axum::async_trait]
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

    async fn is_using_taskprov(&self, req: &DapRequestMeta) -> Result<bool, DapError> {
        S::is_using_taskprov(&**self, req).await
    }
}

pub fn new(role: DapRole, aggregator: App) -> axum::Router<()> {
    let router = axum::Router::new();

    let router = aggregator::add_aggregator_routes(router);

    let router = match role {
        DapRole::Leader => leader::add_leader_routes(router),
        DapRole::Helper => helper::add_helper_routes(router),
    };

    #[cfg(feature = "test-utils")]
    let router = test_routes::add_test_routes(router, role);

    async fn request_metrics(
        State(app): State<Arc<App>>,
        req: Request,
        next: Next,
    ) -> impl IntoResponse {
        tracing::info!(method = %req.method(), uri = %req.uri(), "received request");
        let resp = next.run(req).await;
        app.server_metrics()
            .count_http_status_code(resp.status().as_u16());
        tracing::info!(status_code = %resp.status(), "request finished");
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
        let (status, problem_details) = match error {
            Ok(abort) => {
                tracing::error!(error = ?abort, "request aborted due to protocol abort");
                let status = if let DapAbort::UnauthorizedRequest { .. } = abort {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::BAD_REQUEST
                };
                (status, abort.into_problem_details())
            }
            Err(fatal_error) => {
                tracing::error!(error = ?fatal_error, "request aborted due to fatal error");
                // TODO(mendess) uncomment the line below
                // self.error_reporter.report_abort(&e);
                let problem_details = fatal_error.into_problem_details();
                (StatusCode::INTERNAL_SERVER_ERROR, problem_details)
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
