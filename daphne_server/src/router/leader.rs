// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{AppendHeaders, IntoResponse, Response},
    routing::{get, post, put},
};
use daphne::{
    constants::DapMediaType,
    error::DapAbort,
    roles::leader::{self, DapLeader},
    DapVersion,
};
use daphne_service_utils::auth::DaphneAuth;
use prio::codec::ParameterizedEncode;
use serde::Deserialize;

use super::{AxumDapResponse, DapRequestExtractor, DaphneService};

#[derive(Deserialize, Debug)]
struct PathVersion {
    version: DapVersion,
}

async fn require_draft02(
    Path(PathVersion { version }): Path<PathVersion>,
    request: Request,
    next: Next,
) -> Response {
    if version != DapVersion::Draft02 {
        return (
            StatusCode::NOT_FOUND,
            format!("route not implemented for version {version}"),
        )
            .into_response();
    }
    next.run(request).await
}

pub(super) fn add_leader_routes<A>(router: super::Router<A>) -> super::Router<A>
where
    A: DapLeader<DaphneAuth> + DaphneService + Send + Sync + 'static,
{
    router
        .route("/:version/upload", post(handle_upload_req))
        .route("/:version/collect", post(handle_get_collect_uri))
        .route(
            "/:version/collect/task/:task_id/req/:collect_job_id",
            get(handle_collect_req),
        )
        .layer(middleware::from_fn(require_draft02)) // applies to routes above this layer
        .route("/:version/tasks/:task_id/reports", put(handle_upload_req))
        .route(
            "/:version/tasks/:task_id/collections_jobs/:collect_job_id",
            post(handle_get_collect_uri).put(handle_collect_req),
        )
}

async fn handle_upload_req<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor,
) -> Response
where
    A: DapLeader<DaphneAuth> + DaphneService + Send + Sync,
{
    match leader::handle_upload_req(&*app, &req).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}

async fn handle_get_collect_uri<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor,
) -> Response
where
    A: DapLeader<DaphneAuth> + DaphneService + Send + Sync,
{
    match leader::handle_collect_job_req(&*app, &req).await {
        Ok(uri) => (
            StatusCode::SEE_OTHER,
            AppendHeaders([(header::LOCATION, uri.as_str())]),
        )
            .into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}

async fn handle_collect_req<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor,
) -> Response
where
    A: DapLeader<DaphneAuth> + DaphneService + Send + Sync,
{
    if req.version != DapVersion::Draft02 {
        return StatusCode::NOT_FOUND.into_response();
    }
    let task_id = match req.task_id() {
        Ok(id) => id,
        Err(e) => return AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    };
    let collect_id = match req.collection_job_id() {
        Ok(id) => id,
        Err(e) => return AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    };
    match app.poll_collect_job(task_id, collect_id).await {
        Ok(daphne::DapCollectJob::Done(collect_resp)) => AxumDapResponse::new_success(
            daphne::DapResponse {
                version: req.version,
                media_type: DapMediaType::Collection,
                payload: collect_resp.get_encoded_with_param(&req.version),
            },
            app.server_metrics(),
        )
        .into_response(),
        Ok(daphne::DapCollectJob::Pending) => StatusCode::ACCEPTED.into_response(),
        Ok(daphne::DapCollectJob::Unknown) => AxumDapResponse::new_error(
            DapAbort::BadRequest("unknown collection job id".into()),
            app.server_metrics(),
        )
        .into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}
