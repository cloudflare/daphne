// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    body::HttpBody,
    extract::{Path, State},
    http::{header, Request, StatusCode},
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

async fn require_draft02<B>(
    Path(PathVersion { version }): Path<PathVersion>,
    request: Request<B>,
    next: Next<B>,
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

pub(super) fn add_leader_routes<A, B>(router: super::Router<A, B>) -> super::Router<A, B>
where
    A: DapLeader<DaphneAuth> + DaphneService + Send + Sync + 'static,
    B: Send + HttpBody + 'static,
    B::Data: Send,
    B::Error: Send + Sync,
{
    router
        .route(
            "/:version/upload",
            post(upload).layer(middleware::from_fn(require_draft02)),
        )
        .route(
            "/:version/collect",
            post(get_collect_uri).layer(middleware::from_fn(require_draft02)),
        )
        .route(
            "/:version/collect/task/:task_id/req/:collect_job_id",
            get(collect).layer(middleware::from_fn(require_draft02)),
        )
        .route("/:version/tasks/:task_id/reports", put(upload))
        .route(
            "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
            put(get_collect_uri).post(collect),
        )
}

#[tracing::instrument(
    skip_all,
    fields(
        task_id = ?req.task_id().ok(),
        version = ?req.version
    )
)]
async fn upload<A>(
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

#[tracing::instrument(
    skip_all,
    fields(
        task_id = ?req.task_id().ok(),
        version = ?req.version
    )
)]
async fn get_collect_uri<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor,
) -> Response
where
    A: DapLeader<DaphneAuth> + DaphneService + Send + Sync,
{
    match (
        leader::handle_collect_job_req(&*app, &req).await,
        req.version,
    ) {
        (Ok(uri), DapVersion::Draft02) => (
            StatusCode::SEE_OTHER,
            AppendHeaders([(header::LOCATION, uri.as_str())]),
        )
            .into_response(),
        (Ok(_), DapVersion::DraftLatest) => StatusCode::CREATED.into_response(),
        (Err(e), _) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}

#[tracing::instrument(
    skip_all,
    fields(
        task_id = ?req.task_id().ok(),
        version = ?req.version
    )
)]
async fn collect<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor,
) -> Response
where
    A: DapLeader<DaphneAuth> + DaphneService + Send + Sync,
{
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
