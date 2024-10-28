// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    body::HttpBody,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{post, put},
};
use daphne::{
    constants::DapMediaType,
    error::DapAbort,
    messages::{self, request::resource},
    roles::leader::{self, DapLeader},
    DapError, DapVersion,
};
use prio::codec::ParameterizedEncode;

use super::{
    extractor::dap_sender::FROM_COLLECTOR, AxumDapResponse, DapRequestExtractor, DaphneService,
    UnauthenticatedDapRequestExtractor,
};

pub(super) fn add_leader_routes<A, B>(router: super::Router<A, B>) -> super::Router<A, B>
where
    A: DapLeader + DaphneService + Send + Sync + 'static,
    B: Send + HttpBody + 'static,
    B::Data: Send,
    B::Error: Send + Sync,
{
    router
        .route("/:version/tasks/:task_id/reports", put(upload_draft09))
        .route("/:version/tasks/:task_id/reports", post(upload_draft13))
        .route(
            "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
            put(start_collection_job).post(collect),
        )
}

#[tracing::instrument(
    skip_all,
    fields(
        task_id = ?req.task_id,
        version = ?req.version,
    )
)]
async fn upload_draft13<A>(
    State(app): State<Arc<A>>,
    UnauthenticatedDapRequestExtractor(req): UnauthenticatedDapRequestExtractor<
        messages::Report,
        resource::None,
    >,
) -> Response
where
    A: DapLeader + DaphneService + Send + Sync,
{
    if req.version == DapVersion::Draft09 {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            format!("route not implemented for version {}", req.version),
        )
            .into_response();
    }
    match leader::handle_upload_req(&*app, req).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}

async fn upload_draft09<A>(
    State(app): State<Arc<A>>,
    UnauthenticatedDapRequestExtractor(req): UnauthenticatedDapRequestExtractor<
        messages::Report,
        resource::None,
    >,
) -> Response
where
    A: DapLeader + DaphneService + Send + Sync,
{
    if req.version != DapVersion::Draft09 {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            format!("route not implemented for version {}", req.version),
        )
            .into_response();
    }
    match leader::handle_upload_req(&*app, req).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}
#[tracing::instrument(
    skip_all,
    fields(
        task_id = ?req.task_id,
        version = ?req.version,
    )
)]
async fn start_collection_job<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor<
        FROM_COLLECTOR,
        messages::CollectionReq,
        resource::CollectionJobId,
    >,
) -> Response
where
    A: DapLeader + DaphneService + Send + Sync,
{
    match leader::handle_coll_job_req(&*app, &req).await {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}

#[tracing::instrument(
    skip_all,
    fields(
        task_id = ?req.task_id,
        version = ?req.version,
    )
)]
async fn collect<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_COLLECTOR, (), resource::CollectionJobId>,
) -> Response
where
    A: DapLeader + DaphneService + Send + Sync,
{
    match app.poll_collect_job(&req.task_id, &req.resource_id).await {
        Ok(daphne::DapCollectionJob::Done(collect_resp)) => AxumDapResponse::new_success(
            daphne::DapResponse {
                version: req.version,
                media_type: DapMediaType::Collection,
                payload: match collect_resp.get_encoded_with_param(&req.version) {
                    Ok(payload) => payload,
                    Err(e) => {
                        return AxumDapResponse::new_error(
                            DapError::encoding(e),
                            app.server_metrics(),
                        )
                        .into_response()
                    }
                },
            },
            app.server_metrics(),
        )
        .into_response(),
        Ok(daphne::DapCollectionJob::Pending) => StatusCode::ACCEPTED.into_response(),
        Ok(daphne::DapCollectionJob::Unknown) => AxumDapResponse::new_error(
            DapAbort::BadRequest("unknown collection job id".into()),
            app.server_metrics(),
        )
        .into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}
