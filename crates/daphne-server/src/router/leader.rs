// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use daphne::{
    constants::DapMediaType,
    error::DapAbort,
    messages::{self, request::CollectionPollReq},
    roles::leader::{self, DapLeader},
    DapError, DapVersion,
};
use prio_09::codec::ParameterizedEncode;

use super::{
    extractor::dap_sender::FROM_COLLECTOR, AxumDapResponse, DapRequestExtractor, DaphneService,
    UnauthenticatedDapRequestExtractor,
};
use futures::{future::BoxFuture, FutureExt};
use serde::Deserialize;

#[derive(Deserialize)]
struct PathVersion {
    #[serde(rename = "version")]
    presented_version: DapVersion,
}

fn require_version(
    expected_version: DapVersion,
) -> impl Copy + Fn(Path<PathVersion>, Request, Next) -> BoxFuture<'static, Response> {
    move |Path(PathVersion { presented_version }), req, next| {
        async move {
            if presented_version != expected_version {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            next.run(req).await
        }
        .boxed()
    }
}

pub(super) fn add_leader_routes<A>(router: super::Router<A>) -> super::Router<A>
where
    A: DapLeader + DaphneService + Send + Sync + 'static,
{
    router
        .route(
            "/:version/tasks/:task_id/reports",
            put(upload).layer(from_fn(require_version(DapVersion::Draft09))),
        )
        .route(
            "/:version/tasks/:task_id/reports",
            post(upload).layer(from_fn(require_version(DapVersion::Latest))),
        )
        .route(
            "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
            put(start_collection_job),
        )
        .route(
            "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
            post(poll_collect).layer(from_fn(require_version(DapVersion::Draft09))),
        )
        .route(
            "/:version/tasks/:task_id/collection_jobs/:collect_job_id",
            get(poll_collect).layer(from_fn(require_version(DapVersion::Latest))),
        )
}

#[tracing::instrument(
    skip_all,
    fields(
        task_id = ?req.task_id,
        version = ?req.version,
    )
)]
async fn upload<A>(
    State(app): State<Arc<A>>,
    UnauthenticatedDapRequestExtractor(req): UnauthenticatedDapRequestExtractor<messages::Report>,
) -> Response
where
    A: DapLeader + DaphneService + Send + Sync,
{
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
    DapRequestExtractor(req): DapRequestExtractor<FROM_COLLECTOR, messages::CollectionReq>,
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
async fn poll_collect<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_COLLECTOR, CollectionPollReq>,
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
