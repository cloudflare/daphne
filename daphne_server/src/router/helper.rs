// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{body::HttpBody, extract::State, routing::post};
use daphne::{
    constants::DapMediaType,
    error::DapAbort,
    roles::{helper, DapHelper},
};
use daphne_service_utils::auth::DaphneAuth;
use http::StatusCode;

use super::{AxumDapResponse, DapRequestExtractor, DaphneService};

pub(super) fn add_helper_routes<A: DapHelper<DaphneAuth>, B>(
    router: super::Router<A, B>,
) -> super::Router<A, B>
where
    A: DapHelper<DaphneAuth> + DaphneService + Send + Sync + 'static,
    B: Send + HttpBody + 'static,
    B::Data: Send,
    B::Error: Send + Sync,
{
    router
        .route("/:version/aggregate", post(agg_job))
        .route("/:version/aggregate_share", post(agg_share))
        .route(
            "/:version/tasks/:task_id/aggregation_jobs/:agg_job_id",
            post(agg_job).put(agg_job),
        )
        .route("/:version/tasks/:task_id/aggregate_shares", post(agg_share))
}

#[tracing::instrument(
    skip_all,
    fields(
        media_type = ?req.media_type,
        task_id = ?req.task_id().ok(),
        version = ?req.version
    )
)]
async fn agg_job<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor,
) -> AxumDapResponse
where
    A: DapHelper<DaphneAuth> + DaphneService + Send + Sync,
{
    match req.media_type {
        Some(DapMediaType::AggregationJobInitReq) => {
            let resp = helper::handle_agg_job_init_req(&*app, &req).await;
            AxumDapResponse::from_result_with_success_code(
                resp,
                app.server_metrics(),
                match req.version {
                    daphne::DapVersion::Draft02 => StatusCode::OK,
                    daphne::DapVersion::DraftLatest => StatusCode::CREATED,
                },
            )
        }
        Some(DapMediaType::AggregationJobContinueReq) => {
            let resp = helper::handle_agg_job_cont_req(&*app, &req).await;
            AxumDapResponse::from_result(resp, app.server_metrics())
        }
        m => AxumDapResponse::new_error(
            DapAbort::BadRequest(format!("unexpected media type: {m:?}")),
            app.server_metrics(),
        ),
    }
}

#[tracing::instrument(
    skip_all,
    fields(
        media_type = ?req.media_type,
        task_id = ?req.task_id().ok(),
        version = ?req.version
    )
)]
async fn agg_share<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor,
) -> AxumDapResponse
where
    A: DapHelper<DaphneAuth> + DaphneService + Send + Sync,
{
    AxumDapResponse::from_result(
        helper::handle_agg_share_req(&*app, &req).await,
        app.server_metrics(),
    )
}
