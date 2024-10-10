// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    body::HttpBody,
    extract::State,
    routing::{post, put},
};
use daphne::{
    messages::{AggregateShareReq, AggregationJobInitReq},
    roles::{helper, DapHelper},
};
use http::StatusCode;

use crate::{roles::fetch_replay_protection_override, App};

use super::{
    extractor::dap_sender::FROM_LEADER, AxumDapResponse, DapRequestExtractor, DaphneService,
};

pub(super) fn add_helper_routes<B>(router: super::Router<App, B>) -> super::Router<App, B>
where
    B: Send + HttpBody + 'static,
    B::Data: Send,
    B::Error: Send + Sync,
{
    router
        .route(
            "/:version/tasks/:task_id/aggregation_jobs/:agg_job_id",
            put(agg_job),
        )
        .route("/:version/tasks/:task_id/aggregate_shares", post(agg_share))
}

#[tracing::instrument(
    skip_all,
    fields(
        media_type = ?req.media_type,
        task_id = ?req.task_id,
        version = ?req.version,
    )
)]
async fn agg_job(
    State(app): State<Arc<App>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_LEADER, AggregationJobInitReq>,
) -> AxumDapResponse {
    let resp = helper::handle_agg_job_init_req(
        &*app,
        req,
        fetch_replay_protection_override(app.kv()).await,
    )
    .await;
    AxumDapResponse::from_result_with_success_code(resp, app.server_metrics(), StatusCode::CREATED)
}

#[tracing::instrument(
    skip_all,
    fields(
        media_type = ?req.media_type,
        task_id = ?req.task_id,
        version = ?req.version,
    )
)]
async fn agg_share<A>(
    State(app): State<Arc<A>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_LEADER, AggregateShareReq>,
) -> AxumDapResponse
where
    A: DapHelper + DaphneService + Send + Sync,
{
    AxumDapResponse::from_result(
        helper::handle_agg_share_req(&*app, req).await,
        app.server_metrics(),
    )
}
