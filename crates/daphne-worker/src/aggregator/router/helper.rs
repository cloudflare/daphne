// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    extract::State,
    routing::{post, put},
};
use daphne::{
    messages::AggregateShareReq,
    roles::{
        helper::{self, HashedAggregationJobReq},
        DapHelper,
    },
};
use http::StatusCode;

use super::{
    super::roles::fetch_replay_protection_override, extractor::dap_sender::FROM_LEADER, App,
    AxumDapResponse, DapRequestExtractor, DaphneService,
};
use crate::elapsed;

pub(super) fn add_helper_routes(router: super::Router<App>) -> super::Router<App> {
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
#[worker::send]
async fn agg_job(
    State(app): State<Arc<App>>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_LEADER, HashedAggregationJobReq>,
) -> AxumDapResponse {
    let now = worker::Date::now();

    let resp = helper::handle_agg_job_init_req(
        &*app,
        req,
        fetch_replay_protection_override(app.kv()).await,
    )
    .await;

    let elapsed = elapsed(&now);

    app.server_metrics().aggregate_job_latency(elapsed);

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
