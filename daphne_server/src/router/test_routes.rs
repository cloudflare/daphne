// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
};
use daphne::{
    hpke::HpkeReceiverConfig,
    messages::TaskId,
    roles::{leader, DapLeader},
    DapVersion,
};
use daphne_service_utils::{
    auth::DaphneAuth,
    test_route_types::{InternalTestAddTask, InternalTestEndpointForTask},
    DapRole,
};
use serde::Deserialize;

use crate::App;

use super::{AxumDapResponse, DaphneService};

pub fn add_test_routes(router: super::Router<App>, role: DapRole) -> super::Router<App> {
    let router = if role == DapRole::Leader {
        router
            .route("/internal/process", post(handle_leader_process))
            .route(
                "/internal/current_batch/task/:task_id",
                get(handle_leader_current_batch),
            )
    } else {
        router
    };

    router
        .route("/internal/delete_all", post(handle_delete_all))
        .route("/internal/test/ready", post(StatusCode::OK))
        .route(
            "/internal/test/endpoint_for_task",
            post(handle_endpoint_for_task_default),
        )
        .route(
            "/:version/internal/test/endpoint_for_task",
            post(handle_endpoint_for_task),
        )
        // TODO: could be removed after we add the divviup api
        .route("/internal/test/add_task", post(handle_add_task))
        .route("/:version/internal/test/add_task", post(handle_add_task))
        .route(
            "/:version/internal/test/add_hpke_config",
            post(handle_add_hpke_config),
        )
}

async fn handle_leader_process(
    State(app): State<Arc<App>>,
    Json(report_sel): Json<<App as DapLeader<DaphneAuth>>::ReportSelector>,
) -> Response {
    match leader::process(&*app, &report_sel, "unspecified-daphne-worker-host").await {
        Ok(telem) => (StatusCode::OK, Json(telem)).into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}

#[derive(Deserialize)]
struct PathTaskId {
    #[serde(deserialize_with = "daphne::messages::base64url::deserialize")]
    task_id: TaskId,
}

async fn handle_leader_current_batch(
    State(_app): State<Arc<App>>,
    #[allow(unused_variables)] Path(PathTaskId { task_id }): Path<PathTaskId>,
) -> impl IntoResponse {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn handle_delete_all(State(_app): State<Arc<App>>) -> impl IntoResponse {}

async fn handle_endpoint_for_task_default(
    state: State<Arc<App>>,
    cmd: Json<InternalTestEndpointForTask>,
) -> impl IntoResponse {
    handle_endpoint_for_task(state, Path(DapVersion::DraftLatest), cmd).await
}

async fn handle_endpoint_for_task(
    State(_app): State<Arc<App>>,
    Path(_version): Path<DapVersion>,
    Json(_cmd): Json<InternalTestEndpointForTask>,
) -> impl IntoResponse {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn handle_add_task(
    State(_app): State<Arc<App>>,
    Json(_cmd): Json<InternalTestAddTask>,
) -> impl IntoResponse {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn handle_add_hpke_config(
    State(_app): State<Arc<App>>,
    Json(_cmd): Json<HpkeReceiverConfig>,
) -> impl IntoResponse {
    StatusCode::INTERNAL_SERVER_ERROR
}
