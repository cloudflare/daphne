// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use axum::{
    body::HttpBody,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
};
use daphne::{
    hpke::HpkeReceiverConfig,
    messages::{Base64Encode, TaskId},
    roles::{leader, DapLeader},
    DapVersion,
};
use daphne_service_utils::{
    test_route_types::{InternalTestAddTask, InternalTestEndpointForTask},
    DapRole,
};
use serde::Deserialize;

use crate::App;

use super::{AxumDapResponse, DaphneService};

pub fn add_test_routes<B>(router: super::Router<App, B>, role: DapRole) -> super::Router<App, B>
where
    B: Send + HttpBody + 'static,
    B::Data: Send,
    B::Error: Send + Sync + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let router = if role == DapRole::Leader {
        router
            .route("/internal/process", post(leader_process))
            .route(
                "/internal/current_batch/task/:task_id",
                get(leader_current_batch),
            )
    } else {
        router
    };

    router
        .route("/internal/delete_all", post(delete_all))
        .route("/internal/test/ready", post(check_storage_readyness))
        .route(
            "/internal/test/endpoint_for_task",
            post(endpoint_for_task_default),
        )
        .route(
            "/:version/internal/test/endpoint_for_task",
            post(endpoint_for_task),
        )
        .route("/internal/test/add_task", post(add_task_default))
        .route("/:version/internal/test/add_task", post(add_task))
        .route(
            "/internal/test/add_hpke_config",
            post(add_hpke_config_default),
        )
        .route(
            "/:version/internal/test/add_hpke_config",
            post(add_hpke_config),
        )
}

#[tracing::instrument(skip(app))]
async fn check_storage_readyness(State(app): State<Arc<App>>) -> Response {
    match app.storage_ready_check().await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => AxumDapResponse::new_error(e, &*app.metrics).into_response(),
    }
}

#[tracing::instrument(skip(app))]
async fn leader_process(State(app): State<Arc<App>>) -> Response {
    match leader::process(&*app, "unspecified-daphne-worker-host", 100).await {
        Ok(telem) => (StatusCode::OK, Json(telem)).into_response(),
        Err(e) => AxumDapResponse::new_error(e, app.server_metrics()).into_response(),
    }
}

#[derive(Deserialize)]
struct PathTaskId {
    task_id: TaskId,
}

#[tracing::instrument(skip(app))]
async fn leader_current_batch(
    State(app): State<Arc<App>>,
    Path(PathTaskId { task_id }): Path<PathTaskId>,
) -> impl IntoResponse {
    match app.current_batch(&task_id).await {
        Ok(batch_id) => (StatusCode::OK, batch_id.to_base64url().into_bytes()).into_response(),
        Err(e) => AxumDapResponse::new_error(e, &*app.metrics).into_response(),
    }
}

#[tracing::instrument(skip(app))]
async fn delete_all(State(app): State<Arc<App>>) -> impl IntoResponse {
    match app.internal_delete_all().await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => AxumDapResponse::new_error(e, &*app.metrics).into_response(),
    }
}

async fn endpoint_for_task_default(
    state: State<Arc<App>>,
    cmd: Json<InternalTestEndpointForTask>,
) -> impl IntoResponse {
    let version = state.0.service_config.default_version;
    endpoint_for_task(state, Path(version), cmd).await
}

#[tracing::instrument(skip(app, cmd))]
async fn endpoint_for_task(
    State(app): State<Arc<App>>,
    Path(version): Path<DapVersion>,
    Json(cmd): Json<InternalTestEndpointForTask>,
) -> impl IntoResponse {
    match app.internal_endpoint_for_task(version, cmd) {
        Ok(path) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success", "endpoint": path })),
        )
            .into_response(),
        Err(e) => AxumDapResponse::new_error(e, &*app.metrics).into_response(),
    }
}

#[tracing::instrument(skip(app, cmd))]
async fn add_task(
    State(app): State<Arc<App>>,
    Path(version): Path<DapVersion>,
    Json(cmd): Json<InternalTestAddTask>,
) -> impl IntoResponse {
    match app.internal_add_task(version, cmd).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success" })),
        )
            .into_response(),
        Err(e) => AxumDapResponse::new_error(e, &*app.metrics).into_response(),
    }
}

#[tracing::instrument(skip(app, json))]
async fn add_task_default(
    State(app): State<Arc<App>>,
    json: Json<InternalTestAddTask>,
) -> impl IntoResponse {
    let version = app.service_config.default_version;
    add_task(State(app), Path(version), json).await
}

#[tracing::instrument(skip(app, hpke))]
async fn add_hpke_config(
    State(app): State<Arc<App>>,
    Path(version): Path<DapVersion>,
    Json(hpke): Json<HpkeReceiverConfig>,
) -> impl IntoResponse {
    match app.internal_add_hpke_config(version, hpke).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success" })),
        )
            .into_response(),
        Err(e) => AxumDapResponse::new_error(e, &*app.metrics).into_response(),
    }
}

#[tracing::instrument(skip(app, json))]
async fn add_hpke_config_default(
    State(app): State<Arc<App>>,
    json: Json<HpkeReceiverConfig>,
) -> impl IntoResponse {
    let version = app.service_config.default_version;
    add_hpke_config(State(app), Path(version), json).await
}
