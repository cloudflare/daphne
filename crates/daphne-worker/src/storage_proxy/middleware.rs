// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::{Arc, OnceLock};

use axum::{
    extract::{Path, State},
    middleware::Next,
    response::IntoResponse,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use daphne::messages::constant_time_eq;
use http::{Method, StatusCode};
use tower_service::Service;

use super::RequestContext;
use crate::elapsed;

/// Performs bearer token auth of a request.
pub async fn bearer_auth(
    ctx: State<Arc<RequestContext>>,
    bearer: TypedHeader<Authorization<Bearer>>,
    request: axum::extract::Request,
    mut next: Next,
) -> axum::response::Response {
    static TRUSTED_TOKEN: OnceLock<Option<String>> = OnceLock::new();

    let Some(trusted_token) = TRUSTED_TOKEN.get_or_init(|| {
        ctx.env
            .var("DAPHNE_SERVER_AUTH_TOKEN")
            .ok()
            .map(|t| t.to_string())
    }) else {
        tracing::warn!("trusted bearer token not configured");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Authorization token for storage proxy is not configured",
        )
            .into_response();
    };

    if !constant_time_eq(bearer.token().as_bytes(), trusted_token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "Incorrect authorization token").into_response();
    }

    match next.call(request.map(axum::body::Body::new)).await {
        Ok(r) => r,
        Err(infalible) => match infalible {},
    }
}

#[worker::send]
pub async fn time_kv_requests(
    ctx: State<Arc<RequestContext>>,
    method: Method,
    request: axum::extract::Request,
    mut next: Next,
) -> axum::response::Response {
    let start = worker::Date::now();
    let response = match next.call(request).await {
        Ok(r) => r,
        Err(infalible) => match infalible {},
    };
    let elapsed = elapsed(&start);

    let op = match method {
        Method::GET => "kv_get",
        Method::POST => "kv_put",
        Method::PUT => "kv_put_if_not_exists",
        Method::DELETE => "kv_delete",
        method => {
            tracing::warn!(?method, status = ?response.status(), "unexpected method in kv request");
            "unknown"
        }
    };
    let status = if response.status().is_success() {
        "success"
    } else {
        "error"
    };
    ctx.metrics
        .kv_request_time_seconds_observe(op, status, elapsed);

    response
}

#[worker::send]
pub async fn time_do_requests(
    ctx: State<Arc<RequestContext>>,
    Path(uri): Path<String>,
    request: axum::extract::Request,
    mut next: Next,
) -> axum::response::Response {
    let start = worker::Date::now();
    let response = match next.call(request).await {
        Ok(r) => r,
        Err(infalible) => match infalible {},
    };
    let elapsed = elapsed(&start);
    ctx.metrics.durable_request_time_seconds_observe(
        &uri,
        if response.status().is_success() {
            "success"
        } else {
            "error"
        },
        elapsed,
    );
    response
}
