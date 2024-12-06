// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(unused_variables)]

use axum::{
    extract::State,
    response::Response,
    routing::{post, put},
};
use daphne::{
    constants::DapRole,
    messages::{AggregationJobInitReq, TaskId},
    roles::{
        aggregator::{TaskConfigurator, TaskprovConfig},
        helper,
    },
    taskprov, DapError, DapRequestMeta, DapTaskConfig,
};
use daphne_server::{
    metrics::DaphneServiceMetrics,
    router::{
        extractor::{dap_sender::FROM_LEADER, DapRequestExtractor},
        DaphneService,
    },
};
use daphne_service_utils::bearer_token::BearerToken;
use either::Either;
use http::Method;
use prometheus::Registry;
use std::sync::Arc;
use tower_service::Service;
use worker::HttpRequest;

#[derive(Clone)]
struct Helper {
    compute_offload: Arc<dyn CPUOffload>,
}

const _: () = {
    const fn is_send<T: Send + Sync>() {}
    is_send::<Helper>();
};

#[async_trait::async_trait]
impl TaskConfigurator for Helper {
    fn get_taskprov_config(&self) -> Option<TaskprovConfig<'_>> {
        todo!()
    }

    async fn taskprov_opt_in(
        &self,
        task_id: &TaskId,
        task_config: taskprov::DapTaskConfigNeedsOptIn,
    ) -> Result<DapTaskConfig, DapError> {
        todo!()
    }

    async fn taskprov_put(
        &self,
        task_id: &TaskId,
        task_config: DapTaskConfig,
    ) -> Result<(), DapError> {
        todo!()
    }

    async fn get_task_config_for<'req>(
        &'req self,
        task_id: &'req TaskId,
    ) -> Result<Option<DapTaskConfig>, DapError> {
        todo!()
    }
}

#[async_trait::async_trait]
impl DaphneService for Helper {
    fn signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
        None
    }

    fn server_metrics(&self) -> &dyn DaphneServiceMetrics {
        todo!()
    }

    async fn check_bearer_token(
        &self,
        presented_token: &BearerToken,
        sender: DapRole,
        task_id: TaskId,
        is_taskprov: bool,
    ) -> Result<(), Either<String, DapError>> {
        todo!()
    }

    async fn is_using_taskprov(&self, req: &DapRequestMeta) -> Result<bool, DapError> {
        todo!()
    }
}

#[async_trait::async_trait]
pub trait CPUOffload {
    async fn request(&self, req: HttpRequest) -> Response;
}

pub async fn handle_request(
    req: HttpRequest,
    registry: &Registry,
    compute_offload: Arc<dyn CPUOffload>,
) -> Response {
    let mut router = axum::Router::new()
        .route(
            "/:version/tasks/:task_id/aggregation_jobs/:agg_job_id",
            put(agg_job),
        )
        .route("/:version/tasks/:task_id/aggregate_shares", post(agg_share))
        .with_state::<()>(Helper { compute_offload });

    let Ok(resp) = router.call(req).await;
    resp
}

#[worker::send]
async fn agg_job(
    State(helper): State<Helper>,
    DapRequestExtractor(req): DapRequestExtractor<FROM_LEADER, AggregationJobInitReq>,
) {
    let state_machine = helper::handle_agg_job::start(req)
        .resolve_task_config(&helper)
        .await
        .unwrap(); // TODO

    let response = helper
        .compute_offload
        .request(
            http::Request::builder()
                .method(Method::POST)
                .uri("/cpu_offload/initialize_reports")
                .body(worker::Body::empty())
                .unwrap(),
        )
        .await;

    let initialized_reports = unsafe { std::mem::transmute_copy(&response.into_body()) };

    let (agg_span, agg_job_resp) = state_machine
        .with_initialized_reports(initialized_reports)
        .produce_agg_job_response(None)
        .unwrap(); // TODO
}

async fn agg_share() {}
