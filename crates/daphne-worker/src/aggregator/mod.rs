// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod config;
mod metrics;
mod roles;
mod router;

use crate::storage::{kv, Do, Kv};
use axum::response::{IntoResponse, Response};
use config::{DaphneServiceConfig, PeerBearerToken};
use daphne::{
    audit_log::{AuditLog, NoopAuditLog},
    constants::DapRole,
    fatal_error,
    messages::TaskId,
    roles::{leader::in_memory_leader::InMemoryLeaderState, DapAggregator as _},
    DapError,
};
use daphne_service_utils::bearer_token::BearerToken;
use either::Either::{self, Left, Right};
use http::StatusCode;
use metrics::DaphneServiceMetrics;
use roles::BearerTokens;
use router::DaphneService;
use std::sync::{Arc, Mutex};
use tower::ServiceExt as _;
use worker::{send::SendWrapper, HttpRequest};

pub async fn handle_request(
    req: HttpRequest,
    env: worker::Env,
    registry: &prometheus::Registry,
    audit_log: Option<Box<dyn AuditLog + Send + Sync>>,
    cpu_offload: Box<dyn CpuOffload + Send + Sync>,
) -> Response {
    let config = match config::load_config_from_env(&env) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = ?e, "fatal error loading config");
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    let registry = match metrics::DaphnePromServiceMetrics::register(registry) {
        Ok(registry) => registry,
        Err(e) => {
            tracing::error!(error = ?e, "fatal error setting up metrics");
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    let Ok(resp) = router::new(
        daphne::constants::DapAggregatorRole::Helper,
        App::new(
            env,
            registry,
            config,
            cpu_offload,
            audit_log.unwrap_or_else(|| Box::new(NoopAuditLog)),
        ),
    )
    .oneshot(req)
    .await;

    resp
}

#[async_trait::async_trait]
pub trait CpuOffload {
    async fn request(&self, req: HttpRequest) -> Response;
}

struct App {
    http: reqwest::Client,
    env: SendWrapper<worker::Env>,
    kv_state: kv::State,
    metrics: Box<dyn DaphneServiceMetrics + Send + Sync>,
    service_config: DaphneServiceConfig,
    audit_log: Box<dyn AuditLog + Send + Sync>,

    cpu_offload: Box<dyn CpuOffload + Send + Sync>,

    /// Volatile memory for the Leader, including the work queue, pending reports, and pending
    /// colleciton requests. Note that in a production Leader, it is necessary to store this state
    /// across requsets.
    test_leader_state: Arc<Mutex<InMemoryLeaderState>>,
}

static_assertions::assert_impl_all!(App: Send, Sync);

#[async_trait::async_trait]
impl DaphneService for App {
    fn server_metrics(&self) -> &dyn DaphneServiceMetrics {
        &*self.metrics
    }

    fn signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
        self.service_config.signing_key.as_ref()
    }

    async fn check_bearer_token(
        &self,
        presented_token: &BearerToken,
        sender: DapRole,
        task_id: TaskId,
        is_taskprov: bool,
    ) -> Result<(), Either<String, DapError>> {
        let reject = |extra_args| {
            Err(Left(format!(
                "the indicated bearer token is incorrect for the {sender:?} {extra_args}",
            )))
        };
        if let Some(taskprov) = self
            .service_config
            .taskprov
            .as_ref()
            // we only use taskprov auth if it's allowed by config and if the request is using taskprov
            .filter(|_| self.service_config.taskprov.is_some() && is_taskprov)
        {
            match (&taskprov.peer_auth, sender) {
                (PeerBearerToken::Leader { expected_token }, DapRole::Leader)
                | (PeerBearerToken::Collector { expected_token }, DapRole::Collector)
                    if expected_token == presented_token =>
                {
                    Ok(())
                }
                (PeerBearerToken::Leader { .. }, DapRole::Collector) => Err(Right(fatal_error!(
                    err = "expected a leader sender but got a collector sender"
                ))),
                (PeerBearerToken::Collector { .. }, DapRole::Leader) => Err(Right(fatal_error!(
                    err = "expected a collector sender but got a leader sender"
                ))),
                _ => reject(format_args!("using taskprov")),
            }
        } else if self
            .bearer_tokens()
            .matches(sender, task_id, presented_token)
            .await
            .map_err(|e| {
                Right(fatal_error!(
                    err = ?e,
                    "internal error occurred while running authentication"
                ))
            })?
        {
            Ok(())
        } else {
            reject(format_args!("with task_id {task_id}"))
        }
    }

    async fn is_using_taskprov(&self, req: &daphne::DapRequestMeta) -> Result<bool, DapError> {
        if req.taskprov_advertisement.is_some() {
            Ok(true)
        } else if self
            .get_task_config_for(&req.task_id)
            .await?
            .is_some_and(|task_config| task_config.method_is_taskprov())
        {
            tracing::warn!("Client referencing a taskprov task id without taskprov advertisement");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl App {
    /// Create a new configured app. See [`App`] for details.
    fn new<M>(
        env: worker::Env,
        daphne_service_metrics: M,
        service_config: DaphneServiceConfig,
        cpu_offload: Box<dyn CpuOffload + Send + Sync>,
        audit_log: Box<dyn AuditLog + Send + Sync>,
    ) -> Self
    where
        M: DaphneServiceMetrics + Send + Sync + 'static,
    {
        Self {
            http: reqwest::Client::new(),
            env: SendWrapper(env),
            kv_state: Default::default(),
            metrics: Box::new(daphne_service_metrics),
            audit_log,
            service_config,
            cpu_offload,
            test_leader_state: Default::default(),
        }
    }

    fn durable(&self) -> Do<'_> {
        Do::new(&self.env)
    }

    fn kv(&self) -> Kv<'_> {
        Kv::new(&self.env, &self.kv_state)
    }

    fn bearer_tokens(&self) -> BearerTokens<'_> {
        BearerTokens::from(Kv::new(&self.env, &self.kv_state))
    }

    fn service_config(&self) -> &DaphneServiceConfig {
        &self.service_config
    }
}
