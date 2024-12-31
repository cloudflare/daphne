// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod config;
mod metrics;
pub mod queues;
mod roles;
mod router;

use crate::storage::{kv, Do, Kv};
use axum::response::Response;
use config::{DaphneServiceConfig, PeerBearerToken};
use daphne::{
    audit_log::{AuditLog, NoopAuditLog},
    constants::DapRole,
    fatal_error,
    messages::TaskId,
    roles::{leader::in_memory_leader::InMemoryLeaderState, DapAggregator as _},
    DapError,
};
use daphne_service_utils::{
    bearer_token::BearerToken,
    capnproto::{
        CapnprotoPayloadDecode, CapnprotoPayloadDecodeExt, CapnprotoPayloadEncode,
        CapnprotoPayloadEncodeExt,
    },
};
use either::Either::{self, Left, Right};
use metrics::DaphneServiceMetrics;
use roles::BearerTokens;
use router::DaphneService;
use std::sync::{Arc, LazyLock, Mutex};
use worker::send::SendWrapper;

use queues::Queue;
pub use router::handle_dap_request;

#[async_trait::async_trait(?Send)]
pub trait ComputeOffload {
    async fn request(&self, path: &str, body: &[u8]) -> worker::Result<Response<worker::Body>>;
}

impl dyn ComputeOffload + Send + Sync {
    pub async fn compute<I, O>(&self, path: &str, body: &I) -> worker::Result<O>
    where
        I: CapnprotoPayloadEncode,
        O: CapnprotoPayloadDecode,
    {
        let resp = self.request(path, &body.encode_to_bytes()).await?;

        if resp.status().is_success() {
            O::decode_from_bytes(
                &http_body_util::BodyExt::collect(resp.into_body())
                    .await?
                    .to_bytes(),
            )
            .map_err(|e| {
                worker::Error::RustError(format!("failed to decode body from cpu offload: {e:?}"))
            })
        } else {
            Err(worker::Error::RustError(format!(
                "request to cpu offload failed with code: {}",
                resp.status()
            )))
        }
    }
}

pub struct App {
    http: reqwest::Client,
    env: SendWrapper<worker::Env>,
    kv_state: kv::State,
    metrics: Box<dyn DaphneServiceMetrics + Send + Sync>,
    service_config: DaphneServiceConfig,
    audit_log: Box<dyn AuditLog + Send + Sync>,

    compute_offload: Box<dyn ComputeOffload + Send + Sync>,

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
    pub fn new(
        env: worker::Env,
        registry: &prometheus::Registry,
        audit_log: impl Into<Option<Box<dyn AuditLog + Send + Sync>>>,
        compute_offload: Box<dyn ComputeOffload + Send + Sync>,
    ) -> Result<Self, DapError> {
        static PERSISTENT_ENOUGH_STATE: LazyLock<Arc<Mutex<InMemoryLeaderState>>> =
            LazyLock::new(Default::default);
        let metrics = metrics::DaphnePromServiceMetrics::register(registry)?;
        let service_config = config::load_config_from_env(&env)?;
        Ok(Self {
            http: reqwest::Client::new(),
            env: SendWrapper(env),
            kv_state: Default::default(),
            metrics: Box::new(metrics),
            audit_log: audit_log.into().unwrap_or_else(|| Box::new(NoopAuditLog)),
            service_config,
            test_leader_state: PERSISTENT_ENOUGH_STATE.clone(),
            compute_offload,
        })
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

    fn async_aggregation_queue(&self) -> Queue<queues::AsyncAggregationMessage> {
        Queue::from(
            self.env
                .get_binding::<worker::Queue>("ASYNC_AGGREGATION_QUEUE")
                .unwrap(),
        )
    }
}
