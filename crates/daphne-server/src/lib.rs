// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use config::{DaphneServiceConfig, PeerBearerToken};
use daphne::{
    audit_log::{AuditLog, NoopAuditLog},
    constants::DapRole,
    fatal_error,
    messages::{Base64Encode, TaskId},
    roles::{leader::in_memory_leader::InMemoryLeaderState, DapAggregator},
    DapError,
};
use daphne_service_utils::bearer_token::BearerToken;
use either::Either::{self, Left, Right};
use futures::lock::Mutex;
use metrics::DaphneServiceMetrics;
use roles::BearerTokens;
use serde::{Deserialize, Serialize};
use storage_proxy_connection::{kv, Do, Kv};
use url::Url;

pub mod config;
pub mod metrics;
mod roles;
pub mod router;
mod storage_proxy_connection;

/// Entrypoint to the server implementation. This struct implements
/// [`DapLeader`](daphne::roles::DapLeader) and [`DapHelper`](daphne::roles::DapHelper) and can be
/// passed to the router.
///
/// It depends on a cloudflare worker to do it's storage using durable objects.
///
/// It can be constructed from:
/// - a `url` that points to a cloudflare worker which serves as proxy for the storage
///   implementation.
/// - an implementation of [`DaphneServiceMetrics`].
/// - a [`DaphneServiceConfig`].
///
/// # Examples
/// ```
/// use std::num::NonZeroUsize;
/// use url::Url;
/// use daphne::{DapGlobalConfig, constants::DapAggregatorRole, hpke::HpkeKemId, DapVersion};
/// use daphne_server::{
///     App,
///     router,
///     StorageProxyConfig,
///     metrics::DaphnePromServiceMetrics,
///     config::DaphneServiceConfig,
/// };
///
/// let storage_proxy_settings = StorageProxyConfig {
///     url: Url::parse("http://example.com").unwrap(),
///     auth_token: "some-token".into(),
/// };
/// let registry = prometheus::Registry::new();
/// let daphne_service_metrics = DaphnePromServiceMetrics::register(&registry).unwrap();
/// let global = DapGlobalConfig {
///     max_batch_duration: 360_00,
///     min_batch_interval_start: 259_200,
///     max_batch_interval_end: 259_200,
///     supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
///     default_num_agg_span_shards: NonZeroUsize::new(2).unwrap(),
/// };
/// let service_config = DaphneServiceConfig {
///     role: DapAggregatorRole::Helper,
///     global,
///     base_url: None,
///     taskprov: None,
///     default_version: DapVersion::Draft09,
///     report_storage_epoch_duration: 300,
///     report_storage_max_future_time_skew: 300,
///     signing_key: None,
/// };
/// let app = App::new(storage_proxy_settings, daphne_service_metrics, service_config)?;
///
/// let router = router::new(DapAggregatorRole::Helper, app);
///
/// # Ok::<(), daphne::DapError>(())
/// ```
pub struct App {
    storage_proxy_config: StorageProxyConfig,
    http: reqwest::Client,
    kv_state: kv::State,
    metrics: Box<dyn DaphneServiceMetrics>,
    service_config: DaphneServiceConfig,
    audit_log: Box<dyn AuditLog + Send + Sync>,

    /// Volatile memory for the Leader, including the work queue, pending reports, and pending
    /// colleciton requests. Note that in a production Leader, it is necessary to store this state
    /// across requsets.
    test_leader_state: Arc<Mutex<InMemoryLeaderState>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageProxyConfig {
    pub url: Url,
    pub auth_token: BearerToken,
}

#[axum::async_trait]
impl router::DaphneService for App {
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
            reject(format_args!("with task_id {}", task_id.to_base64url()))
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
    pub fn new<M>(
        storage_proxy_config: StorageProxyConfig,
        daphne_service_metrics: M,
        service_config: DaphneServiceConfig,
    ) -> Result<Self, DapError>
    where
        M: DaphneServiceMetrics + 'static,
    {
        Ok(Self {
            storage_proxy_config,
            http: reqwest::Client::new(),
            kv_state: Default::default(),
            metrics: Box::new(daphne_service_metrics),
            audit_log: Box::new(NoopAuditLog),
            service_config,
            test_leader_state: Default::default(),
        })
    }

    pub fn set_audit_log<A>(&mut self, audit_log: A)
    where
        A: AuditLog + Send + Sync + 'static,
    {
        self.audit_log = Box::new(audit_log);
    }

    pub(crate) fn durable(&self) -> Do<'_> {
        Do::new(&self.storage_proxy_config, &self.http)
    }

    pub(crate) fn kv(&self) -> Kv<'_> {
        Kv::new(&self.storage_proxy_config, &self.http, &self.kv_state)
    }

    pub(crate) fn bearer_tokens(&self) -> BearerTokens<'_> {
        BearerTokens::from(Kv::new(
            &self.storage_proxy_config,
            &self.http,
            &self.kv_state,
        ))
    }
}
