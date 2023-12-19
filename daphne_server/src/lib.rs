// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![warn(unused_crate_dependencies)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::ignored_unit_patterns)]
#![allow(clippy::if_not_else)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::inconsistent_struct_constructor)]
#![allow(clippy::similar_names)]
#![allow(clippy::inline_always)]

use daphne::DapError;
use daphne_service_utils::{config::DaphneServiceConfig, metrics};
// there is a bug in cargo where if a dependency is only used in tests/examples but not in the
// library you get unused_crate_dependencies warnings when compiling the them.
#[cfg(test)]
mod silence_unused_crate_warning {
    use clap as _;
    use config as _;
    use tracing_subscriber as _;
}
use url::Url;

mod roles;
pub mod router;
mod worker_connection;

/// Entrypoint to the server implementation. This struct implements
/// [`DapLeader`](daphne::roles::DapLeader) and [`DapHelper`](daphne::roles::DapHelper) and can be
/// passed to the router.
///
/// It depends on a cloudflare worker to do it's storage using durable objects.
///
/// It can be constructed from:
/// - a `url` that points to a cloudflare worker which serves as proxy for the storage
/// implementation.
/// - a prometheus registry to register metrics.
/// - a [`DaphneServiceConfig`].
///
/// # Examples
/// ```
/// use url::Url;
/// use daphne::{DapGlobalConfig, hpke::HpkeKemId, DapVersion};
/// use daphne_service_utils::{config::DaphneServiceConfig, DapRole};
/// use daphne_server::{App, router};
///
/// let worker_url = Url::parse("http://example.com").unwrap();
/// let registry = prometheus::Registry::new();
/// let global = DapGlobalConfig {
///     max_batch_duration: 360_00,
///     min_batch_interval_start: 259_200,
///     max_batch_interval_end: 259_200,
///     supported_hpke_kems: vec![HpkeKemId::X25519HkdfSha256],
///     allow_taskprov: true,
/// };
/// let service_config = DaphneServiceConfig {
///     env: "some-machine-identifier".into(),
///     role: DapRole::Helper,
///     global,
///     report_shard_key: [1; 32],
///     report_shard_count: 4,
///     base_url: None,
///     taskprov: None,
///     default_version: DapVersion::DraftLatest,
///     report_storage_epoch_duration: 300,
/// };
/// let app = App::new(worker_url, &registry, service_config)?;
///
/// let router = router::new(DapRole::Helper, app);
///
/// # Ok::<(), daphne::DapError>(())
/// ```
pub struct App {
    worker: worker_connection::WorkerConn,
    metrics: metrics::DaphneServiceMetrics,
    service_config: DaphneServiceConfig,
}

impl router::DaphneService for App {
    fn server_metrics(&self) -> &metrics::DaphneServiceMetrics {
        &self.metrics
    }
}

impl App {
    /// Create a new configured app. See [`App`] for details.
    pub fn new(
        url: Url,
        registry: &prometheus::Registry,
        service_config: DaphneServiceConfig,
    ) -> Result<Self, DapError> {
        Ok(Self {
            worker: worker_connection::WorkerConn::new(url),
            metrics: metrics::DaphneServiceMetrics::register(registry)?,
            service_config,
        })
    }
}
