// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::path::PathBuf;

use clap::Parser;
use daphne_server::{metrics::DaphnePromServiceMetrics, router, App, StorageProxyConfig};
use daphne_service_utils::{config::DaphneServiceConfig, DapRole};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    service: DaphneServiceConfig,
    port: u16,
    storage_proxy: StorageProxyConfig,
}

impl TryFrom<Args> for Config {
    type Error = config::ConfigError;
    fn try_from(
        Args {
            configuration,
            role,
            port,
            storage_proxy,
        }: Args,
    ) -> Result<Self, Self::Error> {
        config::Config::builder()
            .set_default("port", 3000)?
            .add_source(match configuration {
                Some(path) => config::File::from(path.as_ref()),
                None => config::File::with_name("configuration"),
            })
            .add_source(
                config::Environment::with_prefix("DAP")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .set_override_option(
                "service.role",
                role.map(|role| {
                    config::Value::new(
                        Some(&String::from("args.role")),
                        match role {
                            DapRole::Leader => "leader",
                            DapRole::Helper => "helper",
                        },
                    )
                }),
            )?
            .set_override_option(
                "port",
                port.map(|port| config::Value::new(Some(&String::from("args.port")), port)),
            )?
            .set_override_option(
                "storage_proxy",
                storage_proxy.map(|storage_proxy| {
                    config::Value::new(
                        Some(&String::from("args.storage_proxy")),
                        storage_proxy.to_string(),
                    )
                }),
            )?
            .build()?
            .try_deserialize()
    }
}

/// Daphne test service used in e2e tests and general manual testing
#[derive(clap::Parser)]
struct Args {
    /// A configuration file, can be in json, yaml or toml.
    #[arg(short, long)]
    configuration: Option<PathBuf>,

    // --- command line overridable parameters ---
    /// One of `leader` or `helper`.
    #[arg(short, long)]
    role: Option<DapRole>,
    /// The port to listen on.
    #[arg(short, long)]
    port: Option<u16>,
    /// The storage url.
    #[arg(short, long)]
    storage_proxy: Option<Url>,
}

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let _profiler = dhat::Profiler::new_heap();

    // Parse the configuration from the command line arguments.
    let config = Config::try_from(Args::parse())?;
    println!(
        "starting service with config:\n{}",
        serde_yaml::to_string(&config).unwrap()
    );

    // Create a new prometheus registry where metrics will be registered and measured
    let registry = prometheus::Registry::new();
    let daphne_service_metrics = DaphnePromServiceMetrics::register(&registry)?;

    let role = config.service.role;
    // Configure the application
    let app = App::new(config.storage_proxy, daphne_service_metrics, config.service)?;

    // create the router that will handle the protocol's http requests
    let router = router::new(role, app);

    // initialize tracing in a very default way.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // hand the router to axum for it to run
    let serve = axum::Server::bind(&std::net::SocketAddr::new(
        "0.0.0.0".parse().unwrap(),
        config.port,
    ))
    .serve(router.into_make_service());

    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        _ = serve => {}
        _ = ctrl_c => {}
    }

    Ok(())
}
