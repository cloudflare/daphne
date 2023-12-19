// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::path::PathBuf;

use clap::Parser;
use daphne_server::{router, App};
use daphne_service_utils::{config::DaphneServiceConfig, DapRole};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Config {
    service: DaphneServiceConfig,
    port: u16,
}

impl TryFrom<Args> for Config {
    type Error = config::ConfigError;
    fn try_from(
        Args {
            configuration,
            role,
            port,
        }: Args,
    ) -> Result<Self, Self::Error> {
        config::Config::builder()
            .set_default("port", 3000)?
            .add_source(match configuration {
                Some(path) => config::File::from(path.as_ref()),
                None => config::File::with_name("configuration"),
            })
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
            .add_source(config::Environment::with_prefix("DAP"))
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
    /// One of `leader` or `helper`.
    #[arg(short, long)]
    role: Option<DapRole>,
    /// The port to listen on.
    #[arg(short, long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    // Parse the configuration from the command line arguments.
    let config = Config::try_from(Args::parse())?;
    println!("starting service with config:\n{config:#?}");

    // Create a new prometheus registry where metrics will be registered and measured
    let registry = prometheus::Registry::new();

    let role = config.service.role;
    // Configure the application
    let app = App::new(
        "https://example.com".parse().unwrap(),
        &registry,
        config.service,
    )?;

    // create the router that will handle the protocol's http requests
    let router = router::new(role, app);

    // initialize tracing in a very default way.
    tracing_subscriber::fmt().pretty().init();

    // hand the router to axum for it to run
    axum::serve(
        tokio::net::TcpListener::bind(("0.0.0.0", config.port))
            .await
            .unwrap(),
        router,
    )
    .await?;

    Ok(())
}
