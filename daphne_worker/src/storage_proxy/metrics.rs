// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashMap, sync::OnceLock};

use daphne::auth::BearerToken;
use prometheus::{
    register_int_counter_vec_with_registry, Encoder, IntCounterVec, Registry, TextEncoder,
};
use url::Url;
use worker::Env;

struct Config {
    prometheus_server: Url,

    bearer_token: BearerToken,
}

impl Config {
    fn from_env(env: &Env) -> Option<&'static Self> {
        const DAP_METRICS_PUSH_SERVER_URL: &str = "DAP_METRICS_PUSH_SERVER_URL";
        const DAP_METRICS_PUSH_BEARER_TOKEN: &str = "DAP_METRICS_PUSH_BEARER_TOKEN";
        static CONFIG: OnceLock<Option<Config>> = OnceLock::new();

        CONFIG
            .get_or_init(|| {
                match (
                    env.var(DAP_METRICS_PUSH_SERVER_URL),
                    env.var(DAP_METRICS_PUSH_BEARER_TOKEN),
                ) {
                    (Ok(server_str), Ok(bearer_token_str)) => {
                        let prometheus_server = match server_str.to_string().parse() {
                            Ok(server) => server,
                            Err(error) => {
                                tracing::error!(error = ?error, "invalid server url");
                                return None;
                            }
                        };
                        Some(Self {
                            prometheus_server,
                            bearer_token: BearerToken::from(bearer_token_str.to_string()),
                        })
                    }
                    (Err(_), Err(_)) => None,
                    (Ok(_), Err(error)) => {
                        tracing::error!(%error, "failed to configure metrics push: missing bearer token");
                        None
                    }
                    (Err(error), Ok(_)) => {
                        tracing::error!(%error, "failed to configure metrics push: missing server URL");
                        None
                    }
                }
            })
            .as_ref()
    }
}

pub struct Metrics {
    config: &'static Config,

    _registry: Registry,

    /// Number of retries done in durable object requests before returning (whether by success
    /// or failure).
    durable_request_retry_count: IntCounterVec,
}

impl Metrics {
    pub fn new(host: &str, env: &Env) -> Option<Self> {
        let config = Config::from_env(env)?;

        let registry = Registry::new_custom(
            Option::None,
            Option::Some(HashMap::from([("host".to_string(), host.to_string())])),
        )
        .unwrap();

        let durable_request_retry_count = register_int_counter_vec_with_registry!(
            "durable_request_retry_count",
            "The number of times a request to a durable object was retried. count = -1 means the number of retries was exhausted",
            &["count", "object", "path"],
            registry,
        ).unwrap();

        Some(Self {
            config,
            _registry: registry,
            durable_request_retry_count,
        })
    }

    pub fn durable_request_retry_count_inc(
        &self,
        number_of_retries: i8,
        object: Option<&str>,
        path: &str,
    ) {
        self.durable_request_retry_count
            .with_label_values(&[
                &number_of_retries.to_string().as_str(),
                object.unwrap_or("unknown"),
                path,
            ])
            .inc();
    }

    pub async fn push_metrics(self) {
        let encoded_metrics = {
            let encoder = TextEncoder::new();
            let metrics = prometheus::gather();
            let mut encoded_metrics = Vec::new();
            if let Err(e) = encoder.encode(&metrics, &mut encoded_metrics) {
                tracing::error!(error = ?e, "failed to encode metrics");
            }
            encoded_metrics
        };

        let resp = reqwest_wasm::Client::new()
            .post(self.config.prometheus_server.clone())
            .bearer_auth(&self.config.bearer_token)
            .body(encoded_metrics)
            .send()
            .await;

        if let Err(e) = resp.and_then(|r| r.error_for_status()) {
            tracing::error!(error = ?e, "failed to push metrics");
        }
    }
}
