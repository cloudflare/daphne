// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashMap;

use prometheus::{
    register_int_counter_vec_with_registry, Encoder, IntCounterVec, Registry, TextEncoder,
};

pub struct Metrics {
    registry: Registry,

    /// Number of retries done in durable object requests before returning (whether by success
    /// or failure).
    durable_request_retry_count: IntCounterVec,

    /// HTTP response status.
    http_status_code_counter: IntCounterVec,
}

impl Metrics {
    pub fn new(host: &str) -> Self {
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

        let http_status_code_counter = register_int_counter_vec_with_registry!(
            "http_status_code",
            "HTTP response status code.",
            &["code"],
            registry
        )
        .unwrap();

        Self {
            registry,
            durable_request_retry_count,
            http_status_code_counter,
        }
    }

    pub fn durable_request_retry_count_inc(&self, number_of_retries: i8, object: &str, path: &str) {
        self.durable_request_retry_count
            .with_label_values(&[&number_of_retries.to_string(), object, path])
            .inc();
    }

    pub fn count_http_status_code(&self, status_code: u16) {
        self.http_status_code_counter
            .with_label_values(&[&status_code.to_string()])
            .inc();
    }

    pub fn encode_metrics(self) -> String {
        let encoder = TextEncoder::new();
        let metrics = self.registry.gather();
        let mut encoded_metrics = Vec::new();
        if let Err(e) = encoder.encode(&metrics, &mut encoded_metrics) {
            tracing::error!(error = ?e, "failed to encode metrics");
        }
        String::from_utf8(encoded_metrics).unwrap()
    }
}
