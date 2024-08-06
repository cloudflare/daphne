// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry, HistogramVec,
    IntCounterVec, Registry,
};
use std::time::Duration;

pub struct Metrics {
    /// Number of retries done in durable object requests before returning (whether by success
    /// or failure).
    durable_request_retry_count: IntCounterVec,

    durable_request_time_seconds: HistogramVec,

    kv_request_time_seconds: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        let durable_request_retry_count = register_int_counter_vec_with_registry!(
            "durable_request_retry_count",
            "The number of times a request to a durable object was retried. count = -1 means the number of retries was exhausted",
            &["count", "object", "path"],
            registry,
        ).unwrap();

        let durable_request_time_seconds = register_histogram_vec_with_registry!(
            "durable_request_time_seconds",
            "Histogram of durable object request timings",
            &["uri", "outcome"],
            registry,
        )
        .unwrap();

        let kv_request_time_seconds = register_histogram_vec_with_registry!(
            "kv_request_time_seconds",
            "Histogram of KV request timings",
            &["op", "status"],
            registry,
        )
        .unwrap();

        Self {
            durable_request_retry_count,
            durable_request_time_seconds,
            kv_request_time_seconds,
        }
    }

    pub fn durable_request_retry_count_inc(&self, number_of_retries: i8, object: &str, path: &str) {
        self.durable_request_retry_count
            .with_label_values(&[&number_of_retries.to_string(), object, path])
            .inc();
    }

    pub fn durable_request_time_seconds_observe(&self, uri: &str, status: &str, time: Duration) {
        self.durable_request_time_seconds
            .with_label_values(&[uri, status])
            .observe(time.as_secs_f64());
    }

    pub fn kv_request_time_seconds_observe(&self, op: &str, status: &str, time: Duration) {
        self.kv_request_time_seconds
            .with_label_values(&[op, status])
            .observe(time.as_secs_f64());
    }
}
