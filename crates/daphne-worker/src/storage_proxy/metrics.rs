// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};

pub struct Metrics {
    /// Number of retries done in durable object requests before returning (whether by success
    /// or failure).
    durable_request_retry_count: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        let durable_request_retry_count = register_int_counter_vec_with_registry!(
            "durable_request_retry_count",
            "The number of times a request to a durable object was retried. count = -1 means the number of retries was exhausted",
            &["count", "object", "path"],
            registry,
        ).unwrap();

        Self {
            durable_request_retry_count,
        }
    }

    pub fn durable_request_retry_count_inc(&self, number_of_retries: i8, object: &str, path: &str) {
        self.durable_request_retry_count
            .with_label_values(&[&number_of_retries.to_string(), object, path])
            .inc();
    }
}
