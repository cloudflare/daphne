// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker metrics.

use std::time::Duration;

use daphne::metrics::DaphneMetrics;

pub trait DaphneServiceMetrics: DaphneMetrics {
    fn abort_count_inc(&self, label: &str);
    fn count_http_status_code(&self, status_code: u16);
    fn daphne(&self) -> &dyn DaphneMetrics;
    fn auth_method_inc(&self, method: AuthMethod);
    fn observe_aggregate_store_merge_time(&self, d: Duration);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    BearerToken,
    TlsClientAuth,
}

#[cfg(any(feature = "prometheus", feature = "test-utils", test))]
mod prometheus {
    use std::time::Duration;

    use super::DaphneServiceMetrics;
    use daphne::{
        fatal_error,
        metrics::{prometheus::DaphnePromMetrics, DaphneMetrics},
        DapError,
    };
    use prometheus::{
        register_histogram_with_registry, register_int_counter_vec_with_registry, Histogram,
        IntCounterVec, Registry,
    };

    impl DaphneMetrics for DaphnePromServiceMetrics {
        fn report_inc_by(&self, status: &str, val: u64) {
            self.daphne.report_inc_by(status, val);
        }

        fn inbound_req_inc(&self, request_type: daphne::metrics::DaphneRequestType) {
            self.daphne.inbound_req_inc(request_type);
        }

        fn agg_job_started_inc(&self) {
            self.daphne.agg_job_started_inc();
        }

        fn agg_job_completed_inc(&self) {
            self.daphne.agg_job_completed_inc();
        }

        fn agg_job_observe_batch_size(&self, val: usize) {
            self.daphne.agg_job_observe_batch_size(val);
        }

        fn agg_job_put_span_retry_inc(&self) {
            self.daphne.agg_job_put_span_retry_inc();
        }
    }

    impl DaphneServiceMetrics for DaphnePromServiceMetrics {
        fn abort_count_inc(&self, label: &str) {
            self.dap_abort_counter.with_label_values(&[label]).inc();
        }

        fn count_http_status_code(&self, status_code: u16) {
            self.http_status_code_counter
                .with_label_values(&[&status_code.to_string()])
                .inc();
        }

        fn auth_method_inc(&self, method: super::AuthMethod) {
            let method = match method {
                super::AuthMethod::TlsClientAuth => "mutual_tls",
                super::AuthMethod::BearerToken => "tls_client_auth",
            };
            self.auth_method.with_label_values(&[method]).inc();
        }

        fn daphne(&self) -> &dyn DaphneMetrics {
            self
        }

        fn observe_aggregate_store_merge_time(&self, d: Duration) {
            self.aggregate_store_merge_time_histogram
                .observe(d.as_millis() as f64);
        }
    }

    #[derive(Clone)]
    pub struct DaphnePromServiceMetrics {
        /// Daphne metrics.
        daphne: DaphnePromMetrics,

        /// HTTP response status.
        http_status_code_counter: IntCounterVec,

        /// DAP aborts.
        dap_abort_counter: IntCounterVec,

        /// Counts the used authentication methods
        auth_method: IntCounterVec,

        /// Histogram of the times merge requests to aggregate store take.
        aggregate_store_merge_time_histogram: Histogram,
    }

    impl DaphnePromServiceMetrics {
        pub fn register(registry: &Registry) -> Result<Self, DapError> {
            let http_status_code_counter = register_int_counter_vec_with_registry!(
                "http_status_code",
                "HTTP response status code.",
                &["code"],
                registry
            )
            .map_err(|e| fatal_error!(err = ?e, "failed to register http_status_code"))?;

            let dap_abort_counter = register_int_counter_vec_with_registry!(
                "dap_abort",
                "DAP aborts.",
                &["reason"],
                registry
            )
            .map_err(|e| fatal_error!(err = ?e, "failed to register dap_abort"))?;

            let auth_method = register_int_counter_vec_with_registry!(
                "auth_method",
                "The authentication method used",
                &["method"],
                registry
            )
            .map_err(|e| fatal_error!(err = ?e, "failed to register dap_abort"))?;

            let aggregate_store_merge_time_histogram = register_histogram_with_registry!(
                "aggregate_store_merge_time_histogram",
                "Time it takes to resolve an aggregate store merge request",
                vec![1., 10., 100., 1_000., 10_000., 20_000., 30_000., 40_000.],
                registry
            )
            .map_err(|e| fatal_error!(err = ?e, "failed to register aggregation_job_batch_size"))?;

            let daphne = DaphnePromMetrics::register(registry)?;

            Ok(Self {
                daphne,
                http_status_code_counter,
                dap_abort_counter,
                auth_method,
                aggregate_store_merge_time_histogram,
            })
        }
    }
}

#[cfg(any(feature = "prometheus", feature = "test-utils", test))]
pub use prometheus::DaphnePromServiceMetrics;
