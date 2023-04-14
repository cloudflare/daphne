// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne metrics.

use crate::DapError;
use prometheus::{
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry, IntCounterVec,
    IntGaugeVec, Registry,
};

pub struct DaphneMetrics {
    /// Report metrics. How many reports have been rejected, aggregated, and collected. When
    /// a report is rejected, the failure type is recorded.
    report_counter: IntCounterVec,

    /// Helper: Number of running aggregation jobs.
    aggregation_job_gauge: IntGaugeVec,
}

impl DaphneMetrics {
    /// Register Daphne metrics with the specified registry. If a prefix is provided, then
    /// "{prefix_}" is prepended to the name.
    pub fn register(registry: &Registry, prefix: Option<&str>) -> Result<Self, DapError> {
        let front = if let Some(prefix) = prefix {
            format!("{prefix}_")
        } else {
            "".into()
        };

        let report_counter = register_int_counter_vec_with_registry!(
            format!("{front}report_counter"),
            "Total number reports rejected, aggregated, and collected.",
            &["host", "status"],
            registry
        )?;

        let aggregation_job_gauge = register_int_gauge_vec_with_registry!(
            format!("{front}aggregation_job_gauge"),
            "Number of running aggregation jobs.",
            &["host"],
            registry
        )?;

        Ok(Self {
            report_counter,
            aggregation_job_gauge,
        })
    }

    pub fn with_host<'req>(&'req self, host: &'req str) -> ContextualizedDaphneMetrics<'req> {
        ContextualizedDaphneMetrics {
            metrics: self,
            host,
        }
    }
}

pub struct ContextualizedDaphneMetrics<'req> {
    metrics: &'req DaphneMetrics,
    host: &'req str,
}

impl ContextualizedDaphneMetrics<'_> {
    pub fn report_inc_by(&self, status: &str, val: u64) {
        self.metrics
            .report_counter
            .with_label_values(&[self.host, status])
            .inc_by(val);
    }

    pub fn agg_job_inc(&self) {
        self.metrics
            .aggregation_job_gauge
            .with_label_values(&[self.host])
            .inc();
    }

    pub fn agg_job_dec(&self) {
        self.metrics
            .aggregation_job_gauge
            .with_label_values(&[self.host])
            .dec();
    }
}
