// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne metrics.

use crate::{fatal_error, DapError};
use prometheus::{
    exponential_buckets, register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, Histogram, IntCounter, IntCounterVec, Registry,
};

pub struct DaphneMetrics {
    /// Inbound request metrics: Successful requests served, broken down by type.
    inbound_request_counter: IntCounterVec,

    /// Report metrics. How many reports have been rejected, aggregated, and collected. When
    /// a report is rejected, the failure type is recorded.
    report_counter: IntCounterVec,

    /// Helper: Total number of aggregation jobs started and completed.
    aggregation_job_counter: IntCounterVec,

    /// Helper: Number of records in an incoming AggregationJobInitReq.
    aggregation_job_batch_size_histogram: Histogram,

    /// Helper: Number of times replays caused the aggregation to be retried.
    aggregation_job_continue_repeats_due_to_replays: IntCounter,
}

impl DaphneMetrics {
    /// Register Daphne metrics with the specified registry. If a prefix is provided, then
    /// "{prefix_}" is prepended to the name.
    pub fn register(registry: &Registry) -> Result<Self, DapError> {
        let inbound_request_counter = register_int_counter_vec_with_registry!(
            "inbound_request_counter",
            "Total number of successful inbound requests.",
            &["type"],
            registry
        )
        .map_err(|e| fatal_error!(err = ?e, "failed to regsiter inbound_request_counter"))?;

        let report_counter = register_int_counter_vec_with_registry!(
            "report_counter",
            "Total number reports rejected, aggregated, and collected.",
            &["status"],
            registry
        )
        .map_err(|e| fatal_error!(err = ?e, "failed to register report_counter"))?;

        let aggregation_job_batch_size_histogram = register_histogram_with_registry!(
            "aggregation_job_batch_size",
            "Number of records in an incoming AggregationJobInitReq.",
            // <1, <2, <4, <8, ... <256, +Inf
            exponential_buckets(1.0, 2.0, 8)
                .expect("this shouldn't panic for these hardcoded values"),
            registry
        )
        .map_err(|e| fatal_error!(err = ?e, "failed to register aggregation_job_batch_size"))?;

        let aggregation_job_counter = register_int_counter_vec_with_registry!(
            format!("aggregation_job_counter"),
            "Total number of aggregation jobs started and completed.",
            &["status"],
            registry
        )
        .map_err(|e| fatal_error!(err = ?e, "failed to register aggregation_job_counter"))?;

        let aggregation_job_continue_repeats_due_to_replays =
            register_int_counter_with_registry!(
                "aggregation_continuation_repeats_due_to_replays",
                "Total number of times the aggregation continuation was restarted due to replayed reports",
                registry
            )
            .map_err(|e| fatal_error!(err = ?e, "failed to register aggregation_continuation_repeats_due_to_replays"))?;

        Ok(Self {
            inbound_request_counter,
            report_counter,
            aggregation_job_counter,
            aggregation_job_batch_size_histogram,
            aggregation_job_continue_repeats_due_to_replays,
        })
    }

    pub fn inbound_req_inc(&self, request_type: DaphneRequestType) {
        let request_type_str = match request_type {
            DaphneRequestType::HpkeConfig => "hpke_config",
            DaphneRequestType::Upload => "upload",
            DaphneRequestType::Aggregate => "aggregate",
            DaphneRequestType::Collect => "collect",
        };

        self.inbound_request_counter
            .with_label_values(&[request_type_str])
            .inc();
    }

    pub fn report_inc_by(&self, status: &str, val: u64) {
        self.report_counter.with_label_values(&[status]).inc_by(val);
    }

    pub fn agg_job_observe_batch_size(&self, val: usize) {
        self.aggregation_job_batch_size_histogram
            .observe(val as f64);
    }

    pub fn agg_job_started_inc(&self) {
        self.aggregation_job_counter
            .with_label_values(&["started"])
            .inc();
    }

    pub fn agg_job_completed_inc(&self) {
        self.aggregation_job_counter
            .with_label_values(&["completed"])
            .inc();
    }

    pub fn agg_job_cont_restarted_inc(&self) {
        self.aggregation_job_continue_repeats_due_to_replays.inc();
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DaphneRequestType {
    /// DAP request for fetching the Aggregator's HPKE config.
    HpkeConfig,
    /// DAP upload request.
    Upload,
    /// DAP aggregate request.
    Aggregate,
    /// DAP collect request.
    Collect,
}
