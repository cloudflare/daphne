// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne metrics.

use crate::DapError;
use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};

pub struct DaphneMetrics {
    /// Report metrics. How many reports have been rejected, aggregated, and collected. When
    /// a report is rejected, the failure type is recorded.
    pub(crate) report_counter: IntCounterVec,
}

impl DaphneMetrics {
    /// Register Daphne metrics with the specified registry.
    pub fn register(registry: &Registry, prefix: &str) -> Result<Self, DapError> {
        let report_counter = register_int_counter_vec_with_registry!(
            format!("{prefix}_report_counter"),
            "Total number reports rejected, aggregated, and collected.",
            &["status"],
            registry
        )?;

        Ok(Self { report_counter })
    }
}
