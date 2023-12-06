// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker metrics.

use daphne::{fatal_error, metrics::DaphneMetrics, DapError};
use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};

pub struct DaphneServiceMetrics {
    /// Daphne metrics.
    pub daphne: DaphneMetrics,

    /// HTTP response status.
    pub http_status_code_counter: IntCounterVec,

    /// DAP aborts.
    pub dap_abort_counter: IntCounterVec,
}

impl DaphneServiceMetrics {
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

        let daphne = DaphneMetrics::register(registry)?;

        Ok(Self {
            daphne,
            http_status_code_counter,
            dap_abort_counter,
        })
    }
}
