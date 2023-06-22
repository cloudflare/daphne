// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker metrics.

use crate::DapError;
use daphne::{fatal_error, metrics::DaphneMetrics};
use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};

pub(crate) struct DaphneWorkerMetrics {
    /// Daphne metrics.
    pub(crate) daphne: DaphneMetrics,

    /// HTTP response status.
    pub(crate) http_status_code_counter: IntCounterVec,

    /// DAP aborts.
    pub(crate) dap_abort_counter: IntCounterVec,
}

impl DaphneWorkerMetrics {
    pub(crate) fn register(registry: &Registry, prefix: Option<&str>) -> Result<Self, DapError> {
        let front = if let Some(prefix) = prefix {
            format!("{prefix}_")
        } else {
            "".into()
        };

        let http_status_code_counter = register_int_counter_vec_with_registry!(
            format!("{front}http_status_code"),
            "HTTP response status code.",
            &["host", "code"],
            registry
        )
        .map_err(|e| fatal_error!(err = e, "failed to register http_status_code"))?;

        let dap_abort_counter = register_int_counter_vec_with_registry!(
            format!("{front}dap_abort"),
            "DAP aborts.",
            &["host"],
            registry
        )
        .map_err(|e| fatal_error!(err = e, "failed to register dap_abort"))?;

        let daphne = DaphneMetrics::register(registry, prefix)?;

        Ok(Self {
            daphne,
            http_status_code_counter,
            dap_abort_counter,
        })
    }
}
