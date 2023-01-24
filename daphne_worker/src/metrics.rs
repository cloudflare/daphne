// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker metrics.

use crate::DapError;
use daphne::metrics::DaphneMetrics;
use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};

pub(crate) struct DaphneWorkerMetrics {
    /// Daphne metrics.
    pub(crate) daphne: DaphneMetrics,

    /// HTTP response status.
    pub(crate) http_status_code: IntCounterVec,
}

impl DaphneWorkerMetrics {
    pub(crate) fn register(registry: &Registry, prefix: &str) -> Result<Self, DapError> {
        let daphne = DaphneMetrics::register(registry, prefix)?;

        let http_status_code = register_int_counter_vec_with_registry!(
            format!("{prefix}_http_status_code"),
            "HTTP response status code.",
            &["code"],
            registry
        )?;

        Ok(Self {
            daphne,
            http_status_code,
        })
    }
}
