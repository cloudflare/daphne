// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne-Worker error reporting trait and default implementation.

use daphne::aborts::DapAbort;

/// Interface for error reporting in Daphne
/// Refer to NoopErrorReporter for implementation example.
pub trait ErrorReporter {
    fn report_abort(&self, error: &DapAbort);
}

/// Default implementation of the error reporting trait, which is a no-op.
pub(crate) struct NoopErrorReporter {}

impl ErrorReporter for NoopErrorReporter {
    fn report_abort(&self, _error: &DapAbort) {}
}
