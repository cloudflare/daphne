// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Workers backend for `daphne-server`.

mod durable;
pub mod storage_proxy;
mod tracing_utils;

use tracing::error;
use worker::Error;

pub use crate::tracing_utils::initialize_tracing;
pub use daphne::DapRequest;

pub(crate) fn int_err<S: ToString>(s: S) -> Error {
    error!("internal error: {}", s.to_string());
    Error::RustError("internalError".to_string())
}
