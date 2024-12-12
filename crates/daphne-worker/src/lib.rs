// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(clippy::semicolon_if_nothing_returned)]

//! Workers backend for `daphne-server`.

pub mod aggregator;
pub mod durable;
pub mod storage;
pub mod storage_proxy;
pub mod tracing_utils;

use tracing::error;
use worker::Error;

pub use crate::tracing_utils::initialize_tracing;
pub use axum::{
    body::Body,
    response::{IntoResponse, Response},
};
pub use daphne::DapRequest;
use std::time::Duration;

pub(crate) fn int_err<S: ToString>(s: S) -> Error {
    error!("internal error: {}", s.to_string());
    Error::RustError("internalError".to_string())
}

pub(crate) fn elapsed(date: &worker::Date) -> Duration {
    Duration::from_millis(worker::Date::now().as_millis() - date.as_millis())
}
