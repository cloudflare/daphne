// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Workers backend for `daphne-server`.
//!
//! The code is intended to be packaged with
//! [workers-rs](https://github.com/cloudflare/workers-rs). See [`DaphneWorkerRouter`] for usage
//! instructions.

mod durable;
pub mod storage_proxy;
mod tracing_utils;

use tracing::error;
use worker::{Env, Error};

pub use crate::tracing_utils::initialize_tracing;
pub use daphne::DapRequest;

pub(crate) fn int_err<S: ToString>(s: S) -> Error {
    error!("internal error: {}", s.to_string());
    Error::RustError("internalError".to_string())
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum DapWorkerMode {
    StorageProxy,
}
pub fn get_worker_mode(env: &Env) -> DapWorkerMode {
    match env
        .var("DAP_WORKER_MODE")
        .expect("DAP_WORKER_MODE is required")
        .to_string()
        .as_str()
    {
        "storage-proxy" => DapWorkerMode::StorageProxy,
        invalid => panic!("invalid DAP_WORKER_MODE: {invalid}"),
    }
}
