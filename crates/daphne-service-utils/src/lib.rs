// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![cfg_attr(not(test), deny(unused_crate_dependencies))]

pub mod bearer_token;
#[cfg(any(feature = "durable_requests", feature = "compute-offload"))]
pub mod capnproto;
#[cfg(feature = "compute-offload")]
pub mod compute_offload;
#[cfg(feature = "durable_requests")]
pub mod durable_requests;
pub mod http_headers;
#[cfg(feature = "test-utils")]
pub mod test_route_types;

// the generated code expects this module to be defined at the root of the library.
#[cfg(any(feature = "durable_requests", feature = "compute-offload"))]
#[doc(hidden)]
pub mod base_capnp {
    #![allow(dead_code)]
    #![allow(clippy::pedantic)]
    #![allow(clippy::needless_lifetimes)]
    include!(concat!(env!("OUT_DIR"), "/src/capnproto/base_capnp.rs"));
}

#[cfg(feature = "durable_requests")]
mod durable_request_capnp {
    #![allow(dead_code)]
    #![allow(clippy::pedantic)]
    #![allow(clippy::needless_lifetimes)]
    include!(concat!(
        env!("OUT_DIR"),
        "/src/durable_requests/durable_request_capnp.rs"
    ));
}

#[cfg(feature = "durable_requests")]
mod aggregation_job_store_capnp {
    #![allow(dead_code)]
    #![allow(clippy::pedantic)]
    #![allow(clippy::needless_lifetimes)]
    include!(concat!(
        env!("OUT_DIR"),
        "/src/durable_requests/bindings/aggregation_job_store_capnp.rs"
    ));
}

#[cfg(feature = "durable_requests")]
mod agg_job_response_store_capnp {
    #![allow(dead_code)]
    #![allow(clippy::pedantic)]
    #![allow(clippy::needless_lifetimes)]
    include!(concat!(
        env!("OUT_DIR"),
        "/src/durable_requests/bindings/agg_job_response_store_capnp.rs"
    ));
}

#[cfg(feature = "durable_requests")]
mod aggregate_store_v2_capnp {
    #![allow(dead_code)]
    #![allow(clippy::pedantic)]
    #![allow(clippy::needless_lifetimes)]
    include!(concat!(
        env!("OUT_DIR"),
        "/src/durable_requests/bindings/aggregate_store_v2_capnp.rs"
    ));
}

#[cfg(feature = "durable_requests")]
mod replay_checker_capnp {
    #![allow(dead_code)]
    #![allow(clippy::pedantic)]
    #![allow(clippy::needless_lifetimes)]
    include!(concat!(
        env!("OUT_DIR"),
        "/src/durable_requests/bindings/replay_checker_capnp.rs"
    ));
}

#[cfg(feature = "compute-offload")]
#[doc(hidden)]
pub mod compute_offload_capnp {
    #![allow(dead_code)]
    #![allow(clippy::pedantic)]
    #![allow(clippy::needless_lifetimes)]
    include!(concat!(
        env!("OUT_DIR"),
        "/src/compute_offload/compute_offload_capnp.rs"
    ));
}
