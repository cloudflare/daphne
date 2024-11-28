// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![cfg_attr(not(test), deny(unused_crate_dependencies))]

pub mod bearer_token;
#[cfg(feature = "durable_requests")]
pub mod durable_requests;
pub mod http_headers;
#[cfg(feature = "test-utils")]
pub mod test_route_types;

// the generated code expects this module to be defined at the root of the library.
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
