// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub mod bearer_token;
pub mod config;
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
    include!(concat!(
        env!("OUT_DIR"),
        "/src/durable_requests/durable_request_capnp.rs"
    ));
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DapRole {
    Leader,
    Helper,
}

impl DapRole {
    pub fn is_leader(self) -> bool {
        self == Self::Leader
    }

    pub fn is_helper(self) -> bool {
        self == Self::Helper
    }
}

impl FromStr for DapRole {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "leader" => Ok(Self::Leader),
            "helper" => Ok(Self::Helper),
            _ => Err(s.to_string()),
        }
    }
}

impl fmt::Display for DapRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Helper => "helper",
            Self::Leader => "leader",
        })
    }
}
