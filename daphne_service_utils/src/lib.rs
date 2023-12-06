// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub mod auth;
pub mod metrics;
pub mod test_route_types;

/// Parameters used by the Leader to select a set of reports for aggregation.
#[derive(Debug, Deserialize, Serialize)]
pub struct DaphneServiceReportSelector {
    /// Maximum number of aggregation jobs to process at once.
    pub max_agg_jobs: u64,

    /// Maximum number of reports to drain for each aggregation job.
    pub max_reports: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
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
