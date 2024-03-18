// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    ops::{Add, Div},
    time::Duration,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct TestDurations {
    pub hpke_config_fetch: Duration,
    pub aggregate_init_req: Duration,
    pub aggregate_cont_req: Duration,
    pub aggregate_share_req: Duration,
}

impl Add<&Self> for TestDurations {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            hpke_config_fetch: self.hpke_config_fetch + rhs.hpke_config_fetch,
            aggregate_init_req: self.aggregate_init_req + rhs.aggregate_init_req,
            aggregate_cont_req: self.aggregate_cont_req + rhs.aggregate_cont_req,
            aggregate_share_req: self.aggregate_share_req + rhs.aggregate_share_req,
        }
    }
}

impl Add for TestDurations {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            hpke_config_fetch: self.hpke_config_fetch + rhs.hpke_config_fetch,
            aggregate_init_req: self.aggregate_init_req + rhs.aggregate_init_req,
            aggregate_cont_req: self.aggregate_cont_req + rhs.aggregate_cont_req,
            aggregate_share_req: self.aggregate_share_req + rhs.aggregate_share_req,
        }
    }
}

impl Div<u32> for TestDurations {
    type Output = Self;

    fn div(self, rhs: u32) -> Self::Output {
        Self {
            hpke_config_fetch: self.hpke_config_fetch / rhs,
            aggregate_init_req: self.aggregate_init_req / rhs,
            aggregate_cont_req: self.aggregate_cont_req / rhs,
            aggregate_share_req: self.aggregate_share_req / rhs,
        }
    }
}

impl AsRef<Self> for TestDurations {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl TestDurations {
    pub fn total_service_time(&self) -> Duration {
        self.hpke_config_fetch
            + self.aggregate_init_req
            + self.aggregate_cont_req
            + self.aggregate_share_req
    }
}
