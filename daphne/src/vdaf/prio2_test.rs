// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    async_test_version, async_test_versions, hpke::HpkeKemId, testing::AggregationJobTest,
    DapAggregateResult, DapMeasurement, DapVersion, VdafConfig,
};
use paste::paste;

async fn roundtrip(version: DapVersion) {
    let mut t = AggregationJobTest::new(
        &VdafConfig::Prio2 { dimension: 5 },
        HpkeKemId::X25519HkdfSha256,
        version,
    );
    let got = t
        .roundtrip(vec![
            DapMeasurement::U32Vec(vec![1, 1, 0, 0, 1]),
            DapMeasurement::U32Vec(vec![1, 1, 0, 0, 1]),
            DapMeasurement::U32Vec(vec![1, 0, 0, 0, 1]),
            DapMeasurement::U32Vec(vec![0, 1, 0, 0, 1]),
            DapMeasurement::U32Vec(vec![0, 0, 1, 0, 1]),
        ])
        .await;
    assert_eq!(got, DapAggregateResult::U32Vec(vec![3, 3, 1, 0, 5]));
}

async_test_versions! { roundtrip }
