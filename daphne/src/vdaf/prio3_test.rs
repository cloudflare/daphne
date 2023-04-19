// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    async_test_version, async_test_versions, vdaf::mod_test::Test, DapAggregateResult,
    DapMeasurement, DapVersion, Prio3Config, VdafConfig,
};
use paste::paste;

async fn roundtrip_count(version: DapVersion) {
    let mut t = Test::new(&VdafConfig::Prio3(Prio3Config::Count), version);
    let got = t
        .roundtrip(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(1),
            DapMeasurement::U64(1),
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(1),
        ])
        .await;
    assert_eq!(got, DapAggregateResult::U64(5));
}

async_test_versions! { roundtrip_count }

async fn roundtrip_sum(version: DapVersion) {
    let mut t = Test::new(&VdafConfig::Prio3(Prio3Config::Sum { bits: 23 }), version);
    let got = t
        .roundtrip(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(1337),
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(1),
        ])
        .await;
    assert_eq!(got, DapAggregateResult::U128(1340));
}

async_test_versions! { roundtrip_sum }

async fn roundtrip_histogram(version: DapVersion) {
    let mut t = Test::new(
        &VdafConfig::Prio3(Prio3Config::Histogram {
            buckets: vec![0, 23, 999999],
        }),
        version,
    );
    let got = t.roundtrip(vec![DapMeasurement::U64(1337)]).await;
    assert_eq!(got, DapAggregateResult::U128Vec(vec![0, 0, 1, 0]));
}

async_test_versions! { roundtrip_histogram }

async fn roundtrip_sum_vec(version: DapVersion) {
    let mut t = Test::new(
        &VdafConfig::Prio3(Prio3Config::SumVec { bits: 23, len: 1 }),
        version,
    );
    let got = t
        .roundtrip(vec![DapMeasurement::U128Vec(vec![(1 << 23) - 1])])
        .await;
    assert_eq!(got, DapAggregateResult::U128Vec(vec![(1 << 23) - 1]),);

    let mut t = Test::new(
        &VdafConfig::Prio3(Prio3Config::SumVec { bits: 23, len: 3 }),
        version,
    );
    let got = t
        .roundtrip(vec![DapMeasurement::U128Vec(vec![1, 0, 42])])
        .await;
    assert_eq!(got, DapAggregateResult::U128Vec(vec![1, 0, 42]));
}

async_test_versions! { roundtrip_sum_vec }
