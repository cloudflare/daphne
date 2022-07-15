// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{vdaf::mod_test::Test, DapAggregateResult, DapMeasurement, VdafConfig};

#[test]
fn roundtrip() {
    let mut t = Test::new(&VdafConfig::Prio2 { dimension: 5 });
    let got = t.roundtrip(vec![
        DapMeasurement::U32Vec(vec![1, 1, 0, 0, 1]),
        DapMeasurement::U32Vec(vec![1, 1, 0, 0, 1]),
        DapMeasurement::U32Vec(vec![1, 0, 0, 0, 1]),
        DapMeasurement::U32Vec(vec![0, 1, 0, 0, 1]),
        DapMeasurement::U32Vec(vec![0, 0, 1, 0, 1]),
    ]);
    assert_eq!(got, DapAggregateResult::U32Vec(vec![3, 3, 1, 0, 5]));
}
