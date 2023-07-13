// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    vdaf::{
        prio3::{
            prio3_helper_prepare_finish, prio3_leader_prepare_finish, prio3_prepare_init,
            prio3_shard, prio3_unshard,
        },
        VdafError,
    },
    DapAggregateResult, DapMeasurement, Prio3Config,
};
use prio::codec::Encode;
use rand::prelude::*;

#[test]
fn prepare_count() {
    test_prepare(
        &Prio3Config::Count,
        DapMeasurement::U64(0),
        DapAggregateResult::U64(0),
    )
    .unwrap();
}

#[test]
fn prepare_sum() {
    test_prepare(
        &Prio3Config::Sum { bits: 23 },
        DapMeasurement::U64(1337),
        DapAggregateResult::U128(1337),
    )
    .unwrap();
}

#[test]
fn prepare_histogram() {
    test_prepare(
        &Prio3Config::Histogram { len: 3 },
        DapMeasurement::U64(2),
        DapAggregateResult::U128Vec(vec![0, 0, 1]),
    )
    .unwrap();
}

#[test]
fn prepare_sum_vec() {
    test_prepare(
        &Prio3Config::SumVec { bits: 23, len: 1 },
        DapMeasurement::U128Vec(vec![(1 << 23) - 1]),
        DapAggregateResult::U128Vec(vec![(1 << 23) - 1]),
    )
    .unwrap();

    test_prepare(
        &Prio3Config::SumVec { bits: 23, len: 3 },
        DapMeasurement::U128Vec(vec![1, 0, 42]),
        DapAggregateResult::U128Vec(vec![1, 0, 42]),
    )
    .unwrap();
}

fn test_prepare(
    config: &Prio3Config,
    measurement: DapMeasurement,
    expected_result: DapAggregateResult,
) -> Result<(), VdafError> {
    let mut rng = thread_rng();
    let verify_key = rng.gen();
    let nonce = [0; 16];

    // Shard
    let (encoded_public_share, encoded_input_shares) =
        prio3_shard(config, measurement, &nonce).unwrap();
    assert_eq!(encoded_input_shares.len(), 2);

    // Prepare
    let (leader_state, leader_share) = prio3_prepare_init(
        config,
        &verify_key,
        0,
        &nonce,
        &encoded_public_share,
        &encoded_input_shares[0],
    )?;

    let (helper_state, helper_share) = prio3_prepare_init(
        config,
        &verify_key,
        1,
        &nonce,
        &encoded_public_share,
        &encoded_input_shares[1],
    )?;

    let (leader_out_share, leader_message_data) = prio3_leader_prepare_finish(
        config,
        leader_state,
        leader_share,
        &helper_share.get_encoded(),
    )?;

    let helper_out_share = prio3_helper_prepare_finish(config, helper_state, &leader_message_data)?;

    // Unshard
    let agg_res = prio3_unshard(
        config,
        1,
        [
            leader_out_share.get_encoded(),
            helper_out_share.get_encoded(),
        ],
    )
    .unwrap();
    assert_eq!(agg_res, expected_result);

    Ok(())
}
