// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    vdaf::prio3::{
        prio3_encode_prepare_message, prio3_helper_prepare_finish, prio3_leader_prepare_finish,
        prio3_prepare_start, prio3_setup, prio3_shard, prio3_unshard, Prio3Error,
    },
    DapAggregateResult, DapMeasurement, Prio3Config,
};
use prio::codec::Encode;

#[test]
fn prepare_count64() {
    test_prepare(
        &Prio3Config::Count,
        DapMeasurement::U64(0),
        DapAggregateResult::U64(0),
    )
    .unwrap();
}

#[test]
fn prepare_sum64() {
    test_prepare(
        &Prio3Config::Sum { bits: 23 },
        DapMeasurement::U64(1337),
        DapAggregateResult::U64(1337),
    )
    .unwrap();
}

#[test]
fn prepare_histogram64() {
    test_prepare(
        &Prio3Config::Histogram {
            buckets: vec![0, 23, 9999999],
        },
        DapMeasurement::U64(1337),
        DapAggregateResult::U64Vec(vec![0, 0, 1, 0]),
    )
    .unwrap();
}

fn test_prepare(
    param: &Prio3Config,
    measurement: DapMeasurement,
    expected_result: DapAggregateResult,
) -> Result<(), Prio3Error> {
    let nonce = b"this is a good nonce";

    let (leader_verify_param, helper_verify_param) = prio3_setup(param)?;

    // Shard
    let encoded_input_shares = prio3_shard(&param, measurement).unwrap();
    assert_eq!(encoded_input_shares.len(), 2);

    // Prepare
    let (leader_step, leader_message) = prio3_prepare_start(
        &param,
        &leader_verify_param.into_prio3(),
        nonce,
        &encoded_input_shares[0],
    )?;

    let (helper_step, helper_message) = prio3_prepare_start(
        &param,
        &helper_verify_param.into_prio3(),
        nonce,
        &encoded_input_shares[1],
    )?;

    let helper_message_data = prio3_encode_prepare_message(&helper_message);

    let (leader_out_share, leader_message_data) =
        prio3_leader_prepare_finish(&param, leader_step, leader_message, &helper_message_data)?;

    let helper_out_share = prio3_helper_prepare_finish(&param, helper_step, &leader_message_data)?;

    // Unshard
    let agg_res = prio3_unshard(
        &param,
        [
            leader_out_share.get_encoded(),
            helper_out_share.get_encoded(),
        ],
    )
    .unwrap();
    assert_eq!(agg_res, expected_result);

    Ok(())
}
