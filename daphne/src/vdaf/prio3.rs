// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [Prio3 VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{
    vdaf::VdafError, DapAggregateResult, DapMeasurement, Prio3Config, VdafAggregateShare,
    VdafPrepMessage, VdafPrepState,
};
use prio::{
    codec::{Encode, ParameterizedDecode},
    vdaf::{
        prio3::{
            Prio3, Prio3InputShare, Prio3PrepareMessage, Prio3PrepareShare, Prio3PrepareState,
            Prio3PublicShare,
        },
        AggregateShare, Aggregator, Client, Collector, PrepareTransition, Vdaf,
    },
};
use std::io::Cursor;

const ERR_EXPECT_FINISH: &str = "unexpected transition (continued)";
const ERR_FIELD_TYPE: &str = "unexpected field type for step or message";

macro_rules! shard {
    (
        $vdaf:ident,
        $measurement:expr,
        $nonce:expr
    ) => {{
        // Split measurement into input shares.
        let (public_share, input_shares) = $vdaf.shard($measurement, $nonce)?;

        (
            public_share.get_encoded(),
            input_shares
                .iter()
                .map(|input_share| input_share.get_encoded())
                .collect(),
        )
    }};
}

/// Split the given measurement into a sequence of encoded input shares.
pub(crate) fn prio3_shard(
    config: &Prio3Config,
    measurement: DapMeasurement,
    nonce: &[u8; 16],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), VdafError> {
    match (&config, measurement) {
        (Prio3Config::Count, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_count(2)?;
            Ok(shard!(vdaf, &measurement, nonce))
        }
        (Prio3Config::Histogram { len }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_histogram(2, *len)?;
            let m: usize = measurement.try_into().unwrap();
            Ok(shard!(vdaf, &m, nonce))
        }
        (Prio3Config::Sum { bits }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            Ok(shard!(vdaf, &(measurement as u128), nonce))
        }
        (Prio3Config::SumVec { bits, len }, DapMeasurement::U128Vec(measurement)) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            Ok(shard!(vdaf, &measurement, nonce))
        }
        _ => panic!("prio3_shard: unexpected VDAF config {config:?}"),
    }
}

macro_rules! prep_init {
    (
        $vdaf:ident,
        $verify_key:expr,
        $agg_id:expr,
        $nonce:expr,
        $public_share_data:expr,
        $input_share_data:expr
    ) => {{
        // Parse the public share.
        let public_share = Prio3PublicShare::get_decoded_with_param(&$vdaf, $public_share_data)?;

        // Parse the input share.
        let input_share =
            Prio3InputShare::get_decoded_with_param(&(&$vdaf, $agg_id), $input_share_data)?;

        // Run the prepare-init algorithm, returning the initial state.
        $vdaf.prepare_init(
            $verify_key,
            $agg_id,
            &(),
            $nonce,
            &public_share,
            &input_share,
        )?
    }};
}

/// Consume an input share and return the corresponding VDAF step and message.
pub(crate) fn prio3_prepare_init(
    config: &Prio3Config,
    verify_key: &[u8; 16],
    agg_id: usize,
    nonce: &[u8; 16],
    public_share_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafPrepState, VdafPrepMessage), VdafError> {
    match &config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_count(2)?;
            let (state, share) = prep_init!(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data
            );
            Ok((
                VdafPrepState::Prio3Field64(state),
                VdafPrepMessage::Prio3ShareField64(share),
            ))
        }
        Prio3Config::Histogram { len } => {
            let vdaf = Prio3::new_histogram(2, *len)?;
            let (state, share) = prep_init!(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data
            );
            Ok((
                VdafPrepState::Prio3Field128(state),
                VdafPrepMessage::Prio3ShareField128(share),
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let (state, share) = prep_init!(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data
            );
            Ok((
                VdafPrepState::Prio3Field128(state),
                VdafPrepMessage::Prio3ShareField128(share),
            ))
        }
        Prio3Config::SumVec { bits, len } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            let (state, share) = prep_init!(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data
            );
            Ok((
                VdafPrepState::Prio3Field128(state),
                VdafPrepMessage::Prio3ShareField128(share),
            ))
        }
    }
}

macro_rules! leader_prep_fin {
    (
        $vdaf:ident,
        $leader_state:expr,
        $leader_share:expr,
        $helper_share_data:expr
    ) => {{
        // Decode the Helper's inbound message.
        let helper_share =
            Prio3PrepareShare::get_decoded_with_param(&$leader_state, $helper_share_data)?;

        // Preprocess the inbound messages.
        let message = $vdaf.prepare_preprocess([$leader_share, helper_share])?;
        let message_data = message.get_encoded();

        // Compute the leader's output share.
        match $vdaf.prepare_step($leader_state, message)? {
            PrepareTransition::Continue(..) => {
                panic!("prio3_leader_prepare_finish: {ERR_EXPECT_FINISH}")
            }
            PrepareTransition::Finish(out_share) => (out_share, message_data),
        }
    }};
}

/// Consume the verifier shares and return the output share and serialized outbound message.
pub(crate) fn prio3_leader_prepare_finish(
    config: &Prio3Config,
    leader_state: VdafPrepState,
    leader_share: VdafPrepMessage,
    helper_share_data: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
    let (agg_share, outbound) = match (&config, leader_state, leader_share) {
        (
            Prio3Config::Count,
            VdafPrepState::Prio3Field64(state),
            VdafPrepMessage::Prio3ShareField64(share),
        ) => {
            let vdaf = Prio3::new_count(2)?;
            let (out_share, outbound) = leader_prep_fin!(vdaf, state, share, helper_share_data);
            let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Histogram { len },
            VdafPrepState::Prio3Field128(state),
            VdafPrepMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_histogram(2, *len)?;
            let (out_share, outbound) = leader_prep_fin!(vdaf, state, share, helper_share_data);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Sum { bits },
            VdafPrepState::Prio3Field128(state),
            VdafPrepMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let (out_share, outbound) = leader_prep_fin!(vdaf, state, share, helper_share_data);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::SumVec { bits, len },
            VdafPrepState::Prio3Field128(state),
            VdafPrepMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            let (out_share, outbound) = leader_prep_fin!(vdaf, state, share, helper_share_data);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        _ => panic!("prio3_leader_prepare_finish: {ERR_FIELD_TYPE}"),
    };

    Ok((agg_share, outbound))
}

macro_rules! helper_prep_fin {
    (
        $vdaf:ident,
        $helper_state:expr,
        $leader_message_data:expr
    ) => {{
        // Decode the inbound message from the Leader, which contains the preprocessed prepare
        // message.
        let leader_message =
            Prio3PrepareMessage::get_decoded_with_param(&$helper_state, $leader_message_data)?;

        // Compute the Helper's output share.
        match $vdaf.prepare_step($helper_state, leader_message)? {
            PrepareTransition::Continue(..) => {
                panic!("prio3_helper_prepare_finish: {ERR_EXPECT_FINISH}")
            }
            PrepareTransition::Finish(out_share) => out_share,
        }
    }};
}

/// Consume the peer's prepare message and return an output share.
pub(crate) fn prio3_helper_prepare_finish(
    config: &Prio3Config,
    state: VdafPrepState,
    peer_message_data: &[u8],
) -> Result<VdafAggregateShare, VdafError> {
    let agg_share = match (&config, state) {
        (Prio3Config::Count, VdafPrepState::Prio3Field64(state)) => {
            let vdaf = Prio3::new_count(2)?;
            let out_share = helper_prep_fin!(vdaf, state, peer_message_data);
            VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Histogram { len }, VdafPrepState::Prio3Field128(state)) => {
            let vdaf = Prio3::new_histogram(2, *len)?;
            let out_share = helper_prep_fin!(vdaf, state, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Sum { bits }, VdafPrepState::Prio3Field128(state)) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let out_share = helper_prep_fin!(vdaf, state, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::SumVec { bits, len }, VdafPrepState::Prio3Field128(state)) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            let out_share = helper_prep_fin!(vdaf, state, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        _ => panic!("prio3_helper_prepare_finish: {ERR_FIELD_TYPE}"),
    };

    Ok(agg_share)
}

/// Parse a prio3 prepare message from the front of `reader` whose type is compatible with `param`.
pub(crate) fn prio3_decode_prepare_state(
    config: &Prio3Config,
    agg_id: usize,
    bytes: &mut Cursor<&[u8]>,
) -> Result<VdafPrepState, VdafError> {
    match config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_count(2)?;
            Ok(VdafPrepState::Prio3Field64(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::Histogram { len } => {
            let vdaf = Prio3::new_histogram(2, *len)?;
            Ok(VdafPrepState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            Ok(VdafPrepState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::SumVec { bits, len } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            Ok(VdafPrepState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
    }
}

macro_rules! unshard {
    (
        $vdaf:ident,
        $num_measurements:ident,
        $agg_shares:expr
    ) => {{
        let mut agg_shares = Vec::with_capacity($vdaf.num_aggregators());
        for data in $agg_shares.into_iter() {
            let agg_share = AggregateShare::get_decoded_with_param(&(&$vdaf, &()), data.as_ref())?;
            agg_shares.push(agg_share)
        }
        $vdaf.unshard(&(), agg_shares, $num_measurements)
    }};
}

/// Interpret `agg_shares` as a sequence of encoded aggregate shares and unshard them.
pub(crate) fn prio3_unshard<M: IntoIterator<Item = Vec<u8>>>(
    config: &Prio3Config,
    num_measurements: usize,
    agg_shares: M,
) -> Result<DapAggregateResult, VdafError> {
    match &config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_count(2)?;
            let agg_res = unshard!(vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U64(agg_res))
        }
        Prio3Config::Histogram { len } => {
            let vdaf = Prio3::new_histogram(2, *len)?;
            let agg_res = unshard!(vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U128Vec(agg_res))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let agg_res = unshard!(vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U128(agg_res))
        }
        Prio3Config::SumVec { bits, len } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            let agg_res = unshard!(vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U128Vec(agg_res))
        }
    }
}
