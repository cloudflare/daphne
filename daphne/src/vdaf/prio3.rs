// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [Prio3 VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{
    vdaf::VdafError, DapAggregateResult, DapMeasurement, Prio3Config, VdafAggregateShare,
    VdafMessage, VdafState,
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
        (Prio3Config::Histogram { buckets }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_histogram(2, buckets)?;
            Ok(shard!(vdaf, &(measurement as u128), nonce))
        }
        (Prio3Config::Sum { bits }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            Ok(shard!(vdaf, &(measurement as u128), nonce))
        }
        (Prio3Config::SumVec { bits, len }, DapMeasurement::U128Vec(measurement)) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            Ok(shard!(vdaf, &measurement, nonce))
        }
        _ => panic!("prio3_shard: unexpected VDAF config"),
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
pub(crate) fn prio3_prep_init(
    config: &Prio3Config,
    verify_key: &[u8; 16],
    agg_id: usize,
    nonce: &[u8; 16],
    public_share_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafState, VdafMessage), VdafError> {
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
                VdafState::Prio3Field64(state),
                VdafMessage::Prio3ShareField64(share),
            ))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3::new_histogram(2, buckets)?;
            let (state, share) = prep_init!(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data
            );
            Ok((
                VdafState::Prio3Field128(state),
                VdafMessage::Prio3ShareField128(share),
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
                VdafState::Prio3Field128(state),
                VdafMessage::Prio3ShareField128(share),
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
                VdafState::Prio3Field128(state),
                VdafMessage::Prio3ShareField128(share),
            ))
        }
    }
}

macro_rules! prep_finish_from_shares {
    (
        $vdaf:ident,
        $host_state:expr,
        $host_share:expr,
        $peer_share_data:expr,
        $is_leader:expr
    ) => {{
        // Decode the peer's prep share.
        let peer_share = Prio3PrepareShare::get_decoded_with_param(&$host_state, $peer_share_data)?;
        let shares = if $is_leader {
            [$host_share, peer_share]
        } else {
            [peer_share, $host_share]
        };

        // Combine the prep shares into the prep message.
        let message = $vdaf.prepare_preprocess(shares)?;
        let message_data = message.get_encoded();

        // Compute the host's output share.
        match $vdaf.prepare_step($host_state, message)? {
            PrepareTransition::Continue(..) => {
                panic!("prio3_prep_finish: {ERR_EXPECT_FINISH}")
            }
            PrepareTransition::Finish(out_share) => (out_share, message_data),
        }
    }};
}

/// Consume the verifier shares and return the output share and serialized outbound message.
pub(crate) fn prio3_prep_finish_from_shares(
    config: &Prio3Config,
    host_state: VdafState,
    host_share: VdafMessage,
    peer_share_data: &[u8],
    is_leader: bool,
) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
    let (agg_share, outbound) = match (&config, host_state, host_share) {
        (
            Prio3Config::Count,
            VdafState::Prio3Field64(state),
            VdafMessage::Prio3ShareField64(share),
        ) => {
            let vdaf = Prio3::new_count(2)?;
            let (out_share, outbound) =
                prep_finish_from_shares!(vdaf, state, share, peer_share_data, is_leader);
            let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Histogram { buckets },
            VdafState::Prio3Field128(state),
            VdafMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_histogram(2, buckets)?;
            let (out_share, outbound) =
                prep_finish_from_shares!(vdaf, state, share, peer_share_data, is_leader);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Sum { bits },
            VdafState::Prio3Field128(state),
            VdafMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let (out_share, outbound) =
                prep_finish_from_shares!(vdaf, state, share, peer_share_data, is_leader);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::SumVec { bits, len },
            VdafState::Prio3Field128(state),
            VdafMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            let (out_share, outbound) =
                prep_finish_from_shares!(vdaf, state, share, peer_share_data, is_leader);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        _ => panic!("prio3_prep_finish_from_shares: {ERR_FIELD_TYPE}"),
    };

    Ok((agg_share, outbound))
}

macro_rules! prep_finish {
    (
        $vdaf:ident,
        $host_state:expr,
        $peer_message_data:expr
    ) => {{
        // Decode the prep message.
        let peer_message =
            Prio3PrepareMessage::get_decoded_with_param(&$host_state, $peer_message_data)?;

        // Compute the host's output share.
        match $vdaf.prepare_step($host_state, peer_message)? {
            PrepareTransition::Continue(..) => {
                panic!("prio3_prep_finish: {ERR_EXPECT_FINISH}")
            }
            PrepareTransition::Finish(out_share) => out_share,
        }
    }};
}

/// Consume the peer's prepare message and return an outpprio3_append_prepare_stateut share.
pub(crate) fn prio3_prep_finish(
    config: &Prio3Config,
    host_state: VdafState,
    peer_message_data: &[u8],
) -> Result<VdafAggregateShare, VdafError> {
    let agg_share = match (&config, host_state) {
        (Prio3Config::Count, VdafState::Prio3Field64(state)) => {
            let vdaf = Prio3::new_count(2)?;
            let out_share = prep_finish!(vdaf, state, peer_message_data);
            VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Histogram { buckets }, VdafState::Prio3Field128(host_state)) => {
            let vdaf = Prio3::new_histogram(2, buckets)?;
            let out_share = prep_finish!(vdaf, host_state, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Sum { bits }, VdafState::Prio3Field128(host_state)) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let out_share = prep_finish!(vdaf, host_state, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::SumVec { bits, len }, VdafState::Prio3Field128(host_state)) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            let out_share = prep_finish!(vdaf, host_state, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        _ => panic!("prio3_prep_finish: {ERR_FIELD_TYPE}"),
    };

    Ok(agg_share)
}

/// Interpret `step` as a prepare message for prio3 and append it to `bytes`. Returns an error if
/// the `step` is not compatible with `param`.
pub(crate) fn prio3_append_prep_state(
    bytes: &mut Vec<u8>,
    config: &Prio3Config,
    state: &VdafState,
) -> Result<(), VdafError> {
    match (&config, state) {
        (Prio3Config::Count, VdafState::Prio3Field64(state)) => {
            state.encode(bytes);
        }
        (Prio3Config::Histogram { .. }, VdafState::Prio3Field128(state))
        | (Prio3Config::Sum { .. }, VdafState::Prio3Field128(state))
        | (Prio3Config::SumVec { .. }, VdafState::Prio3Field128(state)) => {
            state.encode(bytes);
        }
        _ => panic!("prio3_append_prepare_state: {ERR_FIELD_TYPE}"),
    }
    Ok(())
}

/// Parse a prio3 prepare message from the front of `reader` whose type is compatible with `param`.
pub(crate) fn prio3_decode_prep_state(
    config: &Prio3Config,
    agg_id: usize,
    bytes: &mut Cursor<&[u8]>,
) -> Result<VdafState, VdafError> {
    match config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_count(2)?;
            Ok(VdafState::Prio3Field64(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3::new_histogram(2, buckets)?;
            Ok(VdafState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            Ok(VdafState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::SumVec { bits, len } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *len)?;
            Ok(VdafState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
    }
}

/// Encode `message` as a byte string.
pub(crate) fn prio3_encode_prep_message(message: &VdafMessage) -> Vec<u8> {
    match message {
        VdafMessage::Prio3ShareField64(message) => message.get_encoded(),
        VdafMessage::Prio3ShareField128(message) => message.get_encoded(),
        _ => panic!("prio3_encode_prepare_message: unexpected message type"),
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
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3::new_histogram(2, buckets)?;
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
