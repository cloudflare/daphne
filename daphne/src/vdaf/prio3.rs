// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [prio3 VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{
    DapAggregateResult, DapMeasurement, Prio3Config, VdafAggregateShare, VdafMessage, VdafState,
};
use prio::{
    codec::{CodecError, Encode, ParameterizedDecode},
    vdaf::{
        prio3::{
            Prio3, Prio3InputShare, Prio3PrepareMessage, Prio3PrepareShare, Prio3PrepareState,
        },
        AggregateShare, Aggregator, Client, Collector, PrepareTransition, Vdaf, VdafError,
    },
};
use std::{convert::TryFrom, fmt::Debug, io::Cursor};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Prio3Error {
    #[error("Codec error: {0}")]
    Codec(#[from] CodecError),
    #[error("VDAF error: {0}")]
    Vdaf(#[from] VdafError),
}

const ERR_EXPECT_FINISH: &str = "unexpected transition (continued)";
const ERR_FIELD_TYPE: &str = "unexpected field type for step or message";

macro_rules! shard {
    (
        $vdaf:ident,
        $measurement:expr
    ) => {{
        // Split measurement into input shares.
        let input_shares = $vdaf.shard($measurement)?;

        // Encode input shares.
        input_shares
            .iter()
            .map(|input_share| input_share.get_encoded())
            .collect()
    }};
}

/// Split the given measurement into a sequence of encoded input shares.
pub(crate) fn prio3_shard(
    config: &Prio3Config,
    measurement: DapMeasurement,
) -> Result<Vec<Vec<u8>>, Prio3Error> {
    match (&config, measurement) {
        (Prio3Config::Count, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_aes128_count(2)?;
            Ok(shard!(vdaf, &measurement))
        }
        (Prio3Config::Histogram { buckets }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_aes128_histogram(2, buckets)?;
            Ok(shard!(vdaf, &(measurement as u128)))
        }
        (Prio3Config::Sum { bits }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_aes128_sum(2, *bits)?;
            Ok(shard!(vdaf, &(measurement as u128)))
        }
    }
}

macro_rules! prep_start {
    (
        $vdaf:ident,
        $verify_key:expr,
        $agg_id:expr,
        $nonce_data:expr,
        $input_share_data:expr
    ) => {{
        // Parse the input share.
        let input_share =
            Prio3InputShare::get_decoded_with_param(&(&$vdaf, $agg_id), $input_share_data)?;

        // Run the prepare-init algorithm, returning the initial state.
        $vdaf.prepare_init($verify_key, $agg_id, &(), $nonce_data, &input_share)?
    }};
}

/// Consume an input share and return the corresponding VDAF step and message.
pub(crate) fn prio3_prepare_start(
    config: &Prio3Config,
    verify_key: &[u8; 16],
    agg_id: usize,
    nonce_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafState, VdafMessage), Prio3Error> {
    match &config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_aes128_count(2)?;
            let (state, share) =
                prep_start!(vdaf, verify_key, agg_id, nonce_data, input_share_data);
            Ok((
                VdafState::Prio3Field64(state),
                VdafMessage::Prio3ShareField64(share),
            ))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3::new_aes128_histogram(2, buckets)?;
            let (state, share) =
                prep_start!(vdaf, verify_key, agg_id, nonce_data, input_share_data);
            Ok((
                VdafState::Prio3Field128(state),
                VdafMessage::Prio3ShareField128(share),
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_aes128_sum(2, *bits)?;
            let (state, share) =
                prep_start!(vdaf, verify_key, agg_id, nonce_data, input_share_data);
            Ok((
                VdafState::Prio3Field128(state),
                VdafMessage::Prio3ShareField128(share),
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
                panic!("prio3_leader_prepare_finish: {}", ERR_EXPECT_FINISH)
            }
            PrepareTransition::Finish(out_share) => (out_share, message_data),
        }
    }};
}

/// Consume the verifier shares and return the output share and serialized outbound message.
pub(crate) fn prio3_leader_prepare_finish(
    config: &Prio3Config,
    leader_state: VdafState,
    leader_share: VdafMessage,
    helper_share_data: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), Prio3Error> {
    let (agg_share, outbound) = match (&config, leader_state, leader_share) {
        (
            Prio3Config::Count,
            VdafState::Prio3Field64(state),
            VdafMessage::Prio3ShareField64(share),
        ) => {
            let vdaf = Prio3::new_aes128_count(2)?;
            let (out_share, outbound) = leader_prep_fin!(vdaf, state, share, helper_share_data);
            let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Histogram { buckets },
            VdafState::Prio3Field128(state),
            VdafMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_aes128_histogram(2, buckets)?;
            let (out_share, outbound) = leader_prep_fin!(vdaf, state, share, helper_share_data);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Sum { bits },
            VdafState::Prio3Field128(state),
            VdafMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_aes128_sum(2, *bits)?;
            let (out_share, outbound) = leader_prep_fin!(vdaf, state, share, helper_share_data);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        _ => panic!("prio3_leader_prepare_finish: {}", ERR_FIELD_TYPE),
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
                panic!("prio3_helper_prepare_finish: {}", ERR_EXPECT_FINISH)
            }
            PrepareTransition::Finish(out_share) => out_share,
        }
    }};
}

/// Consume the peer's prepare message and return an output share.
pub(crate) fn prio3_helper_prepare_finish(
    config: &Prio3Config,
    state: VdafState,
    peer_message_data: &[u8],
) -> Result<VdafAggregateShare, Prio3Error> {
    let data = match (&config, state) {
        (Prio3Config::Count, VdafState::Prio3Field64(state)) => {
            let vdaf = Prio3::new_aes128_count(2)?;
            let out_share = helper_prep_fin!(vdaf, state, peer_message_data);
            VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Histogram { buckets }, VdafState::Prio3Field128(state)) => {
            let vdaf = Prio3::new_aes128_histogram(2, buckets)?;
            let out_share = helper_prep_fin!(vdaf, state, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Sum { bits }, VdafState::Prio3Field128(state)) => {
            let vdaf = Prio3::new_aes128_sum(2, *bits)?;
            let out_share = helper_prep_fin!(vdaf, state, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        _ => panic!("prio3_helper_prepare_finish: {}", ERR_FIELD_TYPE),
    };

    Ok(data)
}

/// Interpret `step` as a prepare message for prio3 and append it to `bytes`. Returns an error if
/// the `step` is not compatible with `param`.
pub(crate) fn prio3_append_prepare_state(
    bytes: &mut Vec<u8>,
    config: &Prio3Config,
    state: &VdafState,
) -> Result<(), Prio3Error> {
    match (&config, state) {
        (Prio3Config::Count, VdafState::Prio3Field64(state)) => {
            state.encode(bytes);
        }
        (Prio3Config::Histogram { buckets: _ }, VdafState::Prio3Field128(state))
        | (Prio3Config::Sum { bits: _ }, VdafState::Prio3Field128(state)) => {
            state.encode(bytes);
        }
        _ => panic!("prio3_append_prepare_state: {}", ERR_FIELD_TYPE),
    }
    Ok(())
}

/// Parse a prio3 prepare message from the front of `reader` whose type is compatible with `param`.
pub(crate) fn prio3_decode_prepare_state(
    config: &Prio3Config,
    agg_id: usize,
    bytes: &mut Cursor<&[u8]>,
) -> Result<VdafState, Prio3Error> {
    match config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_aes128_count(2)?;
            Ok(VdafState::Prio3Field64(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3::new_aes128_histogram(2, buckets)?;
            Ok(VdafState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_aes128_sum(2, *bits)?;
            Ok(VdafState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
    }
}

/// Encode `message` as a byte string.
pub(crate) fn prio3_encode_prepare_message(message: &VdafMessage) -> Vec<u8> {
    match message {
        VdafMessage::Prio3ShareField64(message) => message.get_encoded(),
        VdafMessage::Prio3ShareField128(message) => message.get_encoded(),
    }
}

macro_rules! unshard {
    (
        $vdaf:ident,
        $agg_shares:expr
    ) => {{
        let mut agg_shares = Vec::with_capacity($vdaf.num_aggregators());
        for data in $agg_shares.into_iter() {
            let agg_share = AggregateShare::try_from(data.as_ref())
                .map_err(|e| CodecError::Other(Box::new(e)))?;
            agg_shares.push(agg_share)
        }
        $vdaf.unshard(&(), agg_shares)
    }};
}

/// Interpret `agg_shares` as a sequence of encoded aggregate shares and unshard them.
pub(crate) fn prio3_unshard<M: IntoIterator<Item = Vec<u8>>>(
    config: &Prio3Config,
    agg_shares: M,
) -> Result<DapAggregateResult, Prio3Error> {
    match &config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_aes128_count(2)?;
            let agg_res = unshard!(vdaf, agg_shares)?;
            Ok(DapAggregateResult::U64(agg_res))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3::new_aes128_histogram(2, buckets)?;
            let agg_res = unshard!(vdaf, agg_shares)?;
            Ok(DapAggregateResult::U128Vec(agg_res))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_aes128_sum(2, *bits)?;
            let agg_res = unshard!(vdaf, agg_shares)?;
            Ok(DapAggregateResult::U128(agg_res))
        }
    }
}
