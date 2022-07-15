// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [prio2 VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{DapAggregateResult, DapMeasurement, VdafAggregateShare, VdafMessage, VdafState};
use prio::{
    codec::{CodecError, Encode, ParameterizedDecode},
    field::FieldPrio2,
    vdaf::{
        prio2::{Prio2, Prio2PrepareShare, Prio2PrepareState},
        AggregateShare, Aggregator, Client, Collector, PrepareTransition, Share, Vdaf, VdafError,
    },
};
use std::{convert::TryFrom, fmt::Debug, io::Cursor};

// XXX Unify error handling for VDAFs
#[derive(Debug, thiserror::Error)]
pub(crate) enum Prio2Error {
    #[error("Codec error: {0}")]
    Codec(#[from] CodecError),
    #[error("{0}")]
    Vdaf(#[from] VdafError),
}

// XXX De-dup
const ERR_EXPECT_FINISH: &str = "unexpected transition (continued)";

/// Split the given measurement into a sequence of encoded input shares.
pub(crate) fn prio2_shard(
    input_len: u32,
    measurement: DapMeasurement,
) -> Result<Vec<Vec<u8>>, Prio2Error> {
    let vdaf = Prio2::new(input_len as usize)?;
    let input_shares = match measurement {
        DapMeasurement::U32Vec(ref data) => vdaf.shard(data)?,
        _ => panic!("XXX edge case"),
    };

    Ok(input_shares
        .iter()
        .map(|input_share| input_share.get_encoded())
        .collect())
}

/// Consume an input share and return the corresponding VDAF step and message.
pub(crate) fn prio2_prepare_init(
    input_len: u32,
    verify_key: &[u8; 32],
    agg_id: usize,
    nonce_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafState, VdafMessage), Prio2Error> {
    let vdaf = Prio2::new(input_len as usize)?;
    let input_share: Share<FieldPrio2, 32> =
        Share::get_decoded_with_param(&(&vdaf, agg_id), input_share_data)?;
    let (state, share) = vdaf.prepare_init(verify_key, agg_id, &(), nonce_data, &input_share)?;
    Ok((VdafState::Prio2(state), VdafMessage::Prio2Share(share)))
}

/// Consume the verifier shares and return the output share and serialized outbound message.
pub(crate) fn prio2_leader_prepare_finish(
    input_len: u32,
    leader_state: VdafState,
    leader_share: VdafMessage,
    helper_share_data: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), Prio2Error> {
    let vdaf = Prio2::new(input_len as usize)?;
    let (out_share, outbound) = match (leader_state, leader_share) {
        (VdafState::Prio2(state), VdafMessage::Prio2Share(share)) => {
            let helper_share =
                Prio2PrepareShare::get_decoded_with_param(&state, &helper_share_data)?;

            let message = vdaf.prepare_preprocess([share, helper_share])?;
            let message_data = message.get_encoded();

            match vdaf.prepare_step(state, message)? {
                PrepareTransition::Continue(..) => {
                    panic!("prio2_leader_prepare_finish: {}", ERR_EXPECT_FINISH)
                }
                PrepareTransition::Finish(out_share) => (out_share, message_data),
            }
        }
        _ => panic!("XXX edge case"),
    };
    let agg_share = VdafAggregateShare::FieldPrio2(vdaf.aggregate(&(), [out_share])?);
    Ok((agg_share, outbound))
}

/// Consume the peer's prepare message and return an output share.
pub(crate) fn prio2_helper_prepare_finish(
    input_len: u32,
    helper_state: VdafState,
    leader_message_data: &[u8],
) -> Result<VdafAggregateShare, Prio2Error> {
    let vdaf = Prio2::new(input_len as usize)?;
    let out_share = match helper_state {
        VdafState::Prio2(state) => {
            assert_eq!(leader_message_data.len(), 0); // XXX Return erro rinstead of panic
            match vdaf.prepare_step(state, ())? {
                PrepareTransition::Continue(..) => {
                    panic!("prio2_helper_prepare_finish: {}", ERR_EXPECT_FINISH)
                }
                PrepareTransition::Finish(out_share) => (out_share),
            }
        }
        _ => panic!("XXX edge case"),
    };
    let agg_share = VdafAggregateShare::FieldPrio2(vdaf.aggregate(&(), [out_share])?);
    Ok(agg_share)
}

/// Interpret `step` as a prepare message for prio2 and append it to `bytes`. Returns an error if
/// the `step` is not compatible with `param`.
pub(crate) fn prio2_append_prepare_state(
    bytes: &mut Vec<u8>,
    _input_len: u32, // XXX
    state: &VdafState,
) -> Result<(), Prio2Error> {
    match state {
        VdafState::Prio2(state) => state.encode(bytes),
        _ => panic!("XXX edge case"),
    }
    Ok(())
}

/// Parse a prio2 prepare message from the front of `reader` whose type is compatible with `param`.
pub(crate) fn prio2_decode_prepare_state(
    input_len: u32,
    agg_id: usize,
    bytes: &mut Cursor<&[u8]>,
) -> Result<VdafState, Prio2Error> {
    let vdaf = Prio2::new(input_len as usize)?;
    Ok(VdafState::Prio2(Prio2PrepareState::decode_with_param(
        &(&vdaf, agg_id),
        bytes,
    )?))
}

/// Encode `message` as a byte string.
pub(crate) fn prio2_encode_prepare_message(message: &VdafMessage) -> Vec<u8> {
    match message {
        VdafMessage::Prio2Share(message) => message.get_encoded(),
        _ => panic!("XXX edge case"),
    }
}

/// Interpret `encoded_agg_shares` as a sequence of encoded aggregate shares and unshard them.
pub(crate) fn prio2_unshard<M: IntoIterator<Item = Vec<u8>>>(
    input_len: u32,
    encoded_agg_shares: M,
) -> Result<DapAggregateResult, Prio2Error> {
    let vdaf = Prio2::new(input_len as usize)?;
    let mut agg_shares = Vec::with_capacity(vdaf.num_aggregators());
    for encoded in encoded_agg_shares.into_iter() {
        let agg_share = AggregateShare::try_from(encoded.as_ref())
            .map_err(|e| CodecError::Other(Box::new(e)))?;
        agg_shares.push(agg_share)
    }
    let agg_res = vdaf.unshard(&(), agg_shares)?;
    Ok(DapAggregateResult::U32Vec(agg_res))
}
