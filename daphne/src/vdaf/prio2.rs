// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Prio2, the Prio-based construction used in ENPA. This is not a standard
//! [VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{
    vdaf::VdafError, DapAggregateResult, DapMeasurement, VdafAggregateShare, VdafMessage, VdafState,
};
use prio::{
    codec::{CodecError, Decode, Encode, ParameterizedDecode},
    field::FieldPrio2,
    vdaf::{
        prio2::{Prio2, Prio2PrepareShare, Prio2PrepareState},
        AggregateShare, Aggregator, Client, Collector, PrepareTransition, Share, Vdaf,
    },
};
use std::{convert::TryFrom, io::Cursor};

/// Split the given measurement into a sequence of encoded input shares.
pub(crate) fn prio2_shard(
    dimension: u32,
    measurement: DapMeasurement,
) -> Result<Vec<Vec<u8>>, VdafError> {
    let vdaf = Prio2::new(dimension as usize)?;
    let (_public_share, input_shares) = match measurement {
        DapMeasurement::U32Vec(ref data) => vdaf.shard(data)?,
        _ => panic!("prio2_shard: unexpected measurement type"),
    };

    Ok(input_shares
        .iter()
        .map(|input_share| input_share.get_encoded())
        .collect())
}

/// Consume an input share and return the corresponding VDAF step and message.
pub(crate) fn prio2_prepare_init(
    dimension: u32,
    verify_key: &[u8; 32],
    agg_id: usize,
    nonce_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafState, VdafMessage), VdafError> {
    let vdaf = Prio2::new(dimension as usize)?;
    let input_share: Share<FieldPrio2, 32> =
        Share::get_decoded_with_param(&(&vdaf, agg_id), input_share_data)?;
    let (state, share) =
        vdaf.prepare_init(verify_key, agg_id, &(), nonce_data, &(), &input_share)?;
    Ok((VdafState::Prio2(state), VdafMessage::Prio2Share(share)))
}

/// Consume the verifier shares and return the output share and serialized outbound message.
pub(crate) fn prio2_leader_prepare_finish(
    dimension: u32,
    leader_state: VdafState,
    leader_share: VdafMessage,
    helper_share_data: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
    let vdaf = Prio2::new(dimension as usize)?;
    let (out_share, outbound) = match (leader_state, leader_share) {
        (VdafState::Prio2(state), VdafMessage::Prio2Share(share)) => {
            let helper_share =
                Prio2PrepareShare::get_decoded_with_param(&state, helper_share_data)?;
            vdaf.prepare_preprocess([share, helper_share])?;
            match vdaf.prepare_step(state, ())? {
                PrepareTransition::Continue(..) => {
                    panic!("prio2_leader_prepare_finish: unexpected transition (continued)")
                }
                PrepareTransition::Finish(out_share) => (out_share, Vec::new()),
            }
        }
        _ => panic!("prio2_leader_preapre_finish: leader state does not match share"),
    };
    let agg_share = VdafAggregateShare::FieldPrio2(vdaf.aggregate(&(), [out_share])?);
    Ok((agg_share, outbound))
}

/// Consume the peer's prepare message and return an output share.
pub(crate) fn prio2_helper_prepare_finish(
    dimension: u32,
    helper_state: VdafState,
    leader_message_data: &[u8],
) -> Result<VdafAggregateShare, VdafError> {
    let vdaf = Prio2::new(dimension as usize)?;
    <()>::get_decoded(leader_message_data)?;
    let out_share = match helper_state {
        VdafState::Prio2(state) => match vdaf.prepare_step(state, ())? {
            PrepareTransition::Continue(..) => {
                panic!("prio2_helper_prepare_finish: unexpected transition (continued)")
            }
            PrepareTransition::Finish(out_share) => out_share,
        },
        _ => panic!("prio2_helper_prepare_finish: unexpected helper state type"),
    };
    let agg_share = VdafAggregateShare::FieldPrio2(vdaf.aggregate(&(), [out_share])?);
    Ok(agg_share)
}

/// Parse a prio2 prepare message from the front of `reader` whose type is compatible with `param`.
pub(crate) fn prio2_decode_prepare_state(
    dimension: u32,
    agg_id: usize,
    bytes: &mut Cursor<&[u8]>,
) -> Result<VdafState, VdafError> {
    let vdaf = Prio2::new(dimension as usize)?;
    Ok(VdafState::Prio2(Prio2PrepareState::decode_with_param(
        &(&vdaf, agg_id),
        bytes,
    )?))
}

/// Encode `message` as a byte string.
pub(crate) fn prio2_encode_prepare_message(message: &VdafMessage) -> Vec<u8> {
    match message {
        VdafMessage::Prio2Share(message) => message.get_encoded(),
        _ => panic!("prio2_encode_prepare_message: unexpected message type"),
    }
}

/// Interpret `encoded_agg_shares` as a sequence of encoded aggregate shares and unshard them.
pub(crate) fn prio2_unshard<M: IntoIterator<Item = Vec<u8>>>(
    dimension: u32,
    num_measurements: usize,
    encoded_agg_shares: M,
) -> Result<DapAggregateResult, VdafError> {
    let vdaf = Prio2::new(dimension as usize)?;
    let mut agg_shares = Vec::with_capacity(vdaf.num_aggregators());
    for encoded in encoded_agg_shares.into_iter() {
        let agg_share = AggregateShare::try_from(encoded.as_ref())
            .map_err(|e| CodecError::Other(Box::new(e)))?;
        agg_shares.push(agg_share)
    }
    let agg_res = vdaf.unshard(&(), agg_shares, num_measurements)?;
    Ok(DapAggregateResult::U32Vec(agg_res))
}
