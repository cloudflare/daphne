// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [prio3 VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{
    DapAggregateResult, DapMeasurement, Prio3Config, VdafAggregateShare, VdafMessage, VdafStep,
    VdafVerifyParam,
};
use prio::{
    codec::{CodecError, Encode, ParameterizedDecode},
    vdaf::{
        prio3::{
            Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum, Prio3InputShare,
            Prio3PrepareMessage, Prio3PrepareStep, Prio3VerifyParam,
        },
        AggregateShare, Aggregator, Client, Collector, PrepareTransition, Vdaf, VdafError,
    },
};
use std::{fmt::Debug, io::Cursor};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Prio3Error {
    #[error("Codec error: {0}")]
    Codec(#[from] CodecError),
    #[error("VDAF error: {0}")]
    Vdaf(#[from] VdafError),
}

const ERR_EXPECT_FINISH: &str = "unexpected transition (continued)";
const ERR_EXPECT_CONTINUE: &str = "unexpected transition (finished)";
const ERR_FIELD_TYPE: &str = "unexpected field type for step or message";

pub(crate) fn prio3_get_decoded_verify_param(
    config: &Prio3Config,
    bytes: &[u8],
) -> Result<VdafVerifyParam, Prio3Error> {
    match &config {
        Prio3Config::Count => {
            let vdaf = Prio3Aes128Count::new(2)?;
            Ok(VdafVerifyParam::Prio3(
                Prio3VerifyParam::get_decoded_with_param(&vdaf, bytes)?,
            ))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3Aes128Histogram::new(2, buckets)?;
            Ok(VdafVerifyParam::Prio3(
                Prio3VerifyParam::get_decoded_with_param(&vdaf, bytes)?,
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3Aes128Sum::new(2, *bits)?;
            Ok(VdafVerifyParam::Prio3(
                Prio3VerifyParam::get_decoded_with_param(&vdaf, bytes)?,
            ))
        }
    }
}

macro_rules! setup {
    (
        $vdaf:ident
    ) => {{
        let (_, verify_params) = $vdaf.setup()?;
        let mut verify_params = verify_params.into_iter();
        let leader_verify_param = verify_params.next().unwrap();
        let helper_verify_param = verify_params.next().unwrap();
        (
            VdafVerifyParam::Prio3(leader_verify_param),
            VdafVerifyParam::Prio3(helper_verify_param),
        )
    }};
}

/// Generate verification parameters for the leader and helper.
pub(crate) fn prio3_setup(
    config: &Prio3Config,
) -> Result<(VdafVerifyParam, VdafVerifyParam), Prio3Error> {
    match &config {
        Prio3Config::Count => {
            let vdaf = Prio3Aes128Count::new(2)?;
            Ok(setup!(vdaf))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3Aes128Histogram::new(2, buckets)?;
            Ok(setup!(vdaf))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3Aes128Sum::new(2, *bits)?;
            Ok(setup!(vdaf))
        }
    }
}

macro_rules! shard {
    (
        $vdaf:ident,
        $measurement:expr
    ) => {{
        // Split measurement into input shares.
        let input_shares = $vdaf.shard(&(), $measurement)?;

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
            let vdaf = Prio3Aes128Count::new(2)?;
            Ok(shard!(vdaf, &measurement))
        }
        (Prio3Config::Histogram { buckets }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3Aes128Histogram::new(2, buckets)?;
            Ok(shard!(vdaf, &(measurement as u128)))
        }
        (Prio3Config::Sum { bits }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3Aes128Sum::new(2, *bits)?;
            Ok(shard!(vdaf, &(measurement as u128)))
        }
    }
}

macro_rules! prep_start {
    (
        $vdaf:ident,
        $verify_param:expr,
        $nonce_data:expr,
        $input_share_data:expr
    ) => {{
        // Parse the input share.
        let input_share =
            Prio3InputShare::get_decoded_with_param($verify_param, $input_share_data)?;

        // Run the prepare-init algorithm, returning the initial state.
        let step = $vdaf.prepare_init($verify_param, &(), $nonce_data, &input_share)?;

        // Run the prepare-next algorithm on the initial state.
        match $vdaf.prepare_step(step, None) {
            PrepareTransition::Continue(next_step, msg) => Ok((next_step, msg)),
            PrepareTransition::Finish(..) => {
                panic!("prio3_prepare_start: {}", ERR_EXPECT_CONTINUE)
            }
            PrepareTransition::Fail(err) => Err(err),
        }
    }};
}

/// Consume an input share and return the corresponding VDAF step and message.
pub(crate) fn prio3_prepare_start(
    config: &Prio3Config,
    verify_param: &Prio3VerifyParam<16>,
    nonce_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafStep, VdafMessage), Prio3Error> {
    match &config {
        Prio3Config::Count => {
            let vdaf = Prio3Aes128Count::new(2)?;
            let (step, msg) = prep_start!(vdaf, verify_param, nonce_data, input_share_data)?;
            Ok((VdafStep::Prio3Field64(step), VdafMessage::Prio3Field64(msg)))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3Aes128Histogram::new(2, buckets)?;
            let (step, msg) = prep_start!(vdaf, verify_param, nonce_data, input_share_data)?;
            Ok((
                VdafStep::Prio3Field128(step),
                VdafMessage::Prio3Field128(msg),
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3Aes128Sum::new(2, *bits)?;
            let (step, msg) = prep_start!(vdaf, verify_param, nonce_data, input_share_data)?;
            Ok((
                VdafStep::Prio3Field128(step),
                VdafMessage::Prio3Field128(msg),
            ))
        }
    }
}

macro_rules! leader_prep_fin {
    (
        $vdaf:ident,
        $leader_step:expr,
        $leader_message:expr,
        $helper_message_data:expr
    ) => {{
        // Decode the Helper's inbound message.
        let helper_message =
            Prio3PrepareMessage::get_decoded_with_param(&$leader_step, $helper_message_data)?;

        // Preprocess the inbound messages.
        let verifier = $vdaf.prepare_preprocess([$leader_message, helper_message])?;

        // Encode the leader's outbound message.
        let out_msg = verifier.get_encoded();

        // Compute the leader's output share.
        let out_share = match $vdaf.prepare_step($leader_step, Some(verifier)) {
            PrepareTransition::Continue(..) => {
                panic!("prio3_leader_prepare_finish: {}", ERR_EXPECT_FINISH,)
            }
            PrepareTransition::Finish(out_share) => Ok(out_share),
            PrepareTransition::Fail(err) => Err(err),
        }?;

        (out_share, out_msg)
    }};
}

/// Consume the verifier shares and return the output share and serialized outbound message.
pub(crate) fn prio3_leader_prepare_finish(
    config: &Prio3Config,
    step: VdafStep,
    message: VdafMessage,
    peer_message_data: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), Prio3Error> {
    let (agg_share, outbound_message) = match (&config, step, message) {
        (Prio3Config::Count, VdafStep::Prio3Field64(step), VdafMessage::Prio3Field64(message)) => {
            let vdaf = Prio3Aes128Count::new(2)?;
            let (out_share, out_msg) = leader_prep_fin!(vdaf, step, message, peer_message_data);
            let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
            (agg_share, out_msg)
        }
        (
            Prio3Config::Histogram { buckets },
            VdafStep::Prio3Field128(step),
            VdafMessage::Prio3Field128(message),
        ) => {
            let vdaf = Prio3Aes128Histogram::new(2, buckets)?;
            let (out_share, out_msg) = leader_prep_fin!(vdaf, step, message, peer_message_data);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, out_msg)
        }
        (
            Prio3Config::Sum { bits },
            VdafStep::Prio3Field128(step),
            VdafMessage::Prio3Field128(message),
        ) => {
            let vdaf = Prio3Aes128Sum::new(2, *bits)?;
            let (out_share, out_msg) = leader_prep_fin!(vdaf, step, message, peer_message_data);
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, out_msg)
        }
        _ => panic!("prio3_leader_prepare_finish: {}", ERR_FIELD_TYPE),
    };

    Ok((agg_share, outbound_message))
}

macro_rules! helper_prep_fin {
    (
        $vdaf:ident,
        $helper_step:expr,
        $leader_message_data:expr
    ) => {{
        // Decode the inbound message from the Leader, which contains the preprocessed prepare
        // message.
        let leader_message =
            Prio3PrepareMessage::get_decoded_with_param(&$helper_step, $leader_message_data)?;

        // Compute the Helper's output share.
        let out_share = match $vdaf.prepare_step($helper_step, Some(leader_message)) {
            PrepareTransition::Continue(..) => {
                panic!("prio3_helper_prepare_finish: {}", ERR_EXPECT_FINISH)
            }
            PrepareTransition::Finish(out_share) => Ok(out_share),
            PrepareTransition::Fail(err) => Err(err),
        }?;

        out_share
    }};
}

/// Consume the peer's prepare message and return an output share.
pub(crate) fn prio3_helper_prepare_finish(
    config: &Prio3Config,
    step: VdafStep,
    peer_message_data: &[u8],
) -> Result<VdafAggregateShare, Prio3Error> {
    let data = match (&config, step) {
        (Prio3Config::Count, VdafStep::Prio3Field64(step)) => {
            let vdaf = Prio3Aes128Count::new(2)?;
            let out_share = helper_prep_fin!(vdaf, step, peer_message_data);
            VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Histogram { buckets }, VdafStep::Prio3Field128(step)) => {
            let vdaf = Prio3Aes128Histogram::new(2, buckets)?;
            let out_share = helper_prep_fin!(vdaf, step, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Sum { bits }, VdafStep::Prio3Field128(step)) => {
            let vdaf = Prio3Aes128Sum::new(2, *bits)?;
            let out_share = helper_prep_fin!(vdaf, step, peer_message_data);
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        _ => panic!("prio3_helper_prepare_finish: {}", ERR_FIELD_TYPE),
    };

    Ok(data)
}

/// Interpret `step` as a prepare message for prio3 and append it to `bytes`. Returns an error if
/// the `step` is not compatible with `param`.
pub(crate) fn prio3_append_prepare_step(
    bytes: &mut Vec<u8>,
    config: &Prio3Config,
    step: &VdafStep,
) -> Result<(), Prio3Error> {
    match (&config, step) {
        (Prio3Config::Count, VdafStep::Prio3Field64(step)) => {
            step.encode(bytes);
        }
        (Prio3Config::Histogram { buckets: _ }, VdafStep::Prio3Field128(step))
        | (Prio3Config::Sum { bits: _ }, VdafStep::Prio3Field128(step)) => {
            step.encode(bytes);
        }
        _ => panic!("prio3_append_prepare_step: {}", ERR_FIELD_TYPE),
    }
    Ok(())
}

/// Parse a prio3 prepare message from the front of `reader` whose type is compatible with `param`.
pub(crate) fn prio3_decode_prepare_step(
    config: &Prio3Config,
    verify_param: &Prio3VerifyParam<16>,
    bytes: &mut Cursor<&[u8]>,
) -> Result<VdafStep, Prio3Error> {
    match config {
        Prio3Config::Count => Ok(VdafStep::Prio3Field64(Prio3PrepareStep::decode_with_param(
            verify_param,
            bytes,
        )?)),
        Prio3Config::Histogram { .. } | Prio3Config::Sum { .. } => Ok(VdafStep::Prio3Field128(
            Prio3PrepareStep::decode_with_param(verify_param, bytes)?,
        )),
    }
}

/// Encode `message` as a byte string.
pub(crate) fn prio3_encode_prepare_message(message: &VdafMessage) -> Vec<u8> {
    match message {
        VdafMessage::Prio3Field64(message) => message.get_encoded(),
        VdafMessage::Prio3Field128(message) => message.get_encoded(),
    }
}

macro_rules! unshard {
    (
        $vdaf:ident,
        $agg_shares:expr
    ) => {{
        let mut agg_shares = Vec::with_capacity($vdaf.num_aggregators());
        for data in $agg_shares.into_iter() {
            let agg_share = AggregateShare::get_decoded_with_param(&$vdaf.output_len(), &data)?;
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
            let vdaf = Prio3Aes128Count::new(2)?;
            let agg_res = unshard!(vdaf, agg_shares)?;
            Ok(DapAggregateResult::U64(agg_res.0))
        }
        Prio3Config::Histogram { buckets } => {
            let vdaf = Prio3Aes128Histogram::new(2, buckets)?;
            let agg_res = unshard!(vdaf, agg_shares)?;
            Ok(DapAggregateResult::U64Vec(agg_res.0))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3Aes128Sum::new(2, *bits)?;
            let agg_res = unshard!(vdaf, agg_shares)?;
            Ok(DapAggregateResult::U64(agg_res.0))
        }
    }
}
