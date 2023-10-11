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
        AggregateShare, Aggregator, Client, Collector, OutputShare, PrepareTransition, Vdaf,
    },
};
use std::io::Cursor;

const ERR_EXPECT_FINISH: &str = "unexpected transition (continued)";
const ERR_FIELD_TYPE: &str = "unexpected field type for step or message";

/// Split the given measurement into a sequence of encoded input shares.
pub(crate) fn prio3_shard(
    config: &Prio3Config,
    measurement: DapMeasurement,
    nonce: &[u8; 16],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), VdafError> {
    return match (&config, measurement) {
        (Prio3Config::Count, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_count(2)?;
            shard(vdaf, &measurement, nonce)
        }
        (
            Prio3Config::Histogram {
                length,
                chunk_length,
            },
            DapMeasurement::U64(measurement),
        ) => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)?;
            let m: usize = measurement.try_into().unwrap();
            shard(vdaf, &m, nonce)
        }
        (Prio3Config::Sum { bits }, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            shard(vdaf, &(measurement as u128), nonce)
        }
        (
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            },
            DapMeasurement::U128Vec(measurement),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)?;
            shard(vdaf, &measurement, nonce)
        }
        _ => panic!("prio3_shard: unexpected VDAF config {config:?}"),
    };

    fn shard<T, P, const SEED_SIZE: usize>(
        vdaf: Prio3<T, P, SEED_SIZE>,
        measurement: &T::Measurement,
        nonce: &[u8; 16],
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), VdafError>
    where
        T: prio::flp::Type,
        P: prio::vdaf::xof::Xof<SEED_SIZE>,
    {
        // Split measurement into input shares.
        let (public_share, input_shares) = vdaf.shard(measurement, nonce)?;

        Ok((
            public_share.get_encoded(),
            input_shares
                .iter()
                .map(|input_share| input_share.get_encoded())
                .collect(),
        ))
    }
}

/// Consume an input share and return the corresponding VDAF step and message.
pub(crate) fn prio3_prep_init(
    config: &Prio3Config,
    verify_key: &[u8; 16],
    agg_id: usize,
    nonce: &[u8; 16],
    public_share_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafPrepState, VdafPrepMessage), VdafError> {
    return match &config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_count(2)?;
            let (state, share) = prep_init(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            )?;
            Ok((
                VdafPrepState::Prio3Field64(state),
                VdafPrepMessage::Prio3ShareField64(share),
            ))
        }
        Prio3Config::Histogram {
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)?;
            let (state, share) = prep_init(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            )?;
            Ok((
                VdafPrepState::Prio3Field128(state),
                VdafPrepMessage::Prio3ShareField128(share),
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let (state, share) = prep_init(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            )?;
            Ok((
                VdafPrepState::Prio3Field128(state),
                VdafPrepMessage::Prio3ShareField128(share),
            ))
        }
        Prio3Config::SumVec {
            bits,
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)?;
            let (state, share) = prep_init(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            )?;
            Ok((
                VdafPrepState::Prio3Field128(state),
                VdafPrepMessage::Prio3ShareField128(share),
            ))
        }
    };

    type Prio3Prepared<T, const SEED_SIZE: usize> = (
        Prio3PrepareState<<T as prio::flp::Type>::Field, SEED_SIZE>,
        Prio3PrepareShare<<T as prio::flp::Type>::Field, SEED_SIZE>,
    );

    fn prep_init<T, P, const SEED_SIZE: usize>(
        vdaf: Prio3<T, P, SEED_SIZE>,
        verify_key: &[u8; SEED_SIZE],
        agg_id: usize,
        nonce: &[u8; 16],
        public_share_data: &[u8],
        input_share_data: &[u8],
    ) -> Result<Prio3Prepared<T, SEED_SIZE>, VdafError>
    where
        T: prio::flp::Type,
        P: prio::vdaf::xof::Xof<SEED_SIZE>,
    {
        // Parse the public share.
        let public_share = Prio3PublicShare::get_decoded_with_param(&vdaf, public_share_data)?;

        // Parse the input share.
        let input_share =
            Prio3InputShare::get_decoded_with_param(&(&vdaf, agg_id), input_share_data)?;

        // Run the prepare-init algorithm, returning the initial state.
        Ok(vdaf.prepare_init(verify_key, agg_id, &(), nonce, &public_share, &input_share)?)
    }
}

/// Consume the prep shares and return our output share and the prep message.
pub(crate) fn prio3_prep_finish_from_shares(
    config: &Prio3Config,
    agg_id: usize,
    host_state: VdafPrepState,
    host_share: VdafPrepMessage,
    peer_share_data: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
    let (agg_share, outbound) = match (&config, host_state, host_share) {
        (
            Prio3Config::Count,
            VdafPrepState::Prio3Field64(state),
            VdafPrepMessage::Prio3ShareField64(share),
        ) => {
            let vdaf = Prio3::new_count(2)?;
            let (out_share, outbound) =
                prep_finish_from_shares(&vdaf, agg_id, state, share, peer_share_data)?;
            let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Histogram {
                length,
                chunk_length,
            },
            VdafPrepState::Prio3Field128(state),
            VdafPrepMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)?;
            let (out_share, outbound) =
                prep_finish_from_shares(&vdaf, agg_id, state, share, peer_share_data)?;
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Sum { bits },
            VdafPrepState::Prio3Field128(state),
            VdafPrepMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let (out_share, outbound) =
                prep_finish_from_shares(&vdaf, agg_id, state, share, peer_share_data)?;
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            },
            VdafPrepState::Prio3Field128(state),
            VdafPrepMessage::Prio3ShareField128(share),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)?;
            let (out_share, outbound) =
                prep_finish_from_shares(&vdaf, agg_id, state, share, peer_share_data)?;
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        _ => panic!("prio3_prep_finish_from_shares: {ERR_FIELD_TYPE}"),
    };

    return Ok((agg_share, outbound));

    fn prep_finish_from_shares<T, P, const SEED_SIZE: usize>(
        vdaf: &Prio3<T, P, SEED_SIZE>,
        agg_id: usize,
        host_state: Prio3PrepareState<T::Field, SEED_SIZE>,
        host_share: Prio3PrepareShare<T::Field, SEED_SIZE>,
        peer_share_data: &[u8],
    ) -> Result<(OutputShare<T::Field>, Vec<u8>), VdafError>
    where
        T: prio::flp::Type,
        P: prio::vdaf::xof::Xof<SEED_SIZE>,
    {
        // Decode the Helper's inbound message.
        let peer_share = Prio3PrepareShare::get_decoded_with_param(&host_state, peer_share_data)?;

        // Preprocess the inbound messages.
        let message = vdaf.prepare_shares_to_prepare_message(
            &(),
            if agg_id == 0 {
                [host_share, peer_share]
            } else {
                [peer_share, host_share]
            },
        )?;
        let message_data = message.get_encoded();

        // Compute the host's output share.
        match vdaf.prepare_next(host_state, message)? {
            PrepareTransition::Continue(..) => {
                panic!("prio3_prep_finish_from_shares: {ERR_EXPECT_FINISH}")
            }
            PrepareTransition::Finish(out_share) => Ok((out_share, message_data)),
        }
    }
}

/// Consume the prep message and output our output share.
pub(crate) fn prio3_prep_finish(
    config: &Prio3Config,
    host_state: VdafPrepState,
    peer_message_data: &[u8],
) -> Result<VdafAggregateShare, VdafError> {
    let agg_share = match (&config, host_state) {
        (Prio3Config::Count, VdafPrepState::Prio3Field64(state)) => {
            let vdaf = Prio3::new_count(2)?;
            let out_share = prep_finish(&vdaf, state, peer_message_data)?;
            VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?)
        }
        (
            Prio3Config::Histogram {
                length,
                chunk_length,
            },
            VdafPrepState::Prio3Field128(state),
        ) => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)?;
            let out_share = prep_finish(&vdaf, state, peer_message_data)?;
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Sum { bits }, VdafPrepState::Prio3Field128(state)) => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let out_share = prep_finish(&vdaf, state, peer_message_data)?;
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            },
            VdafPrepState::Prio3Field128(state),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)?;
            let out_share = prep_finish(&vdaf, state, peer_message_data)?;
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        _ => panic!("prio3_prep_finish: {ERR_FIELD_TYPE}"),
    };

    return Ok(agg_share);

    fn prep_finish<T, P, const SEED_SIZE: usize>(
        vdaf: &Prio3<T, P, SEED_SIZE>,
        helper_state: Prio3PrepareState<T::Field, SEED_SIZE>,
        leader_message_data: &[u8],
    ) -> Result<OutputShare<T::Field>, VdafError>
    where
        T: prio::flp::Type,
        P: prio::vdaf::xof::Xof<SEED_SIZE>,
    {
        // Decode the inbound message from the Leader, which contains the preprocessed prepare
        // message.
        let leader_message =
            Prio3PrepareMessage::get_decoded_with_param(&helper_state, leader_message_data)?;

        // Compute the Helper's output share.
        match vdaf.prepare_next(helper_state, leader_message)? {
            PrepareTransition::Continue(..) => {
                panic!("prio3_prep_finish: {ERR_EXPECT_FINISH}")
            }
            PrepareTransition::Finish(out_share) => Ok(out_share),
        }
    }
}

/// Parse our prep state.
pub(crate) fn prio3_decode_prep_state(
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
        Prio3Config::Histogram {
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)?;
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
        Prio3Config::SumVec {
            bits,
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)?;
            Ok(VdafPrepState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
    }
}

/// Interpret `agg_shares` as a sequence of encoded aggregate shares and unshard them.
pub(crate) fn prio3_unshard<M: IntoIterator<Item = Vec<u8>>>(
    config: &Prio3Config,
    num_measurements: usize,
    agg_shares: M,
) -> Result<DapAggregateResult, VdafError> {
    return match &config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_count(2)?;
            let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U64(agg_res))
        }
        Prio3Config::Histogram {
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)?;
            let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U128Vec(agg_res))
        }
        Prio3Config::Sum { bits } => {
            let vdaf = Prio3::new_sum(2, *bits)?;
            let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U128(agg_res))
        }
        Prio3Config::SumVec {
            bits,
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)?;
            let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U128Vec(agg_res))
        }
    };

    fn unshard<T, P, M, const SEED_SIZE: usize>(
        vdaf: &Prio3<T, P, SEED_SIZE>,
        num_measurements: usize,
        agg_shares: M,
    ) -> Result<T::AggregateResult, VdafError>
    where
        T: prio::flp::Type,
        P: prio::vdaf::xof::Xof<SEED_SIZE>,
        M: IntoIterator<Item = Vec<u8>>,
    {
        let mut agg_shares_vec = Vec::with_capacity(vdaf.num_aggregators());
        for data in agg_shares.into_iter() {
            let agg_share = AggregateShare::get_decoded_with_param(&(vdaf, &()), data.as_ref())?;
            agg_shares_vec.push(agg_share)
        }
        Ok(vdaf.unshard(&(), agg_shares_vec, num_measurements)?)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        vdaf::{
            prio3::{
                prio3_prep_finish, prio3_prep_finish_from_shares, prio3_prep_init, prio3_shard,
                prio3_unshard,
            },
            VdafError,
        },
        DapAggregateResult, DapMeasurement, Prio3Config,
    };
    use prio::codec::Encode;
    use rand::prelude::*;

    #[test]
    fn prep_count() {
        test_prep(
            &Prio3Config::Count,
            DapMeasurement::U64(0),
            DapAggregateResult::U64(0),
        )
        .unwrap();
    }

    #[test]
    fn prep_sum() {
        test_prep(
            &Prio3Config::Sum { bits: 23 },
            DapMeasurement::U64(1337),
            DapAggregateResult::U128(1337),
        )
        .unwrap();
    }

    #[test]
    fn prep_histogram() {
        test_prep(
            &Prio3Config::Histogram {
                length: 3,
                chunk_length: 1,
            },
            DapMeasurement::U64(2),
            DapAggregateResult::U128Vec(vec![0, 0, 1]),
        )
        .unwrap();
    }

    #[test]
    fn prep_sum_vec() {
        test_prep(
            &Prio3Config::SumVec {
                bits: 23,
                length: 1,
                chunk_length: 1,
            },
            DapMeasurement::U128Vec(vec![(1 << 23) - 1]),
            DapAggregateResult::U128Vec(vec![(1 << 23) - 1]),
        )
        .unwrap();

        test_prep(
            &Prio3Config::SumVec {
                bits: 23,
                length: 3,
                chunk_length: 1,
            },
            DapMeasurement::U128Vec(vec![1, 0, 42]),
            DapAggregateResult::U128Vec(vec![1, 0, 42]),
        )
        .unwrap();
    }

    fn test_prep(
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
        let (leader_state, leader_share) = prio3_prep_init(
            config,
            &verify_key,
            0,
            &nonce,
            &encoded_public_share,
            &encoded_input_shares[0],
        )?;

        let (helper_state, helper_share) = prio3_prep_init(
            config,
            &verify_key,
            1,
            &nonce,
            &encoded_public_share,
            &encoded_input_shares[1],
        )?;

        let (leader_out_share, message_data) = prio3_prep_finish_from_shares(
            config,
            0,
            leader_state,
            leader_share.clone(),
            &helper_share.get_encoded(),
        )?;

        // If the Helper completes preparation, then the it should compute the same message.
        {
            let (_helper_out_share, other_message_data) = prio3_prep_finish_from_shares(
                config,
                1,
                helper_state.clone(),
                helper_share,
                &leader_share.get_encoded(),
            )?;

            assert_eq!(message_data, other_message_data);
        }

        let helper_out_share = prio3_prep_finish(config, helper_state, &message_data)?;

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
}
