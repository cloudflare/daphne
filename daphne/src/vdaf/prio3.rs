// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [Prio3 VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{
    messages::taskprov::VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128,
    vdaf::{xof::XofHmacSha256Aes128, VdafError, VdafVerifyKey},
    DapAggregateResult, DapMeasurement, Prio3Config, VdafAggregateShare, VdafPrepMessage,
    VdafPrepState,
};
use prio::{
    codec::{Encode, ParameterizedDecode},
    field::Field64,
    flp::{
        gadgets::{Mul, ParallelSum},
        types::SumVec,
    },
    vdaf::{
        self,
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

type Prio3SumVecField64MultiproofHmacSha256Aes128 =
    Prio3<SumVec<Field64, ParallelSum<Field64, Mul<Field64>>>, XofHmacSha256Aes128, 32>;

fn new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
    bits: usize,
    length: usize,
    chunk_length: usize,
    num_proofs: u8,
) -> Result<Prio3SumVecField64MultiproofHmacSha256Aes128, VdafError> {
    Ok(Prio3::new(
        2,
        num_proofs,
        VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128,
        SumVec::new(bits, length, chunk_length).map_err(vdaf::VdafError::from)?,
    )?)
}

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
            shard(vdaf, &u128::from(measurement), nonce)
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
        (
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits,
                length,
                chunk_length,
                num_proofs,
            },
            DapMeasurement::U64Vec(measurement),
        ) => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                *bits,
                *length,
                *chunk_length,
                *num_proofs,
            )?;
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
    verify_key: &VdafVerifyKey,
    agg_id: usize,
    nonce: &[u8; 16],
    public_share_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafPrepState, VdafPrepMessage), VdafError> {
    return match (&config, verify_key) {
        (Prio3Config::Count, VdafVerifyKey::Prio3(verify_key)) => {
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
        (
            Prio3Config::Histogram {
                length,
                chunk_length,
            },
            VdafVerifyKey::Prio3(verify_key),
        ) => {
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
        (Prio3Config::Sum { bits }, VdafVerifyKey::Prio3(verify_key)) => {
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
        (
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            },
            VdafVerifyKey::Prio3(verify_key),
        ) => {
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
        (
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits,
                length,
                chunk_length,
                num_proofs,
            },
            VdafVerifyKey::Prio3HmacSha256Aes128(verify_key),
        ) => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                *bits,
                *length,
                *chunk_length,
                *num_proofs,
            )?;
            let (state, share) = prep_init(
                vdaf,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            )?;
            Ok((
                VdafPrepState::Prio3Field64HmacSha256Aes128(state),
                VdafPrepMessage::Prio3ShareField64HmacSha256Aes128(share),
            ))
        }
        _ => panic!("unhandled config and verify key combination"),
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
        (
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits,
                length,
                chunk_length,
                num_proofs,
            },
            VdafPrepState::Prio3Field64HmacSha256Aes128(state),
            VdafPrepMessage::Prio3ShareField64HmacSha256Aes128(share),
        ) => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                *bits,
                *length,
                *chunk_length,
                *num_proofs,
            )?;
            let (out_share, outbound) =
                prep_finish_from_shares(&vdaf, agg_id, state, share, peer_share_data)?;
            let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
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
        (
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits,
                length,
                chunk_length,
                num_proofs,
            },
            VdafPrepState::Prio3Field64HmacSha256Aes128(state),
        ) => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                *bits,
                *length,
                *chunk_length,
                *num_proofs,
            )?;
            let out_share = prep_finish(&vdaf, state, peer_message_data)?;
            VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?)
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
        Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            bits,
            length,
            chunk_length,
            num_proofs,
        } => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                *bits,
                *length,
                *chunk_length,
                *num_proofs,
            )?;
            Ok(VdafPrepState::Prio3Field64HmacSha256Aes128(
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
        Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            bits,
            length,
            chunk_length,
            num_proofs,
        } => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                *bits,
                *length,
                *chunk_length,
                *num_proofs,
            )?;
            let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U64Vec(agg_res))
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
        for data in agg_shares {
            let agg_share = AggregateShare::get_decoded_with_param(&(vdaf, &()), data.as_ref())?;
            agg_shares_vec.push(agg_share);
        }
        Ok(vdaf.unshard(&(), agg_shares_vec, num_measurements)?)
    }
}

#[cfg(test)]
mod test {

    use crate::{
        async_test_versions, hpke::HpkeKemId, testing::AggregationJobTest, DapAggregateResult,
        DapMeasurement, DapVersion, Prio3Config, VdafConfig,
    };

    async fn roundtrip_count(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Count),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t
            .roundtrip(vec![
                DapMeasurement::U64(0),
                DapMeasurement::U64(1),
                DapMeasurement::U64(1),
                DapMeasurement::U64(1),
                DapMeasurement::U64(0),
            ])
            .await;
        assert_eq!(got, DapAggregateResult::U64(3));
    }

    async_test_versions! { roundtrip_count }

    async fn roundtrip_sum(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Sum { bits: 23 }),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t
            .roundtrip(vec![
                DapMeasurement::U64(0),
                DapMeasurement::U64(1),
                DapMeasurement::U64(1337),
                DapMeasurement::U64(4),
                DapMeasurement::U64(0),
            ])
            .await;
        assert_eq!(got, DapAggregateResult::U128(1342));
    }

    async_test_versions! { roundtrip_sum }

    async fn roundtrip_sum_vec(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::SumVec {
                bits: 23,
                length: 2,
                chunk_length: 1,
            }),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t
            .roundtrip(vec![
                DapMeasurement::U128Vec(vec![1337, 0]),
                DapMeasurement::U128Vec(vec![0, 1337]),
                DapMeasurement::U128Vec(vec![1, 1]),
            ])
            .await;
        assert_eq!(got, DapAggregateResult::U128Vec(vec![1338, 1338]));
    }

    async_test_versions! { roundtrip_sum_vec }

    async fn roundtrip_histogram(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Histogram {
                length: 3,
                chunk_length: 1,
            }),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t
            .roundtrip(vec![
                DapMeasurement::U64(0),
                DapMeasurement::U64(1),
                DapMeasurement::U64(2),
                DapMeasurement::U64(2),
                DapMeasurement::U64(2),
            ])
            .await;
        assert_eq!(got, DapAggregateResult::U128Vec(vec![1, 1, 3]));
    }

    async_test_versions! { roundtrip_histogram }

    async fn roundtrip_sum_vec_field64_multiproof_hmac_sha256_aes128(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits: 23,
                length: 2,
                chunk_length: 1,
                num_proofs: 4,
            }),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t
            .roundtrip(vec![
                DapMeasurement::U64Vec(vec![1337, 0]),
                DapMeasurement::U64Vec(vec![0, 1337]),
                DapMeasurement::U64Vec(vec![1, 1]),
            ])
            .await;
        assert_eq!(got, DapAggregateResult::U64Vec(vec![1338, 1338]));
    }

    async_test_versions! { roundtrip_sum_vec_field64_multiproof_hmac_sha256_aes128 }
}
