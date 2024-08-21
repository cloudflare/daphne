// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [Prio3 VDAF](https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/).

use crate::{
    fatal_error,
    messages::taskprov::VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128,
    vdaf::{VdafError, VdafVerifyKey},
    DapAggregateResult, DapMeasurement, Prio3Config, VdafAggregateShare, VdafPrepMessage,
    VdafPrepState,
};
use prio::{
    codec::ParameterizedDecode,
    field::Field64,
    flp::{
        gadgets::{Mul, ParallelSum},
        types::SumVec,
    },
    vdaf::{
        prio3::{Prio3, Prio3InputShare, Prio3PrepareShare, Prio3PrepareState, Prio3PublicShare},
        xof::XofHmacSha256Aes128,
        Aggregator,
    },
};
use std::io::Cursor;

use super::{prep_finish, prep_finish_from_shares, shard_then_encode, unshard};

const ERR_FIELD_TYPE: &str = "unexpected field type for step or message";

type Prio3SumVecField64MultiproofHmacSha256Aes128 =
    Prio3<SumVec<Field64, ParallelSum<Field64, Mul<Field64>>>, XofHmacSha256Aes128, 32>;

fn new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
    bits: usize,
    length: usize,
    chunk_length: usize,
    num_proofs: u8,
) -> Result<Prio3SumVecField64MultiproofHmacSha256Aes128, VdafError> {
    Prio3::new(
        2,
        num_proofs,
        VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128,
        SumVec::new(bits, length, chunk_length).map_err(|e| {
            VdafError::Dap(fatal_error!(
                err = ?e,
                "failed to create sum vec from bits({bits}), length({length}), chunk_length({chunk_length})"
            ))
        })?,
    )
    .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3")))
}

/// Split the given measurement into a sequence of encoded input shares.
pub(crate) fn prio3_shard(
    config: &Prio3Config,
    measurement: DapMeasurement,
    nonce: &[u8; 16],
) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
    match (config, measurement) {
        (Prio3Config::Count, DapMeasurement::U64(measurement)) => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 count from num_aggregators(2)"),
                )
            })?;
            // TODO(cjpatton) Make this constant time.
            let measurement = match measurement {
                0 => false,
                1 => true,
                _ => {
                    return Err(VdafError::Dap(fatal_error!(
                        err = "cannot represent measurement as a 0 or 1"
                    )))
                }
            };
            shard_then_encode(&vdaf, &measurement, nonce)
        }
        (
            Prio3Config::Histogram {
                length,
                chunk_length,
            },
            DapMeasurement::U64(measurement),
        ) => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 Histogram from num_aggregators(2), length({length}), chunk_length({chunk_length})")))?;
            let m: usize = measurement.try_into().unwrap();
            shard_then_encode(&vdaf, &m, nonce)
        }
        (Prio3Config::Sum { bits }, DapMeasurement::U64(measurement)) => {
            let vdaf =
                Prio3::new_sum(2, *bits).map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum from num_aggregators(2), bits({bits})")))?;
            shard_then_encode(&vdaf, &u128::from(measurement), nonce)
        }
        (
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            },
            DapMeasurement::U128Vec(measurement),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum vec from num_aggregators(2), bits({bits}), length({length}), chunk_length({chunk_length})")))?;
            shard_then_encode(&vdaf, &measurement, nonce)
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
            shard_then_encode(&vdaf, &measurement, nonce)
        }
        _ => Err(VdafError::Dap(fatal_error!(
            err = format!("prio3_shard: unexpected VDAF config {config:?}")
        ))),
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
        (Prio3Config::Count, VdafVerifyKey::L16(verify_key)) => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 from num_aggregators(2)"),
                )
            })?;
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
            VdafVerifyKey::L16(verify_key),
        ) => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 histogram from num_aggregators(2), length({length}), chunk_length({chunk_length})")))?;
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
        (Prio3Config::Sum { bits }, VdafVerifyKey::L16(verify_key)) => {
            let vdaf =
                Prio3::new_sum(2, *bits).map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum from num_aggregators(2), bits({bits})")))?;
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
            VdafVerifyKey::L16(verify_key),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum vec from num_aggregators(2), bits({bits}), length({length}), chunk_length({chunk_length})")))?;
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
            VdafVerifyKey::L32(verify_key),
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
        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = "unhandled config and verify key combination",
            )))
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
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 count num_aggregators(2)"),
                )
            })?;
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
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 histogram from num_aggregators(2), length({length}), chunk_length({chunk_length})")))?;
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
            let vdaf =
                Prio3::new_sum(2, *bits).map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum from num_aggregators(2), bits({bits})")))?;
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
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum vec from num_aggregators(2), bits({bits}), length({length}), chunk_length({chunk_length})")))?;
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
        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = format!("prio3_prep_finish_from_shares: {ERR_FIELD_TYPE}")
            )))
        }
    };

    Ok((agg_share, outbound))
}

/// Consume the prep message and output our output share.
pub(crate) fn prio3_prep_finish(
    config: &Prio3Config,
    host_state: VdafPrepState,
    peer_message_data: &[u8],
) -> Result<VdafAggregateShare, VdafError> {
    let agg_share = match (&config, host_state) {
        (Prio3Config::Count, VdafPrepState::Prio3Field64(state)) => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 count from num_aggregators(2)"),
                )
            })?;
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
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 histogram from num_aggregators(2), length({length}), chunk_length({chunk_length})")))?;
            let out_share = prep_finish(&vdaf, state, peer_message_data)?;
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Sum { bits }, VdafPrepState::Prio3Field128(state)) => {
            let vdaf =
                Prio3::new_sum(2, *bits).map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum from num_aggregators(2), bits({bits})")))?;
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
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum vec from num_aggregators(2), bits({bits}), length({length}), chunk_length({chunk_length})")))?;
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

        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = format!("prio3_prep_finish: {ERR_FIELD_TYPE}")
            )))
        }
    };

    Ok(agg_share)
}

/// Parse our prep state.
pub(crate) fn prio3_decode_prep_state(
    config: &Prio3Config,
    agg_id: usize,
    bytes: &mut Cursor<&[u8]>,
) -> Result<VdafPrepState, VdafError> {
    match config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 count from num_aggregators(2)"),
                )
            })?;
            Ok(VdafPrepState::Prio3Field64(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::Histogram {
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 histogram from num_aggregators(2), length({length}), chunk_length({chunk_length})")))?;
            Ok(VdafPrepState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::Sum { bits } => {
            let vdaf =
                Prio3::new_sum(2, *bits).map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum from num_aggregators(2), bits({bits})")))?;
            Ok(VdafPrepState::Prio3Field128(
                Prio3PrepareState::decode_with_param(&(&vdaf, agg_id), bytes)?,
            ))
        }
        Prio3Config::SumVec {
            bits,
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum vec from num_aggregators(2), bits({bits}), length({length}), chunk_length({chunk_length})")))?;
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
    match config {
        Prio3Config::Count => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 count from num_aggregators(2)"),
                )
            })?;
            let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U64(agg_res))
        }
        Prio3Config::Histogram {
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 histogram from num_aggregators(2), length({length}), chunk_length({chunk_length})")))?;
            let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U128Vec(agg_res))
        }
        Prio3Config::Sum { bits } => {
            let vdaf =
                Prio3::new_sum(2, *bits).map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum from num_aggregators(2), bits({bits})")))?;
            let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
            Ok(DapAggregateResult::U128(agg_res))
        }
        Prio3Config::SumVec {
            bits,
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum vec from num_aggregators(2), bits({bits}), length({length}), chunk_length({chunk_length})")))?;
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
    }
}

#[cfg(test)]
mod test {

    use prio::vdaf::prio3_test::check_test_vec;

    use crate::{
        async_test_versions,
        hpke::HpkeKemId,
        testing::AggregationJobTest,
        vdaf::{
            prio3::new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128, Prio3Config, VdafConfig,
        },
        DapAggregateResult, DapAggregationParam, DapMeasurement, DapVersion,
    };

    async fn roundtrip_count(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Count),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t
            .roundtrip(
                DapAggregationParam::Empty,
                vec![
                    DapMeasurement::U64(0),
                    DapMeasurement::U64(1),
                    DapMeasurement::U64(1),
                    DapMeasurement::U64(1),
                    DapMeasurement::U64(0),
                ],
            )
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
            .roundtrip(
                DapAggregationParam::Empty,
                vec![
                    DapMeasurement::U64(0),
                    DapMeasurement::U64(1),
                    DapMeasurement::U64(1337),
                    DapMeasurement::U64(4),
                    DapMeasurement::U64(0),
                ],
            )
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
            .roundtrip(
                DapAggregationParam::Empty,
                vec![
                    DapMeasurement::U128Vec(vec![1337, 0]),
                    DapMeasurement::U128Vec(vec![0, 1337]),
                    DapMeasurement::U128Vec(vec![1, 1]),
                ],
            )
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
            .roundtrip(
                DapAggregationParam::Empty,
                vec![
                    DapMeasurement::U64(0),
                    DapMeasurement::U64(1),
                    DapMeasurement::U64(2),
                    DapMeasurement::U64(2),
                    DapMeasurement::U64(2),
                ],
            )
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
            .roundtrip(
                DapAggregationParam::Empty,
                vec![
                    DapMeasurement::U64Vec(vec![1337, 0]),
                    DapMeasurement::U64Vec(vec![0, 1337]),
                    DapMeasurement::U64Vec(vec![1, 1]),
                ],
            )
            .await;
        assert_eq!(got, DapAggregateResult::U64Vec(vec![1338, 1338]));
    }

    async_test_versions! { roundtrip_sum_vec_field64_multiproof_hmac_sha256_aes128 }

    #[test]
    fn test_vec_sum_vec_field64_multiproof_hmac_sha256_aes128() {
        for test_vec_json_str in [
            include_str!("test_vec/Prio3SumVecField64MultiproofHmacSha256Aes128_0.json"),
            include_str!("test_vec/Prio3SumVecField64MultiproofHmacSha256Aes128_1.json"),
            include_str!("test_vec/Prio3SumVecField64MultiproofHmacSha256Aes128_2.json"),
        ] {
            check_test_vec(test_vec_json_str, |json_params, num_aggregators| {
                assert_eq!(num_aggregators, 2);
                new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                    json_params["bits"].as_u64().unwrap().try_into().unwrap(),
                    json_params["length"].as_u64().unwrap().try_into().unwrap(),
                    json_params["chunk_length"]
                        .as_u64()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    json_params["proofs"].as_u64().unwrap().try_into().unwrap(),
                )
                .unwrap()
            });
        }
    }
}
