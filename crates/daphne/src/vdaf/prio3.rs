// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [Prio3 VDAF](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/13/).

use crate::{
    fatal_error,
    messages::TaskId,
    vdaf::{VdafError, VdafVerifyKey},
    DapAggregateResult, DapMeasurement, Prio3Config, VdafAggregateShare, VdafPrepShare,
    VdafPrepState,
};

use super::{prep_finish, prep_finish_from_shares, shard_then_encode, unshard};

use prio::{
    codec::ParameterizedDecode,
    flp::Type,
    vdaf::{
        prio3::{Prio3, Prio3InputShare, Prio3PrepareShare, Prio3PrepareState, Prio3PublicShare},
        xof::Xof,
        Aggregator,
    },
};

const CTX_STRING_PREFIX: &[u8] = b"dap-13";

/// Split the given measurement into a sequence of encoded input shares.
pub(crate) fn prio3_shard(
    config: &Prio3Config,
    measurement: DapMeasurement,
    nonce: &[u8; 16],
    task_id: TaskId,
) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
    match (config, measurement) {
        (Prio3Config::Count, DapMeasurement::U64(measurement)) if measurement < 2 => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 count from num_aggregators(2)"),
                )
            })?;
            shard_then_encode(&vdaf, task_id, &(measurement != 0), nonce)
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
            shard_then_encode(&vdaf, task_id, &m, nonce)
        }
        (Prio3Config::Sum { .. }, DapMeasurement::U64(_)) => {
            Err(VdafError::Dap(fatal_error!(err = "Sum unimplemented")))
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
            shard_then_encode(&vdaf, task_id, &measurement, nonce)
        }
        (
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 { .. },
            DapMeasurement::U64Vec(_),
        ) => Err(VdafError::Dap(fatal_error!(
            err = format!(
                "prio3_shard: SumVecField64MultiproofHmacSha256Aes128 is not defined for VDAF-13"
            )
        ))),
        _ => Err(VdafError::Dap(fatal_error!(
            err = format!("prio3_shard: unexpected VDAF config {config:?}")
        ))),
    }
}

/// Consume an input share and return the corresponding VDAF step and message.
pub(crate) fn prio3_prep_init(
    config: &Prio3Config,
    verify_key: &VdafVerifyKey,
    task_id: TaskId,
    agg_id: usize,
    nonce: &[u8; 16],
    public_share_data: &[u8],
    input_share_data: &[u8],
) -> Result<(VdafPrepState, VdafPrepShare), VdafError> {
    return match (&config, verify_key) {
        (Prio3Config::Count, VdafVerifyKey::L32(verify_key)) => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 from num_aggregators(2)"),
                )
            })?;
            let (state, share) = prep_init(
                vdaf,
                task_id,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            )?;
            Ok((
                VdafPrepState::Prio3Field64(state),
                VdafPrepShare::Prio3Field64(share),
            ))
        }
        (
            Prio3Config::Histogram {
                length,
                chunk_length,
            },
            VdafVerifyKey::L32(verify_key),
        ) => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 histogram from num_aggregators(2), length({length}), chunk_length({chunk_length})")))?;
            let (state, share) = prep_init(
                vdaf,
                task_id,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            )?;
            Ok((
                VdafPrepState::Prio3Field128(state),
                VdafPrepShare::Prio3Field128(share),
            ))
        }
        (Prio3Config::Sum { .. }, VdafVerifyKey::L32(_)) => {
            Err(VdafError::Dap(fatal_error!(err = "sum unimplemented")))
        }
        (
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            },
            VdafVerifyKey::L32(verify_key),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum vec from num_aggregators(2), bits({bits}), length({length}), chunk_length({chunk_length})")))?;
            let (state, share) = prep_init(
                vdaf,
                task_id,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            )?;
            Ok((
                VdafPrepState::Prio3Field128(state),
                VdafPrepShare::Prio3Field128(share),
            ))
        }
        (
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            ..},
            VdafVerifyKey::L32(_),
        ) => {
            Err(VdafError::Dap(fatal_error!(err = format!("prio3_shard: SumVecField64MultiproofHmacSha256Aes128 is not defined for VDAF-13"))))
        },
        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = "unhandled config and verify key combination",
            )))
        }

    };

    type Prio3Prepared<T, const SEED_SIZE: usize> = (
        Prio3PrepareState<<T as Type>::Field, SEED_SIZE>,
        Prio3PrepareShare<<T as Type>::Field, SEED_SIZE>,
    );

    fn prep_init<T, P, const SEED_SIZE: usize>(
        vdaf: Prio3<T, P, SEED_SIZE>,
        task_id: TaskId,
        verify_key: &[u8; SEED_SIZE],
        agg_id: usize,
        nonce: &[u8; 16],
        public_share_data: &[u8],
        input_share_data: &[u8],
    ) -> Result<Prio3Prepared<T, SEED_SIZE>, VdafError>
    where
        T: Type,
        P: Xof<SEED_SIZE>,
    {
        // Parse the public share.
        let public_share = Prio3PublicShare::get_decoded_with_param(&vdaf, public_share_data)?;

        // Parse the input share.
        let input_share =
            Prio3InputShare::get_decoded_with_param(&(&vdaf, agg_id), input_share_data)?;

        let mut ctx = [0; CTX_STRING_PREFIX.len() + 32];
        ctx[..CTX_STRING_PREFIX.len()].copy_from_slice(CTX_STRING_PREFIX);
        ctx[CTX_STRING_PREFIX.len()..].copy_from_slice(&task_id.0);
        // Run the prepare-init algorithm, returning the initial state.
        Ok(vdaf.prepare_init(
            verify_key,
            &ctx,
            agg_id,
            &(),
            nonce,
            &public_share,
            &input_share,
        )?)
    }
}

/// Consume the prep shares and return our output share and the prep message.
pub(crate) fn prio3_prep_finish_from_shares(
    config: &Prio3Config,
    agg_id: usize,
    task_id: TaskId,
    host_state: VdafPrepState,
    host_share: VdafPrepShare,
    peer_share_data: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
    let (agg_share, outbound) = match (&config, host_state, host_share) {
        (
            Prio3Config::Count,
            VdafPrepState::Prio3Field64(state),
            VdafPrepShare::Prio3Field64(share),
        ) => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 count num_aggregators(2)"),
                )
            })?;
            let (out_share, outbound) =
                prep_finish_from_shares(&vdaf, task_id, agg_id, state, share, peer_share_data)?;
            let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Histogram {
                length,
                chunk_length,
            },
            VdafPrepState::Prio3Field128(state),
            VdafPrepShare::Prio3Field128(share),
        ) => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 histogram from num_aggregators(2), length({length}), chunk_length({chunk_length})")))?;
            let (out_share, outbound) =
                prep_finish_from_shares(&vdaf, task_id, agg_id, state, share, peer_share_data)?;
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::Sum { .. },
            VdafPrepState::Prio3Field128(_),
            VdafPrepShare::Prio3Field128(_),
        ) => Err(VdafError::Dap(fatal_error!(err = "Prio3Sum is not supported in VDAF-13")))?,
        (
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            },
            VdafPrepState::Prio3Field128(state),
            VdafPrepShare::Prio3Field128(share),
        ) => {
            let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)
                .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "failed to create prio3 sum vec from num_aggregators(2), bits({bits}), length({length}), chunk_length({chunk_length})")))?;
            let (out_share, outbound) =
                prep_finish_from_shares(&vdaf, task_id, agg_id, state, share, peer_share_data)?;
            let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
            (agg_share, outbound)
        }
        (
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            ..
        },
            VdafPrepState::Prio3Field64HmacSha256Aes128(_),
            VdafPrepShare::Prio3Field64HmacSha256Aes128(_),
        ) => {
            return Err(VdafError::Dap(fatal_error!(err = format!("prio3_prep_finish_from_shares: SumVecField64MultiproofHmacSha256Aes128 is not defined for VDAF-13"))))
        }
        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = format!("prio3_prep_finish_from_shares: unexpected field type for step or message")
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
    task_id: TaskId,
) -> Result<VdafAggregateShare, VdafError> {
    let agg_share = match (&config, host_state) {
        (Prio3Config::Count, VdafPrepState::Prio3Field64(state)) => {
            let vdaf = Prio3::new_count(2).map_err(|e| {
                VdafError::Dap(
                    fatal_error!(err = ?e, "failed to create prio3 count from num_aggregators(2)"),
                )
            })?;
            let out_share = prep_finish(&vdaf, task_id, state, peer_message_data)?;
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
            let out_share = prep_finish(&vdaf, task_id, state, peer_message_data)?;
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (Prio3Config::Sum { .. }, VdafPrepState::Prio3Field128(_)) => {
            Err(VdafError::Dap(fatal_error!(err = "sum unimplemented")))?
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
            let out_share = prep_finish(&vdaf, task_id, state, peer_message_data)?;
            VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
        }
        (
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            ..
            },
            VdafPrepState::Prio3Field64HmacSha256Aes128(_),
        ) => {

            return Err(VdafError::Dap(fatal_error!(err = format!("prio3_prep_finish: SumVecField64MultiproofHmacSha256Aes128 is not defined for VDAF-13"))))
        }

        _ => {
            return Err(VdafError::Dap(fatal_error!(
                err = format!("prio3_prep_finish: unexpected field type for step or message")
            )))
        }
    };

    Ok(agg_share)
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
        Prio3Config::Sum { .. } => Err(VdafError::Dap(fatal_error!(err = "sum unimplemented"))),
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
        ..
        } => {
            Err(VdafError::Dap(fatal_error!(err = format!("prio3_prep_finish: SumVecField64MultiproofHmacSha256Aes128 is not defined for VDAF-13"))))
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        hpke::HpkeKemId,
        test_versions,
        testing::AggregationJobTest,
        vdaf::{Prio3Config, VdafConfig},
        DapAggregateResult, DapAggregationParam, DapMeasurement, DapVersion,
    };

    fn roundtrip_count(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Count),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t.roundtrip(
            DapAggregationParam::Empty,
            vec![
                DapMeasurement::U64(0),
                DapMeasurement::U64(1),
                DapMeasurement::U64(1),
                DapMeasurement::U64(1),
                DapMeasurement::U64(0),
            ],
        );
        assert_eq!(got, DapAggregateResult::U64(3));
    }

    test_versions! { roundtrip_count }

    fn roundtrip_sum_vec(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::SumVec {
                bits: 23,
                length: 2,
                chunk_length: 1,
            }),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t.roundtrip(
            DapAggregationParam::Empty,
            vec![
                DapMeasurement::U128Vec(vec![1337, 0]),
                DapMeasurement::U128Vec(vec![0, 1337]),
                DapMeasurement::U128Vec(vec![1, 1]),
            ],
        );
        assert_eq!(got, DapAggregateResult::U128Vec(vec![1338, 1338]));
    }

    test_versions! { roundtrip_sum_vec }

    fn roundtrip_histogram(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Histogram {
                length: 3,
                chunk_length: 1,
            }),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t.roundtrip(
            DapAggregationParam::Empty,
            vec![
                DapMeasurement::U64(0),
                DapMeasurement::U64(1),
                DapMeasurement::U64(2),
                DapMeasurement::U64(2),
                DapMeasurement::U64(2),
            ],
        );
        assert_eq!(got, DapAggregateResult::U128Vec(vec![1, 1, 3]));
    }

    test_versions! { roundtrip_histogram }
}
