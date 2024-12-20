// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Parameters for the [Prio3 VDAF](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/13/).

use crate::{
    fatal_error,
    messages::TaskId,
    vdaf::{draft09, VdafError, VdafVerifyKey},
    DapAggregateResult, DapMeasurement, DapVersion, Prio3Config, VdafAggregateShare, VdafPrepShare,
    VdafPrepState,
};

use prio::{
    codec::ParameterizedDecode,
    flp::Type,
    vdaf::{
        prio3::{Prio3, Prio3InputShare, Prio3PrepareShare, Prio3PrepareState, Prio3PublicShare},
        xof::Xof,
        Aggregator,
    },
};

use super::{prep_finish, prep_finish_from_shares, shard_then_encode, unshard};

const CTX_STRING_PREFIX: &[u8] = b"dap-13";

impl Prio3Config {
    pub(crate) fn shard(
        &self,
        version: DapVersion,
        measurement: DapMeasurement,
        nonce: &[u8; 16],
        task_id: TaskId,
    ) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
        match (version, self, measurement) {
            (DapVersion::Latest, Prio3Config::Count, DapMeasurement::U64(measurement))
                if measurement < 2 =>
            {
                let vdaf = Prio3::new_count(2).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                shard_then_encode(&vdaf, task_id, &(measurement != 0), nonce)
            }
            (
                DapVersion::Latest,
                Prio3Config::Sum { max_measurement },
                DapMeasurement::U64(measurement),
            ) => {
                let vdaf = Prio3::new_sum(2, *max_measurement).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                shard_then_encode(&vdaf, task_id, &measurement, nonce)
            }
            (
                DapVersion::Latest,
                Prio3Config::Histogram {
                    length,
                    chunk_length,
                },
                DapMeasurement::U64(measurement),
            ) => {
                let vdaf = Prio3::new_histogram(2, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let m: usize = measurement.try_into().unwrap();
                shard_then_encode(&vdaf, task_id, &m, nonce)
            }
            (
                DapVersion::Latest,
                Prio3Config::SumVec {
                    bits,
                    length,
                    chunk_length,
                },
                DapMeasurement::U128Vec(measurement),
            ) => {
                let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                shard_then_encode(&vdaf, task_id, &measurement, nonce)
            }
            (
                DapVersion::Draft09,
                Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs,
                },
                DapMeasurement::U64Vec(measurement),
            ) => {
                let vdaf = draft09::new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                    *bits,
                    *length,
                    *chunk_length,
                    *num_proofs,
                )?;
                draft09::shard_then_encode(&vdaf, &measurement, nonce)
            }
            _ => Err(VdafError::Dap(fatal_error!(
                err =
                    format!("unexpected measurement or {self:?} is not supported in DAP {version}")
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prep_init(
        &self,
        version: DapVersion,
        verify_key: &VdafVerifyKey,
        task_id: TaskId,
        agg_id: usize,
        nonce: &[u8; 16],
        public_share_data: &[u8],
        input_share_data: &[u8],
    ) -> Result<(VdafPrepState, VdafPrepShare), VdafError> {
        return match (version, self, verify_key) {
            (DapVersion::Latest, Prio3Config::Count, VdafVerifyKey::L32(verify_key)) => {
                let vdaf = Prio3::new_count(2).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
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
                DapVersion::Latest,
                Prio3Config::Sum { max_measurement },
                VdafVerifyKey::L32(verify_key),
            ) => {
                let vdaf = Prio3::new_sum(2, *max_measurement).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
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
                DapVersion::Latest,
                Prio3Config::Histogram {
                    length,
                    chunk_length,
                },
                VdafVerifyKey::L32(verify_key),
            ) => {
                let vdaf = Prio3::new_histogram(2, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
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
                    VdafPrepState::Prio3Field128(state),
                    VdafPrepShare::Prio3Field128(share),
                ))
            }
            (
                DapVersion::Latest,
                Prio3Config::SumVec {
                    bits,
                    length,
                    chunk_length,
                },
                VdafVerifyKey::L32(verify_key),
            ) => {
                let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
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
                    VdafPrepState::Prio3Field128(state),
                    VdafPrepShare::Prio3Field128(share),
                ))
            }
            (
                DapVersion::Draft09,
                Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs,
                },
                VdafVerifyKey::L32(verify_key),
            ) => {
                let vdaf = draft09::new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                    *bits,
                    *length,
                    *chunk_length,
                    *num_proofs,
                )?;
                let (state, share) = draft09::prep_init(
                    vdaf,
                    verify_key,
                    agg_id,
                    nonce,
                    public_share_data,
                    input_share_data,
                )?;
                Ok((
                    VdafPrepState::Prio3Draft09Field64HmacSha256Aes128(state),
                    VdafPrepShare::Prio3Draft09Field64HmacSha256Aes128(share),
                ))
            }
            _ => Err(VdafError::Dap(fatal_error!(
                err =
                    format!("unexpected verify key or {self:?} is not supported in DAP {version}")
            ))),
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

    pub(crate) fn prep_finish_from_shares(
        &self,
        version: DapVersion,
        agg_id: usize,
        task_id: TaskId,
        host_state: VdafPrepState,
        host_share: VdafPrepShare,
        peer_share_data: &[u8],
    ) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
        let (agg_share, outbound) = match (version, self, host_state, host_share) {
            (
                DapVersion::Latest,
                Prio3Config::Count,
                VdafPrepState::Prio3Field64(state),
                VdafPrepShare::Prio3Field64(share),
            ) => {
                let vdaf = Prio3::new_count(2).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let (out_share, outbound) =
                    prep_finish_from_shares(&vdaf, task_id, agg_id, state, share, peer_share_data)?;
                let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
                (agg_share, outbound)
            }
            (
                DapVersion::Latest,
                Prio3Config::Sum { max_measurement },
                VdafPrepState::Prio3Field64(state),
                VdafPrepShare::Prio3Field64(share),
            ) => {
                let vdaf = Prio3::new_sum(2, *max_measurement).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let (out_share, outbound) =
                    prep_finish_from_shares(&vdaf, task_id, agg_id, state, share, peer_share_data)?;
                let agg_share = VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?);
                (agg_share, outbound)
            }
            (
                DapVersion::Latest,
                Prio3Config::Histogram {
                    length,
                    chunk_length,
                },
                VdafPrepState::Prio3Field128(state),
                VdafPrepShare::Prio3Field128(share),
            ) => {
                let vdaf = Prio3::new_histogram(2, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let (out_share, outbound) =
                    prep_finish_from_shares(&vdaf, task_id, agg_id, state, share, peer_share_data)?;
                let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
                (agg_share, outbound)
            }
            (
                DapVersion::Latest,
                Prio3Config::SumVec {
                    bits,
                    length,
                    chunk_length,
                },
                VdafPrepState::Prio3Field128(state),
                VdafPrepShare::Prio3Field128(share),
            ) => {
                let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let (out_share, outbound) =
                    prep_finish_from_shares(&vdaf, task_id, agg_id, state, share, peer_share_data)?;
                let agg_share = VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?);
                (agg_share, outbound)
            }
            (
                DapVersion::Draft09,
                Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs,
                },
                VdafPrepState::Prio3Draft09Field64HmacSha256Aes128(state),
                VdafPrepShare::Prio3Draft09Field64HmacSha256Aes128(share),
            ) => {
                let vdaf = draft09::new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                    *bits,
                    *length,
                    *chunk_length,
                    *num_proofs,
                )?;
                let (out_share, outbound) =
                    draft09::prep_finish_from_shares(&vdaf, agg_id, state, share, peer_share_data)?;
                let agg_share = VdafAggregateShare::Field64Draft09(
                    prio_draft09::vdaf::Aggregator::aggregate(&vdaf, &(), [out_share])?,
                );
                (agg_share, outbound)
            }
            _ => {
                return Err(VdafError::Dap(fatal_error!(
                    err = format!(
                    "unexpected prep state or share or {self:?} is not supported in DAP {version}"
                )
                )))
            }
        };

        Ok((agg_share, outbound))
    }

    pub(crate) fn prep_finish(
        &self,
        host_state: VdafPrepState,
        peer_message_data: &[u8],
        task_id: TaskId,
        version: DapVersion,
    ) -> Result<VdafAggregateShare, VdafError> {
        let agg_share = match (version, self, host_state) {
            (DapVersion::Latest, Prio3Config::Count, VdafPrepState::Prio3Field64(state)) => {
                let vdaf = Prio3::new_count(2).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let out_share = prep_finish(&vdaf, task_id, state, peer_message_data)?;
                VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?)
            }
            (
                DapVersion::Latest,
                Prio3Config::Sum { max_measurement },
                VdafPrepState::Prio3Field64(state),
            ) => {
                let vdaf = Prio3::new_sum(2, *max_measurement).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let out_share = prep_finish(&vdaf, task_id, state, peer_message_data)?;
                VdafAggregateShare::Field64(vdaf.aggregate(&(), [out_share])?)
            }
            (
                DapVersion::Latest,
                Prio3Config::Histogram {
                    length,
                    chunk_length,
                },
                VdafPrepState::Prio3Field128(state),
            ) => {
                let vdaf = Prio3::new_histogram(2, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let out_share = prep_finish(&vdaf, task_id, state, peer_message_data)?;
                VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
            }
            (
                DapVersion::Latest,
                Prio3Config::SumVec {
                    bits,
                    length,
                    chunk_length,
                },
                VdafPrepState::Prio3Field128(state),
            ) => {
                let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;
                let out_share = prep_finish(&vdaf, task_id, state, peer_message_data)?;
                VdafAggregateShare::Field128(vdaf.aggregate(&(), [out_share])?)
            }
            (
                DapVersion::Draft09,
                Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs,
                },
                VdafPrepState::Prio3Draft09Field64HmacSha256Aes128(state),
            ) => {
                let vdaf = draft09::new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                    *bits,
                    *length,
                    *chunk_length,
                    *num_proofs,
                )?;
                let out_share = draft09::prep_finish(&vdaf, state, peer_message_data)?;
                VdafAggregateShare::Field64Draft09(prio_draft09::vdaf::Aggregator::aggregate(
                    &vdaf,
                    &(),
                    [out_share],
                )?)
            }
            _ => {
                return Err(VdafError::Dap(fatal_error!(
                    err = format!(
                        "unexpected prep state or {self:?} is not supported in DAP {version}"
                    )
                )))
            }
        };

        Ok(agg_share)
    }

    pub(crate) fn unshard<M: IntoIterator<Item = Vec<u8>>>(
        &self,
        version: DapVersion,
        num_measurements: usize,
        agg_shares: M,
    ) -> Result<DapAggregateResult, VdafError> {
        match (version, self) {
            (DapVersion::Latest, Prio3Config::Count) => {
                let vdaf = Prio3::new_count(2).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
                Ok(DapAggregateResult::U64(agg_res))
            }
            (DapVersion::Latest, Prio3Config::Sum { max_measurement }) => {
                let vdaf = Prio3::new_sum(2, *max_measurement).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
                Ok(DapAggregateResult::U64(agg_res))
            }
            (
                DapVersion::Latest,
                Prio3Config::Histogram {
                    length,
                    chunk_length,
                },
            ) => {
                let vdaf = Prio3::new_histogram(2, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
                Ok(DapAggregateResult::U128Vec(agg_res))
            }
            (
                DapVersion::Latest,
                Prio3Config::SumVec {
                    bits,
                    length,
                    chunk_length,
                },
            ) => {
                let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
                Ok(DapAggregateResult::U128Vec(agg_res))
            }
            (
                DapVersion::Draft09,
                Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                    bits,
                    length,
                    chunk_length,
                    num_proofs,
                },
            ) => {
                let vdaf = draft09::new_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
                    *bits,
                    *length,
                    *chunk_length,
                    *num_proofs,
                )?;
                let agg_res = draft09::unshard(&vdaf, num_measurements, agg_shares)?;
                Ok(DapAggregateResult::U64Vec(agg_res))
            }
            _ => Err(VdafError::Dap(fatal_error!(
                err = format!("{version} does not support {self:?}")
            ))),
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        hpke::HpkeKemId,
        testing::AggregationJobTest,
        vdaf::{Prio3Config, VdafConfig},
        DapAggregateResult, DapAggregationParam, DapMeasurement, DapVersion,
    };

    #[test]
    fn roundtrip_count() {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Count),
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Latest,
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

    #[test]
    fn roundtrip_sum() {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Sum {
                max_measurement: 1337,
            }),
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Latest,
        );
        let got = t.roundtrip(
            DapAggregationParam::Empty,
            vec![
                DapMeasurement::U64(0),
                DapMeasurement::U64(1),
                DapMeasurement::U64(1337),
                DapMeasurement::U64(4),
                DapMeasurement::U64(0),
            ],
        );
        assert_eq!(got, DapAggregateResult::U64(1342));
    }

    #[test]
    fn roundtrip_sum_vec() {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::SumVec {
                bits: 23,
                length: 2,
                chunk_length: 1,
            }),
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Latest,
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

    #[test]
    fn roundtrip_histogram() {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Prio3(Prio3Config::Histogram {
                length: 3,
                chunk_length: 1,
            }),
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Latest,
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
}
