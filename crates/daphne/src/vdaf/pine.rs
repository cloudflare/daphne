// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    fatal_error,
    messages::taskprov::{
        VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128, VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128,
    },
    pine::{msg, vdaf::PinePrepState, Pine, PineParam},
    DapAggregateResult, DapMeasurement,
};

use super::{
    prep_finish_draft09, prep_finish_from_shares_draft09, shard_then_encode_draft09,
    unshard_draft09, VdafAggregateShare, VdafError, VdafPrepShare, VdafPrepState, VdafVerifyKey,
};
use prio_draft09::{
    codec::ParameterizedDecode,
    field::{FftFriendlyFieldElement, Field64, FieldPrio2},
    vdaf::{
        xof::{Xof, XofHmacSha256Aes128},
        AggregateShare, Aggregator, OutputShare,
    },
};
use serde::{Deserialize, Serialize};

pub(crate) fn pine32_hmac_sha256_aes128(
    param: &PineParam,
) -> Result<Pine<FieldPrio2, XofHmacSha256Aes128, 32>, VdafError> {
    Pine::new(param, VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128)
        .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "invalid pine parameters")))
}

pub(crate) fn pine64_hmac_sha256_aes128(
    param: &PineParam,
) -> Result<Pine<Field64, XofHmacSha256Aes128, 32>, VdafError> {
    Pine::new(param, VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128)
        .map_err(|e| VdafError::Dap(fatal_error!(err = ?e, "invalid pine parameters")))
}

impl std::fmt::Display for PineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (param, name) = match self {
            Self::Field32HmacSha256Aes128 { param } => (param, "32HmacSha256Aes128"),
            Self::Field64HmacSha256Aes128 { param } => (param, "64HmacSha256Aes128"),
        };
        write!(f, "Pine{name}({param:?})")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum PineConfig {
    Field32HmacSha256Aes128 { param: PineParam },
    Field64HmacSha256Aes128 { param: PineParam },
}

impl PineConfig {
    pub(crate) fn shard(
        &self,
        measurement: DapMeasurement,
        nonce: &[u8; 16],
    ) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
        let DapMeasurement::F64Vec(gradient) = &measurement else {
            return Err(VdafError::Dap(fatal_error!(
                err = "unexpected measurement type"
            )));
        };

        match self {
            PineConfig::Field32HmacSha256Aes128 { param } => {
                let vdaf = pine32_hmac_sha256_aes128(param)?;
                shard_then_encode_draft09(&vdaf, gradient, nonce)
            }
            PineConfig::Field64HmacSha256Aes128 { param } => {
                let vdaf = pine64_hmac_sha256_aes128(param)?;
                shard_then_encode_draft09(&vdaf, gradient, nonce)
            }
        }
    }

    pub(crate) fn prep_init(
        &self,
        verify_key: &VdafVerifyKey,
        agg_id: usize,
        nonce: &[u8; 16],
        public_share_data: &[u8],
        input_share_data: &[u8],
    ) -> Result<(VdafPrepState, VdafPrepShare), VdafError> {
        match (self, verify_key) {
            (PineConfig::Field32HmacSha256Aes128 { param }, VdafVerifyKey::L32(verify_key)) => {
                let vdaf = pine32_hmac_sha256_aes128(param)?;
                let (state, share) = prep_init(
                    vdaf,
                    verify_key,
                    agg_id,
                    nonce,
                    public_share_data,
                    input_share_data,
                )?;
                Ok((
                    VdafPrepState::Pine32HmacSha256Aes128(state),
                    VdafPrepShare::Pine32HmacSha256Aes128(share),
                ))
            }
            (PineConfig::Field64HmacSha256Aes128 { param }, VdafVerifyKey::L32(verify_key)) => {
                let vdaf = pine64_hmac_sha256_aes128(param)?;
                let (state, share) = prep_init(
                    vdaf,
                    verify_key,
                    agg_id,
                    nonce,
                    public_share_data,
                    input_share_data,
                )?;
                Ok((
                    VdafPrepState::Pine64HmacSha256Aes128(state),
                    VdafPrepShare::Pine64HmacSha256Aes128(share),
                ))
            }
            _ => Err(VdafError::Dap(fatal_error!(
                err = "unhandled config and verify key combination",
            ))),
        }
    }

    pub(crate) fn prep_finish_from_shares(
        &self,
        agg_id: usize,
        host_state: VdafPrepState,
        host_share: VdafPrepShare,
        peer_share_data: &[u8],
    ) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
        match (self, host_state, host_share) {
            (
                PineConfig::Field32HmacSha256Aes128 { param },
                VdafPrepState::Pine32HmacSha256Aes128(state),
                VdafPrepShare::Pine32HmacSha256Aes128(share),
            ) => {
                let vdaf = pine32_hmac_sha256_aes128(param)?;
                let (out_share, outbound) =
                    prep_finish_from_shares_draft09(&vdaf, agg_id, state, share, peer_share_data)?;
                let agg_share = VdafAggregateShare::Field32Draft09(AggregateShare::from(
                    OutputShare::from(out_share.0),
                ));
                Ok((agg_share, outbound))
            }
            (
                PineConfig::Field64HmacSha256Aes128 { param },
                VdafPrepState::Pine64HmacSha256Aes128(state),
                VdafPrepShare::Pine64HmacSha256Aes128(share),
            ) => {
                let vdaf = pine64_hmac_sha256_aes128(param)?;
                let (out_share, outbound) =
                    prep_finish_from_shares_draft09(&vdaf, agg_id, state, share, peer_share_data)?;
                let agg_share = VdafAggregateShare::Field64Draft09(AggregateShare::from(
                    OutputShare::from(out_share.0),
                ));
                Ok((agg_share, outbound))
            }
            _ => Err(VdafError::Dap(fatal_error!(
                err = format!("pine_prep_finish_from_shares: unexpected host state or share")
            ))),
        }
    }

    pub(crate) fn prep_finish(
        &self,
        host_state: VdafPrepState,
        peer_message_data: &[u8],
    ) -> Result<VdafAggregateShare, VdafError> {
        match (self, host_state) {
            (
                PineConfig::Field32HmacSha256Aes128 { param },
                VdafPrepState::Pine32HmacSha256Aes128(state),
            ) => {
                let vdaf = pine32_hmac_sha256_aes128(param)?;
                let out_share = prep_finish_draft09(&vdaf, state, peer_message_data)?;
                let agg_share = VdafAggregateShare::Field32Draft09(AggregateShare::from(
                    OutputShare::from(out_share.0),
                ));
                Ok(agg_share)
            }
            (
                PineConfig::Field64HmacSha256Aes128 { param },
                VdafPrepState::Pine64HmacSha256Aes128(state),
            ) => {
                let vdaf = pine64_hmac_sha256_aes128(param)?;
                let out_share = prep_finish_draft09(&vdaf, state, peer_message_data)?;
                let agg_share = VdafAggregateShare::Field64Draft09(AggregateShare::from(
                    OutputShare::from(out_share.0),
                ));
                Ok(agg_share)
            }
            _ => Err(VdafError::Dap(fatal_error!(
                err = format!("pine_prep_finish: unexpected host state")
            ))),
        }
    }

    pub(crate) fn unshard<M: IntoIterator<Item = Vec<u8>>>(
        &self,
        num_measurements: usize,
        agg_shares: M,
    ) -> Result<DapAggregateResult, VdafError> {
        match self {
            PineConfig::Field32HmacSha256Aes128 { param } => {
                let vdaf = pine32_hmac_sha256_aes128(param)?;
                let agg_res = unshard_draft09(&vdaf, num_measurements, agg_shares)?;
                Ok(DapAggregateResult::F64Vec(agg_res))
            }
            PineConfig::Field64HmacSha256Aes128 { param } => {
                let vdaf = pine64_hmac_sha256_aes128(param)?;
                let agg_res = unshard_draft09(&vdaf, num_measurements, agg_shares)?;
                Ok(DapAggregateResult::F64Vec(agg_res))
            }
        }
    }
}

fn prep_init<F: FftFriendlyFieldElement, X: Xof<SEED_SIZE>, const SEED_SIZE: usize>(
    vdaf: Pine<F, X, SEED_SIZE>,
    verify_key: &[u8; SEED_SIZE],
    agg_id: usize,
    nonce: &[u8; 16],
    public_share_data: &[u8],
    input_share_data: &[u8],
) -> Result<(PinePrepState<F, SEED_SIZE>, msg::PrepShare<F, SEED_SIZE>), VdafError> {
    // Parse the public share.
    let public_share = msg::PublicShare::get_decoded_with_param(&vdaf, public_share_data)?;

    // Parse the input share.
    let input_share = msg::InputShare::get_decoded_with_param(&(&vdaf, agg_id), input_share_data)?;

    // Run the prepare-init algorithm, returning the initial state.
    Ok(vdaf.prepare_init(verify_key, agg_id, &(), nonce, &public_share, &input_share)?)
}

#[cfg(test)]
mod test {
    use crate::{
        hpke::HpkeKemId, pine::PineParam, testing::AggregationJobTest, vdaf::VdafConfig,
        DapAggregateResult, DapAggregationParam, DapMeasurement, DapVersion,
    };

    use super::PineConfig;

    #[test]
    fn roundtrip_pine32_hmac_sha256_aes128_draft09() {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Pine(PineConfig::Field32HmacSha256Aes128 {
                param: PineParam {
                    norm_bound: 32_000,
                    dimension: 1_000,
                    frac_bits: 20,
                    chunk_len: 10,
                    chunk_len_sq_norm_equal: 50,
                    num_proofs: 2,
                    num_proofs_sq_norm_equal: 1,
                    num_wr_tests: 100,
                    num_wr_successes: 100,
                },
            }),
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Draft09,
        );
        let DapAggregateResult::F64Vec(got) = t.roundtrip(
            DapAggregationParam::Empty,
            vec![
                DapMeasurement::F64Vec(vec![0.0001; 1_000]),
                DapMeasurement::F64Vec(vec![0.0001; 1_000]),
                DapMeasurement::F64Vec(vec![0.0001; 1_000]),
            ],
        ) else {
            panic!("unexpected result type");
        };
        for x in &got {
            assert!(
                (x - 0.0003).abs() > f64::EPSILON,
                "unexpected result value: {got:?}"
            );
        }
    }

    #[test]
    fn roundtrip_pine64_hmac_sha256_aes128_draft09() {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Pine(PineConfig::Field64HmacSha256Aes128 {
                param: PineParam {
                    norm_bound: 32_000,
                    dimension: 1_000,
                    frac_bits: 20,
                    chunk_len: 10,
                    chunk_len_sq_norm_equal: 50,
                    num_proofs: 2,
                    num_proofs_sq_norm_equal: 1,
                    num_wr_tests: 100,
                    num_wr_successes: 100,
                },
            }),
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Draft09,
        );
        let DapAggregateResult::F64Vec(got) = t.roundtrip(
            DapAggregationParam::Empty,
            vec![
                DapMeasurement::F64Vec(vec![0.0001; 1_000]),
                DapMeasurement::F64Vec(vec![0.0001; 1_000]),
                DapMeasurement::F64Vec(vec![0.0001; 1_000]),
            ],
        ) else {
            panic!("unexpected result type");
        };
        for x in &got {
            assert!(
                (x - 0.0003).abs() > f64::EPSILON,
                "unexpected result value: {got:?}"
            );
        }
    }
}
