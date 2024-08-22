// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    fatal_error,
    pine::{msg, vdaf::PinePrepState, Pine},
    vdaf::{prep_finish, prep_finish_from_shares, unshard},
    DapAggregateResult, DapMeasurement,
};

use super::{
    shard_then_encode, VdafAggregateShare, VdafError, VdafPrepMessage, VdafPrepState, VdafVerifyKey,
};
use prio::{
    codec::ParameterizedDecode,
    field::FftFriendlyFieldElement,
    vdaf::{xof::Xof, Aggregator},
};
use serde::{Deserialize, Serialize};

/// [Pine](crate::pine::Pine) parameters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct PineConfig {
    pub norm_bound: u64,
    pub dimension: usize,
    pub frac_bits: usize,
    pub chunk_len: usize,
    pub chunk_len_sq_norm_equal: usize,
    pub var: PineVariant,
}

impl std::fmt::Display for PineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PineConfig {
            norm_bound,
            dimension,
            frac_bits,
            chunk_len,
            chunk_len_sq_norm_equal,
            var,
        } = self;

        let var_suffix = match var {
            PineVariant::Field128 => "128",
        };

        write!(
            f,
            "Pine{var_suffix}({norm_bound},{dimension},{frac_bits},{chunk_len},{chunk_len_sq_norm_equal})"
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum PineVariant {
    Field128,
}

impl PineConfig {
    pub(crate) fn shard(
        &self,
        measurement: DapMeasurement,
        nonce: &[u8; 16],
    ) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
        let PineConfig {
            norm_bound,
            dimension,
            frac_bits,
            chunk_len,
            chunk_len_sq_norm_equal,
            var,
        } = self;

        let DapMeasurement::F64Vec(gradient) = &measurement else {
            return Err(VdafError::Dap(fatal_error!(
                err = "unexpected measurement type"
            )));
        };

        match var {
            PineVariant::Field128 => {
                let vdaf = Pine::new_128(
                    *norm_bound,
                    *dimension,
                    *frac_bits,
                    *chunk_len,
                    *chunk_len_sq_norm_equal,
                )
                .map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "failed to create pine field"))
                })?;
                shard_then_encode(&vdaf, gradient, nonce)
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
    ) -> Result<(VdafPrepState, VdafPrepMessage), VdafError> {
        let PineConfig {
            norm_bound,
            dimension,
            frac_bits,
            chunk_len,
            chunk_len_sq_norm_equal,
            var,
        } = self;

        match (var, verify_key) {
            (PineVariant::Field128, VdafVerifyKey::L16(verify_key)) => {
                let vdaf = Pine::new_128(
                    *norm_bound,
                    *dimension,
                    *frac_bits,
                    *chunk_len,
                    *chunk_len_sq_norm_equal,
                )
                .map_err(
                    |e| VdafError::Dap(fatal_error!(err = ?e, "failed to create pine from norm_bound({norm_bound}), dimension{dimension}, frac_bits({frac_bits}), chunk_len({chunk_len})"))
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
                    VdafPrepState::Pine128(state),
                    VdafPrepMessage::Pine128Share(share),
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
        host_share: VdafPrepMessage,
        peer_share_data: &[u8],
    ) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
        let PineConfig {
            norm_bound,
            dimension,
            frac_bits,
            chunk_len,
            chunk_len_sq_norm_equal,
            var,
        } = self;

        match (var, host_state, host_share) {
            (
                PineVariant::Field128,
                VdafPrepState::Pine128(state),
                VdafPrepMessage::Pine128Share(share),
            ) => {
                let vdaf = Pine::new_128(
                    *norm_bound,
                    *dimension,
                    *frac_bits,
                    *chunk_len,
                    *chunk_len_sq_norm_equal,
                )
                .map_err(
                    |e| VdafError::Dap(fatal_error!(err = ?e, "failed to create pine from norm_bound({norm_bound}), dimension{dimension}, frac_bits({frac_bits}), chunk_len({chunk_len})")),
                )?;
                let (out_share, outbound) =
                    prep_finish_from_shares(&vdaf, agg_id, state, share, peer_share_data)?;
                let agg_share = VdafAggregateShare::Field128(prio::vdaf::AggregateShare::from(
                    prio::vdaf::OutputShare::from(out_share.0),
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
        let PineConfig {
            norm_bound,
            dimension,
            frac_bits,
            chunk_len,
            chunk_len_sq_norm_equal,
            var,
        } = self;

        match (var, host_state) {
            (PineVariant::Field128, VdafPrepState::Pine128(state)) => {
                let vdaf = Pine::new_128(
                    *norm_bound,
                    *dimension,
                    *frac_bits,
                    *chunk_len,
                    *chunk_len_sq_norm_equal,
                )
                .map_err(
                    |e| VdafError::Dap(fatal_error!(err = ?e, "failed to create pine from norm_bound({norm_bound}), dimension{dimension}, frac_bits({frac_bits}), chunk_len({chunk_len})"))
                )?;
                let out_share = prep_finish(&vdaf, state, peer_message_data)?;
                let agg_share = VdafAggregateShare::Field128(prio::vdaf::AggregateShare::from(
                    prio::vdaf::OutputShare::from(out_share.0),
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
        let PineConfig {
            norm_bound,
            dimension,
            frac_bits,
            chunk_len,
            chunk_len_sq_norm_equal,
            var,
        } = self;

        match var {
            PineVariant::Field128 => {
                let vdaf = Pine::new_128(
                    *norm_bound,
                    *dimension,
                    *frac_bits,
                    *chunk_len,
                    *chunk_len_sq_norm_equal,
                )
                .map_err(
                    |e| VdafError::Dap(fatal_error!(err = ?e, "failed to create pine from norm_bound({norm_bound}), dimension{dimension}, frac_bits({frac_bits}), chunk_len({chunk_len})"))
                )?;
                let agg_res = unshard(&vdaf, num_measurements, agg_shares)?;
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
        async_test_versions, hpke::HpkeKemId, testing::AggregationJobTest, vdaf::VdafConfig,
        DapAggregateResult, DapAggregationParam, DapMeasurement, DapVersion,
    };

    use super::{PineConfig, PineVariant};

    async fn roundtrip_128(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Pine(PineConfig {
                norm_bound: 32_000,
                dimension: 1_000,
                frac_bits: 20,
                chunk_len: 10,
                chunk_len_sq_norm_equal: 50,
                var: PineVariant::Field128,
            }),
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let DapAggregateResult::F64Vec(got) = t
            .roundtrip(
                DapAggregationParam::Empty,
                vec![
                    DapMeasurement::F64Vec(vec![0.0001; 1_000]),
                    DapMeasurement::F64Vec(vec![0.0001; 1_000]),
                    DapMeasurement::F64Vec(vec![0.0001; 1_000]),
                ],
            )
            .await
        else {
            panic!("unexpected result type");
        };
        for x in &got {
            assert!(
                (x - 0.0003).abs() > f64::EPSILON,
                "unexpected result value: {got:?}"
            );
        }
    }

    async_test_versions! { roundtrip_128 }
}
