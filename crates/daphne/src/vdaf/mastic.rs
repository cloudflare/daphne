// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Dummy Mastic [[draft-mouris-cfrg-mastic]], a 2-party, 1-round VDAF. This module implements an
//! insecure, "dummy" version of Mastic intended for testing and prototyping. Eventually it will be
//! replaced by a production-quality implementation.
//!
//! [draft-mouris-cfrg-mastic]: https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/

use crate::{
    fatal_error,
    messages::TaskId,
    vdaf::{prep_finish, prep_finish_from_shares, prep_init, shard_then_encode},
    DapAggregateResult, DapAggregationParam, DapMeasurement,
};

use super::{unshard, VdafAggregateShare, VdafError, VdafPrepShare, VdafPrepState, VdafVerifyKey};

use prio::{vdaf::mastic::Mastic, vidpf::VidpfInput};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct MasticConfig {
    pub bits: usize,
    pub weight_config: MasticWeightConfig,
}

impl std::fmt::Display for MasticConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, Weight({})", self.bits, self.weight_config)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
/// The type of each input's weight.
pub enum MasticWeightConfig {
    /// Each weight is a `0` or `1`.
    Count,
}

impl std::fmt::Display for MasticWeightConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MasticWeightConfig::Count => write!(f, "Count"),
        }
    }
}

/// A weight.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MasticWeight {
    Bool(bool),
}

impl MasticConfig {
    pub(crate) fn shard(
        self,
        measurement: DapMeasurement,
        nonce: &[u8; 16],
        task_id: TaskId,
    ) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
        match (self.weight_config, measurement) {
            (
                MasticWeightConfig::Count,
                DapMeasurement::Mastic {
                    input,
                    weight: MasticWeight::Bool(counter),
                },
            ) => {
                let vdaf = Mastic::new_count(self.bits).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let alpha = VidpfInput::from_bytes(&input);
                shard_then_encode(&vdaf, task_id, &(alpha, counter), nonce)
            }
            _ => todo!(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prep_init(
        self,
        VdafVerifyKey(verify_key): &VdafVerifyKey,
        task_id: TaskId,
        agg_id: usize,
        agg_param: &DapAggregationParam,
        nonce: &[u8; 16],
        public_share_data: &[u8],
        input_share_data: &[u8],
    ) -> Result<(VdafPrepState, VdafPrepShare), VdafError> {
        match (self.weight_config, agg_param) {
            (MasticWeightConfig::Count, DapAggregationParam::Mastic(agg_param)) => {
                let vdaf = Mastic::new_count(self.bits).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let (prep_state, prep_share) = prep_init(
                    &vdaf,
                    task_id,
                    verify_key,
                    agg_id,
                    agg_param,
                    nonce,
                    public_share_data,
                    input_share_data,
                )?;

                Ok((
                    VdafPrepState::MasticField64(prep_state),
                    VdafPrepShare::MasticField64(prep_share),
                ))
            }
            (_, DapAggregationParam::Empty) => todo!(),
        }
    }

    pub(crate) fn prep_finish_from_shares(
        self,
        task_id: TaskId,
        agg_param: &DapAggregationParam,
        host_state: VdafPrepState,
        host_share: VdafPrepShare,
        peer_share_data: &[u8],
    ) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
        match (self.weight_config, agg_param, host_state, host_share) {
            (
                MasticWeightConfig::Count,
                DapAggregationParam::Mastic(agg_param),
                VdafPrepState::MasticField64(host_state),
                VdafPrepShare::MasticField64(host_share),
            ) => {
                let vdaf = Mastic::new_count(self.bits).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let (out_share, prep_msg_data) = prep_finish_from_shares(
                    &vdaf,
                    task_id,
                    agg_param,
                    host_state,
                    host_share,
                    peer_share_data,
                )?;
                Ok((VdafAggregateShare::Field64(out_share.into()), prep_msg_data))
            }
            _ => todo!(),
        }
    }

    pub(crate) fn prep_finish(
        self,
        host_state: VdafPrepState,
        peer_message_data: &[u8],
        task_id: TaskId,
    ) -> Result<VdafAggregateShare, VdafError> {
        match (self.weight_config, host_state) {
            (MasticWeightConfig::Count, VdafPrepState::MasticField64(host_state)) => {
                let vdaf = Mastic::new_count(self.bits).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let out_share = prep_finish(&vdaf, task_id, host_state, peer_message_data)?;
                Ok(VdafAggregateShare::Field64(out_share.into()))
            }
            _ => todo!(),
        }
    }

    pub(crate) fn unshard<M: IntoIterator<Item = Vec<u8>>>(
        self,
        agg_param: &DapAggregationParam,
        agg_shares: M,
        num_measurements: usize,
    ) -> Result<DapAggregateResult, VdafError> {
        match (self.weight_config, agg_param) {
            (MasticWeightConfig::Count, DapAggregationParam::Mastic(agg_param)) => {
                let vdaf = Mastic::new_count(self.bits).map_err(|e| {
                    VdafError::Dap(fatal_error!(err = ?e, "initializing {self:?} failed"))
                })?;

                let agg_result = unshard(&vdaf, agg_param, num_measurements, agg_shares)?;
                Ok(DapAggregateResult::U64Vec(agg_result))
            }
            _ => todo!(),
        }
    }
}

#[cfg(test)]
mod test {
    use prio::{idpf::IdpfInput, vdaf::mastic::MasticAggregationParam};

    use super::*;
    use crate::{
        hpke::HpkeKemId, testing::AggregationJobTest, vdaf::VdafConfig, DapAggregateResult,
        DapMeasurement, DapVersion,
    };

    #[test]
    fn roundtrip_count() {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Mastic(MasticConfig {
                bits: 32,
                weight_config: MasticWeightConfig::Count,
            }),
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Latest,
        );
        let got = t.roundtrip(
            DapAggregationParam::Mastic(
                MasticAggregationParam::new(
                    vec![
                        IdpfInput::from_bytes(b"cool"),
                        IdpfInput::from_bytes(b"trip"),
                    ],
                    true,
                )
                .unwrap(),
            ),
            vec![
                DapMeasurement::Mastic {
                    input: b"cool".to_vec(),
                    weight: MasticWeight::Bool(false),
                },
                DapMeasurement::Mastic {
                    input: b"cool".to_vec(),
                    weight: MasticWeight::Bool(true),
                },
                DapMeasurement::Mastic {
                    input: b"trip".to_vec(),
                    weight: MasticWeight::Bool(true),
                },
                DapMeasurement::Mastic {
                    input: b"trip".to_vec(),
                    weight: MasticWeight::Bool(true),
                },
                DapMeasurement::Mastic {
                    input: b"cool".to_vec(),
                    weight: MasticWeight::Bool(false),
                },
            ],
        );

        assert_eq!(got, DapAggregateResult::U64Vec(vec![1, 2]));
    }
}
