// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Dummy Mastic [[draft-mouris-cfrg-mastic]], a 2-party, 1-round VDAF. This module implements an
//! insecure, "dummy" version of Mastic intended for testing and prototyping. Eventually it will be
//! replaced by a production-quality implementation.
//!
//! [draft-mouris-cfrg-mastic]: https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/

use std::array;

use crate::{fatal_error, DapAggregateResult, DapAggregationParam, DapMeasurement};

use super::{
    decode_field_vec, VdafAggregateShare, VdafError, VdafPrepMessage, VdafPrepState, VdafVerifyKey,
};

use prio::{
    codec::Decode,
    field::{Field64, FieldElement},
    vdaf::AggregateShare,
};
use serde::{Deserialize, Serialize};

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

pub(crate) fn mastic_shard(
    input_size: usize,
    weight_config: MasticWeightConfig,
    measurement: DapMeasurement,
) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
    match (weight_config, measurement) {
        (
            MasticWeightConfig::Count,
            DapMeasurement::Mastic {
                input,
                weight: MasticWeight::Bool(counter),
            },
        ) if input.len() == input_size => {
            // Simulate Mastic, insecurely. Set the public share to the input and each input share
            // to the weight.
            Ok((input, array::from_fn(|_| vec![u8::from(counter)])))
        }
        _ => Err(VdafError::Dap(fatal_error!(
            err = "mastic: unexpected measurement type"
        ))),
    }
}

pub(crate) fn mastic_prep_init(
    input_size: usize,
    weight_config: MasticWeightConfig,
    verify_key: &VdafVerifyKey,
    agg_param: &DapAggregationParam,
    public_share_bytes: &[u8],
    input_share_bytes: &[u8],
) -> Result<(VdafPrepState, VdafPrepMessage), VdafError> {
    let VdafVerifyKey::L16(_verify_key) = verify_key else {
        return Err(VdafError::Dap(fatal_error!(
            err = "mastic: unexpected verify key type"
        )));
    };

    match (weight_config, agg_param) {
        (MasticWeightConfig::Count, DapAggregationParam::Mastic(agg_param)) => {
            // Simulate Mastic, insecurely. The public share encodes the plaintext input; the input
            // share encodes the plaintext weight.
            if public_share_bytes.len() != input_size {
                return Err(VdafError::Codec(prio::codec::CodecError::Other(
                    "mastic: malformed public share".into(),
                )));
            }

            if input_share_bytes.len() != 1 {
                return Err(VdafError::Codec(prio::codec::CodecError::Other(
                    "mastic: malformed input share".into(),
                )));
            }

            let weight = Field64::from(u64::from(input_share_bytes[0]));
            let out_share = agg_param
                .prefixes()
                .iter()
                .map(|prefix| {
                    let prefix_bytes = prefix.to_bytes();
                    if prefix_bytes.len() > input_size {
                        return Err(VdafError::Codec(prio::codec::CodecError::Other(
                            "mastic: malformed agg param: path with invalid length".into(),
                        )));
                    }

                    // If the path is a prefix of the input, then the value is the
                    // weight; otherwise the value is 0.
                    let value = if prefix_bytes == public_share_bytes[..prefix_bytes.len()] {
                        weight
                    } else {
                        Field64::zero()
                    };

                    // Each Aggregator computes a share of the value, so divide by 2.
                    Ok(value / Field64::from(2))
                })
                .collect::<Result<Vec<Field64>, _>>()?;

            Ok((
                VdafPrepState::Mastic { out_share },
                VdafPrepMessage::MasticShare(weight),
            ))
        }
        _ => Err(VdafError::Dap(fatal_error!(
            err = "mastic: unexpected agg param type"
        ))),
    }
}

pub(crate) fn mastic_prep_finish_from_shares(
    weight_config: MasticWeightConfig,
    host_state: VdafPrepState,
    host_share: VdafPrepMessage,
    peer_share_bytes: &[u8],
) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
    match (weight_config, host_state, host_share) {
        (
            MasticWeightConfig::Count,
            VdafPrepState::Mastic { out_share },
            VdafPrepMessage::MasticShare(host_weight),
        ) => {
            // Simulate Mastic. Check that both Aggregators got the same weight, and the weight is
            // valid. This is not secure because the weight is revealed to the caller.
            let peer_weight = Field64::get_decoded(peer_share_bytes)?;
            if peer_weight != host_weight {
                return Err(VdafError::Vdaf(prio::vdaf::VdafError::Uncategorized(
                    "mastic: weights do not match".into(),
                )));
            }

            if peer_weight != Field64::one() && peer_weight != Field64::zero() {
                return Err(VdafError::Vdaf(prio::vdaf::VdafError::Uncategorized(
                    "mastic: weight is out of range".into(),
                )));
            }

            Ok((
                VdafAggregateShare::Field64(AggregateShare::from(out_share)),
                // Empty prep message for now.
                Vec::new(),
            ))
        }
        _ => Err(VdafError::Dap(fatal_error!(
            err = "mastic: unexpected prep state"
        ))),
    }
}

pub(crate) fn mastic_prep_finish(
    host_state: VdafPrepState,
    peer_message_bytes: &[u8],
) -> Result<VdafAggregateShare, VdafError> {
    match host_state {
        VdafPrepState::Mastic { out_share } => {
            // Simulate Mastic: If the prep message is empty, then accept the output share.
            if !peer_message_bytes.is_empty() {
                return Err(VdafError::Vdaf(prio::vdaf::VdafError::Uncategorized(
                    "mastic: invalid prep message".into(),
                )));
            }

            Ok(VdafAggregateShare::Field64(AggregateShare::from(out_share)))
        }
        _ => Err(VdafError::Dap(fatal_error!(
            err = "mastic: unexpected prep state"
        ))),
    }
}

pub(crate) fn mastic_unshard<M: IntoIterator<Item = Vec<u8>>>(
    weight_config: MasticWeightConfig,
    agg_param: &DapAggregationParam,
    agg_share_bytes: M,
) -> Result<DapAggregateResult, VdafError> {
    match (weight_config, agg_param) {
        (MasticWeightConfig::Count, DapAggregationParam::Mastic(agg_param)) => {
            let agg: Vec<Field64> = agg_share_bytes
                .into_iter()
                .map(|bytes| decode_field_vec(&bytes, agg_param.prefixes().len()))
                .reduce(|r, agg_share| {
                    let mut agg = r?;
                    for (x, y) in agg.iter_mut().zip(agg_share?.into_iter()) {
                        *x += y;
                    }
                    Ok(agg)
                })
                .ok_or_else(|| {
                    VdafError::Dap(fatal_error!(
                        err = "mastic: unexpected number of agg shares"
                    ))
                })??;

            Ok(DapAggregateResult::U64Vec(
                agg.into_iter().map(u64::from).collect(),
            ))
        }
        _ => Err(VdafError::Dap(fatal_error!(
            err = "mastic: unexpected agg param type"
        ))),
    }
}

#[cfg(test)]
mod test {
    use prio::{idpf::IdpfInput, vdaf::poplar1::Poplar1AggregationParam};

    use super::*;
    use crate::{
        async_test_version, hpke::HpkeKemId, testing::AggregationJobTest, vdaf::VdafConfig,
        DapAggregateResult, DapMeasurement, DapVersion,
    };

    async fn roundtrip_count(version: DapVersion) {
        let mut t = AggregationJobTest::new(
            &VdafConfig::Mastic {
                input_size: 4,
                weight_config: MasticWeightConfig::Count,
            },
            HpkeKemId::X25519HkdfSha256,
            version,
        );
        let got = t
            .roundtrip(
                DapAggregationParam::Mastic(
                    Poplar1AggregationParam::try_from_prefixes(vec![
                        IdpfInput::from_bytes(b"cool"),
                        IdpfInput::from_bytes(b"trip"),
                    ])
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
            )
            .await;

        assert_eq!(got, DapAggregateResult::U64Vec(vec![1, 2]));
    }

    async_test_version! { roundtrip_count, Draft09 }
    async_test_version! { roundtrip_count, Latest }
}
