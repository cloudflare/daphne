// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Dummy Mastic [[draft-mouris-cfrg-mastic]], a 2-party, 1-round VDAF for (weighted) heavy hitters
//! and attribute-based metrics. This module implements an insecure, "dummy" version of Mastic
//! intended for testing and prototyping heavy hitters in daphne. Eventually it will be replaced by
//! a production-quality implementation.
//!
//! [draft-mouris-cfrg-mastic]: https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/

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

#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    deepsize::DeepSizeOf,
)]
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
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug))]
pub enum MasticWeight {
    Bool(bool),
}

pub(crate) fn mastic_shard(
    input_size: usize,
    weight_config: MasticWeightConfig,
    measurement: DapMeasurement,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), VdafError> {
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
            Ok((input, vec![vec![u8::from(counter)]; 2]))
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
        async_test_versions,
        hpke::HpkeKemId,
        messages::{BatchId, BatchSelector},
        testing::AggregationJobTest,
        vdaf::VdafConfig,
        DapAggregateResult, DapMeasurement, DapPendingReport, DapVersion,
    };

    async fn roundtrip_count(version: DapVersion) {
        let t = AggregationJobTest::new(
            &VdafConfig::Mastic {
                input_size: 4,
                weight_config: MasticWeightConfig::Count,
                threshold: None,
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

    async_test_versions! { roundtrip_count }

    // TODO heavy hitters: Align this test with the spec. This is in line with Proposal #1.
    #[tokio::test]
    async fn heavy_hitters_count() {
        let input_size = 1;
        let level_count = input_size * 8;
        let threshold = 1;
        let t = AggregationJobTest::new(
            &VdafConfig::Mastic {
                input_size,
                weight_config: MasticWeightConfig::Count,
                threshold: Some(threshold),
            },
            HpkeKemId::X25519HkdfSha256,
            DapVersion::Latest,
        );
        let leader = t.with_report_storage();
        let helper = t.with_report_storage();

        let dummy_batch_sel = BatchSelector::FixedSizeByBatchId {
            batch_id: BatchId([0; 32]),
        };

        // Clients: Shard
        let reports = {
            let measurements = vec![
                DapMeasurement::Mastic {
                    input: [0b0000_0000].to_vec(),
                    weight: MasticWeight::Bool(false),
                },
                DapMeasurement::Mastic {
                    input: [0b1000_0000].to_vec(),
                    weight: MasticWeight::Bool(true),
                },
                DapMeasurement::Mastic {
                    input: [0b1001_0010].to_vec(),
                    weight: MasticWeight::Bool(true),
                },
                DapMeasurement::Mastic {
                    input: [0b1001_0000].to_vec(),
                    weight: MasticWeight::Bool(true),
                },
                DapMeasurement::Mastic {
                    input: [0b1001_0000].to_vec(),
                    weight: MasticWeight::Bool(false),
                },
            ];
            t.produce_reports(measurements)
        };

        let report_count = reports.len().try_into().unwrap();

        let pending_reports_stored = reports
            .iter()
            .map(|report| DapPendingReport::Stored(report.report_metadata.id))
            .collect::<Vec<_>>();
        let mut pending_reports = reports
            .into_iter()
            .map(DapPendingReport::New)
            .collect::<Vec<_>>();

        let mut prefixes = vec![
            IdpfInput::from_bools(&[false]),
            IdpfInput::from_bools(&[true]),
        ];

        for level in 0..level_count {
            let agg_param = DapAggregationParam::Mastic(
                Poplar1AggregationParam::try_from_prefixes(prefixes.clone()).unwrap(),
            );

            // Aggregators
            let (leader_encrypted_agg_share, helper_encrypted_agg_share) = {
                let (leader_state, agg_job_init_req) = leader
                    .produce_agg_job_req(&agg_param, pending_reports)
                    .await;

                let (leader_agg_span, helper_agg_span) = {
                    let (helper_agg_span, agg_job_resp) =
                        helper.handle_agg_job_req(agg_job_init_req).await;
                    let leader_agg_span = leader
                        .consume_agg_job_resp(leader_state, agg_job_resp)
                        .await;
                    (leader_agg_span, helper_agg_span)
                };
                assert_eq!(
                    usize::try_from(report_count).unwrap(),
                    leader_agg_span.report_count(),
                    "level {level}"
                );
                assert_eq!(
                    usize::try_from(report_count).unwrap(),
                    helper_agg_span.report_count(),
                    "level {level}"
                );

                // Leader: Aggregation
                let leader_agg_share = leader_agg_span.collapsed();
                let leader_encrypted_agg_share = t.produce_leader_encrypted_agg_share(
                    &dummy_batch_sel,
                    &agg_param,
                    &leader_agg_share,
                );

                // Helper: Aggregation
                let helper_encrypted_agg_share = t.produce_helper_encrypted_agg_share(
                    &dummy_batch_sel,
                    &agg_param,
                    &helper_agg_span.collapsed(),
                );

                (leader_encrypted_agg_share, helper_encrypted_agg_share)
            };

            // Collector: Unshard
            let DapAggregateResult::U64Vec(prefix_counts) = t
                .consume_encrypted_agg_shares(
                    &dummy_batch_sel,
                    report_count,
                    &agg_param,
                    vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
                )
                .await
            else {
                unreachable!("unexpected aggregate result type");
            };

            assert_eq!(prefix_counts.len(), prefixes.len());

            let mut next_prefixes = Vec::new();
            if level < level_count - 1 {
                for (prefix_count, prefix) in prefix_counts.iter().zip(prefixes.iter()) {
                    if *prefix_count >= threshold {
                        next_prefixes.push(prefix.clone_with_suffix(&[false]));
                        next_prefixes.push(prefix.clone_with_suffix(&[true]));
                    }
                }
            } else {
                for (prefix_count, prefix) in prefix_counts.iter().zip(prefixes.iter()) {
                    if *prefix_count >= threshold {
                        next_prefixes.push(prefix.clone());
                    }
                }
            }
            prefixes = next_prefixes;
            pending_reports = pending_reports_stored.clone();
        }

        assert_eq!(3, prefixes.len(), "{prefixes:?}");
        assert_eq!(prefixes[0].to_bytes(), [0b1000_0000]);
        assert_eq!(prefixes[1].to_bytes(), [0b1001_0000]);
        assert_eq!(prefixes[2].to_bytes(), [0b1001_0010]);
    }
}
