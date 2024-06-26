// Copyright (c) 2024 Cloudflare, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of the PINE VDAF.

use std::{borrow::Cow, iter};

use prio::{
    codec::{CodecError, Decode, Encode, ParameterizedDecode},
    field::FftFriendlyFieldElement,
    flp::Type,
    vdaf::{
        xof::{IntoFieldVec, Seed, Xof, XofTurboShake128},
        Aggregatable, Aggregator, Client, Collector, PrepareTransition, Vdaf, VdafError,
    },
};
use rand::prelude::*;

use crate::pine::USAGE_QUERY_RAND;

use super::{
    dst, field_to_f64, msg, Pine, USAGE_MEAS_SHARE, USAGE_PROOF_SHARE, USAGE_PROVE_RAND,
    USAGE_VF_JOINT_RAND, USAGE_VF_JOINT_RAND_PART, USAGE_VF_JOINT_RAND_SEED,
    USAGE_WR_JOINT_RAND_PART, USAGE_WR_JOINT_RAND_SEED, VDAF_ID,
};

const NUM_SHARD_RAND_SEEDS: usize = 7;

/// Represents PINE's aggregatable type (a vector of field elements).
//
// NOTE(cjpatton) libprio API awkwardness: We can't use `AggregateShare` and `OutputShares` because
// we need to be able to implement decoding parameterized by PINE state. In any case, the
// distinction between aggregate shares and output shares is not really that useful.
#[derive(Clone, Debug)]
pub struct PineVec<F>(pub(crate) Vec<F>);

impl<F: FftFriendlyFieldElement> Encode for PineVec<F> {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        for x in &self.0 {
            x.encode(bytes)?;
        }
        Ok(())
    }
}

impl<F: FftFriendlyFieldElement, const PROOFS: u8> ParameterizedDecode<(&Pine<F, PROOFS>, &())>
    for PineVec<F>
{
    fn decode_with_param(
        (pine, _agg_param): &(&Pine<F, PROOFS>, &()),
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        iter::repeat_with(|| F::decode(bytes))
            .take(pine.flp.cfg.dimension)
            .collect::<Result<Vec<_>, _>>()
            .map(PineVec)
    }
}

impl<F: FftFriendlyFieldElement> Aggregatable for PineVec<F> {
    type OutputShare = PineVec<F>;

    fn merge(&mut self, agg_share: &Self) -> Result<(), VdafError> {
        for (x, a) in self.0.iter_mut().zip(agg_share.0.iter()) {
            *x += *a;
        }
        Ok(())
    }

    fn accumulate(&mut self, out_share: &Self::OutputShare) -> Result<(), VdafError> {
        for (x, o) in self.0.iter_mut().zip(out_share.0.iter()) {
            *x += *o;
        }
        Ok(())
    }
}

// Vdaf

impl<F: FftFriendlyFieldElement, const PROOFS: u8> Vdaf for Pine<F, PROOFS> {
    type Measurement = Vec<f64>;
    type AggregateResult = Vec<f64>;
    type AggregationParam = ();
    type PublicShare = msg::PublicShare;
    type InputShare = msg::InputShare<F>;
    type OutputShare = PineVec<F>;
    type AggregateShare = PineVec<F>;

    fn algorithm_id(&self) -> u32 {
        VDAF_ID
    }

    fn num_aggregators(&self) -> usize {
        2
    }
}

impl<F: FftFriendlyFieldElement, const PROOFS: u8> Pine<F, PROOFS> {
    fn joint_rand_part(
        agg_id: u8,
        blind: &[u8; 16],
        nonce: &[u8; 16],
        meas_share: &[F],
        usage: u16,
    ) -> Seed<16> {
        let mut xof = XofTurboShake128::init(blind, &dst(usage));
        xof.update(&[agg_id]);
        xof.update(nonce);
        let mut buf = Vec::with_capacity(F::ENCODED_SIZE);
        for x in meas_share {
            x.encode(&mut buf).unwrap();
            xof.update(&buf);
            buf.clear();
        }
        xof.into_seed()
    }

    fn joint_rand_seed(joint_rand_parts: &[Seed<16>; 2], usage: u16) -> Seed<16> {
        let mut xof = XofTurboShake128::init(&[0; 16], &dst(usage));
        xof.update(joint_rand_parts[0].as_ref());
        xof.update(joint_rand_parts[1].as_ref());
        xof.into_seed()
    }

    fn helper_meas_share(&self, seed: &[u8; 16]) -> Vec<F> {
        let mut xof = XofTurboShake128::init(seed, &dst(USAGE_MEAS_SHARE));
        xof.update(&[1]); // agg_id
        xof.into_seed_stream()
            .into_field_vec(self.flp.cfg.encoded_input_len)
    }

    fn helper_proof_share(&self, seed: &[u8; 16]) -> Vec<F> {
        let mut xof = XofTurboShake128::init(seed, &dst(USAGE_PROOF_SHARE));
        xof.update(&[PROOFS, 1]); // PROOFS, agg_id
        xof.into_seed_stream()
            .into_field_vec(self.flp.proof_len() * usize::from(PROOFS))
    }
}

// Client

impl<F: FftFriendlyFieldElement, const PROOFS: u8> Client<16> for Pine<F, PROOFS> {
    fn shard(
        &self,
        gradient: &Vec<f64>,
        nonce: &[u8; 16],
    ) -> Result<(msg::PublicShare, Vec<msg::InputShare<F>>), VdafError> {
        let mut rng = thread_rng();
        self.shard_with_rand(gradient, nonce, rng.gen())
    }
}

impl<F: FftFriendlyFieldElement, const PROOFS: u8> Pine<F, PROOFS> {
    pub(crate) fn shard_with_rand(
        &self,
        gradient: &[f64],
        nonce: &[u8; 16],
        rand: [[u8; 16]; NUM_SHARD_RAND_SEEDS],
    ) -> Result<(msg::PublicShare, Vec<msg::InputShare<F>>), VdafError> {
        let mut meas = Vec::with_capacity(self.flp.input_len());
        self.flp
            .append_encoded_gradient(&mut meas, gradient.iter().copied())?;

        let [meas_share_seed_1, proofs_share_seed_1, wr_blind_1, vf_blind_1, wr_blind_0, vf_blind_0, prove_seed] =
            rand;

        // Begin encoding the Leader's measurement share (up to the wraparound tests). Complete the
        // Helper's measurement share.
        let meas_share_1 = self.helper_meas_share(&meas_share_seed_1);
        let mut meas_share_0 = Vec::with_capacity(self.flp.cfg.encoded_input_len);
        for (m, s1) in meas.iter().zip(meas_share_1.iter().take(meas.len())) {
            meas_share_0.push(*m - *s1);
        }
        debug_assert_eq!(meas.len(), self.flp.cfg.encoded_gradient_len);
        debug_assert_eq!(meas_share_0.len(), self.flp.cfg.encoded_gradient_len);
        debug_assert_eq!(meas_share_1.len(), self.flp.cfg.encoded_input_len);

        let wr_joint_rand_parts = [
            Self::joint_rand_part(
                0,
                &wr_blind_0,
                nonce,
                &meas_share_0,
                USAGE_WR_JOINT_RAND_PART,
            ),
            Self::joint_rand_part(
                1,
                &wr_blind_1,
                nonce,
                &meas_share_1[..self.flp.cfg.encoded_gradient_len],
                USAGE_WR_JOINT_RAND_PART,
            ),
        ];

        // Run the wraparound tests and complete the Leader's measurement share.
        {
            let wr_joint_rand_seed =
                Self::joint_rand_seed(&wr_joint_rand_parts, USAGE_WR_JOINT_RAND_SEED);

            let i = meas.len();
            let wr_test_results = self
                .flp
                .append_wr_test_results(&mut meas, &wr_joint_rand_seed)?;

            for (m, s1) in meas[i..].iter().zip(meas_share_1[i..].iter()) {
                meas_share_0.push(*m - *s1);
            }

            meas.extend_from_slice(&wr_test_results);
        }
        debug_assert_eq!(meas.len(), self.flp.input_len());
        debug_assert_eq!(meas_share_0.len(), self.flp.cfg.encoded_input_len);

        let vf_joint_rand_parts = [
            Self::joint_rand_part(
                0,
                &vf_blind_0,
                nonce,
                &meas_share_0,
                USAGE_VF_JOINT_RAND_PART,
            ),
            Self::joint_rand_part(
                1,
                &vf_blind_1,
                nonce,
                &meas_share_1,
                USAGE_VF_JOINT_RAND_PART,
            ),
        ];

        // Generate the Leader's proof share.
        let proofs_share_0 = {
            let vf_joint_rands = {
                let vf_joint_rand_seed =
                    Self::joint_rand_seed(&vf_joint_rand_parts, USAGE_VF_JOINT_RAND_SEED);

                XofTurboShake128::seed_stream(
                    &vf_joint_rand_seed,
                    &dst(USAGE_VF_JOINT_RAND),
                    &[PROOFS],
                )
                .into_field_vec(self.flp.joint_rand_len() * usize::from(PROOFS))
            };

            let prove_rands = {
                let mut xof = XofTurboShake128::init(&prove_seed, &dst(USAGE_PROVE_RAND));
                xof.update(&[PROOFS]);
                xof.into_seed_stream()
                    .into_field_vec(self.flp.prove_rand_len() * usize::from(PROOFS))
            };

            let mut proofs = Vec::with_capacity(self.flp.proof_len() * usize::from(PROOFS));
            for (prove_rand, vf_joint_rand) in prove_rands
                .chunks(self.flp.prove_rand_len())
                .zip(vf_joint_rands.chunks(self.flp.joint_rand_len()))
            {
                proofs.append(&mut self.flp.prove(&meas, prove_rand, vf_joint_rand)?);
            }

            for (p, s1) in proofs
                .iter_mut()
                .zip(self.helper_proof_share(&proofs_share_seed_1).into_iter())
            {
                *p -= s1;
            }

            proofs
        };

        Ok((
            msg::PublicShare {
                wr_joint_rand_parts,
                vf_joint_rand_parts,
            },
            vec![
                msg::InputShare(msg::InputShareFor::Leader {
                    meas_share: meas_share_0,
                    proofs_share: proofs_share_0,
                    wr_blind: Seed::get_decoded(&wr_blind_0).unwrap(),
                    vf_blind: Seed::get_decoded(&vf_blind_0).unwrap(),
                }),
                msg::InputShare(msg::InputShareFor::Helper {
                    meas_share: Seed::get_decoded(&meas_share_seed_1).unwrap(),
                    proofs_share: Seed::get_decoded(&proofs_share_seed_1).unwrap(),
                    wr_blind: Seed::get_decoded(&wr_blind_1).unwrap(),
                    vf_blind: Seed::get_decoded(&vf_blind_1).unwrap(),
                }),
            ],
        ))
    }
}

// Aggregator

#[derive(Clone, Debug)]
pub struct PinePrepState<F> {
    gradient_share: Vec<F>,
    corrected_wr_joint_rand_seed: Seed<16>,
    corrected_vf_joint_rand_seed: Seed<16>,
    pub(crate) verifiers_len: usize,
}

impl<F: FftFriendlyFieldElement> PartialEq for PinePrepState<F> {
    fn eq(&self, _other: &Self) -> bool {
        todo!("constant time compare")
    }
}

impl<F: FftFriendlyFieldElement> Eq for PinePrepState<F> {}

impl<F: FftFriendlyFieldElement, const PROOFS: u8> Aggregator<16, 16> for Pine<F, PROOFS> {
    type PrepareState = PinePrepState<F>;
    type PrepareShare = msg::PrepShare<F>;
    type PrepareMessage = msg::Prep;

    fn prepare_init(
        &self,
        verify_key: &[u8; 16],
        agg_id: usize,
        _agg_param: &(),
        nonce: &[u8; 16],
        public_share: &msg::PublicShare,
        input_share: &msg::InputShare<F>,
    ) -> Result<(PinePrepState<F>, msg::PrepShare<F>), VdafError> {
        let msg::PublicShare {
            wr_joint_rand_parts,
            vf_joint_rand_parts,
        } = public_share;

        let (mut meas_share, proofs_share, wr_blind, vf_blind) = match (agg_id, input_share) {
            (
                0,
                msg::InputShare(msg::InputShareFor::Leader {
                    meas_share,
                    proofs_share,
                    wr_blind,
                    vf_blind,
                }),
            ) => {
                // Copy the measurement share into a buffer that is large for the FLP input.
                let mut buf = Vec::with_capacity(self.flp.input_len());
                buf.extend_from_slice(meas_share);
                (buf, Cow::Borrowed(proofs_share), wr_blind, vf_blind)
            }
            (
                1,
                msg::InputShare(msg::InputShareFor::Helper {
                    meas_share: meas_share_seed,
                    proofs_share: proofs_share_seed,
                    wr_blind,
                    vf_blind,
                }),
            ) => (
                self.helper_meas_share(meas_share_seed.as_ref()),
                Cow::Owned(self.helper_proof_share(proofs_share_seed.as_ref())),
                wr_blind,
                vf_blind,
            ),
            (agg_id, ..) if agg_id >= 2 => {
                return Err(VdafError::Uncategorized(format!(
                    "unrecognized aggregator id {agg_id}"
                )))
            }
            _ => {
                return Err(VdafError::Uncategorized(format!(
                    "unexpected message type for input share (agg_id={agg_id}): {input_share}"
                )))
            }
        };

        let wr_joint_rand_part = Self::joint_rand_part(
            agg_id.try_into().unwrap(),
            wr_blind.as_ref(),
            nonce,
            &meas_share[..self.flp.cfg.encoded_gradient_len],
            USAGE_WR_JOINT_RAND_PART,
        );

        let corrected_wr_joint_rand_seed = {
            let mut corrected_wr_joint_rand_parts = wr_joint_rand_parts.clone();
            corrected_wr_joint_rand_parts[agg_id] = wr_joint_rand_part.clone();
            Self::joint_rand_seed(&corrected_wr_joint_rand_parts, USAGE_WR_JOINT_RAND_SEED)
        };

        // Run the wraparound tests.
        {
            let wr_test_results = self.flp.run_wr_tests(
                &meas_share[..self.flp.cfg.dimension],
                &corrected_wr_joint_rand_seed,
            );

            meas_share.extend_from_slice(&wr_test_results);
        }

        let vf_joint_rand_part = Self::joint_rand_part(
            agg_id.try_into().unwrap(),
            vf_blind.as_ref(),
            nonce,
            &meas_share[..self.flp.cfg.encoded_input_len],
            USAGE_VF_JOINT_RAND_PART,
        );

        let corrected_vf_joint_rand_seed = {
            let mut corrected_vf_joint_rand_parts = vf_joint_rand_parts.clone();
            corrected_vf_joint_rand_parts[agg_id] = vf_joint_rand_part.clone();
            Self::joint_rand_seed(&corrected_vf_joint_rand_parts, USAGE_VF_JOINT_RAND_SEED)
        };

        // Query the proofs.
        let verifiers_share = {
            let corrected_vf_joint_rands = {
                XofTurboShake128::seed_stream(
                    &corrected_vf_joint_rand_seed,
                    &dst(USAGE_VF_JOINT_RAND),
                    &[PROOFS],
                )
                .into_field_vec(self.flp.joint_rand_len() * usize::from(PROOFS))
            };

            let query_rands = {
                let mut xof = XofTurboShake128::init(verify_key, &dst(USAGE_QUERY_RAND));
                xof.update(&[PROOFS]);
                xof.update(nonce);
                xof.into_seed_stream()
                    .into_field_vec(self.flp.query_rand_len() * usize::from(PROOFS))
            };

            let mut verifiers_share =
                Vec::with_capacity(self.flp.verifier_len() * usize::from(PROOFS));
            for (proof_share, (vf_joint_rand, query_rand)) in
                proofs_share.chunks(self.flp.proof_len()).zip(
                    corrected_vf_joint_rands
                        .chunks(self.flp.joint_rand_len())
                        .zip(query_rands.chunks(self.flp.query_rand_len())),
                )
            {
                verifiers_share.append(&mut self.flp.query(
                    &meas_share,
                    proof_share,
                    query_rand,
                    vf_joint_rand,
                    2,
                )?);
            }

            verifiers_share
        };

        Ok((
            PinePrepState {
                gradient_share: self.flp.truncate(meas_share)?,
                corrected_wr_joint_rand_seed,
                corrected_vf_joint_rand_seed,
                verifiers_len: verifiers_share.len(),
            },
            msg::PrepShare {
                verifiers_share,
                wr_joint_rand_part,
                vf_joint_rand_part,
            },
        ))
    }

    fn prepare_shares_to_prepare_message<M: IntoIterator<Item = msg::PrepShare<F>>>(
        &self,
        _agg_param: &(),
        inputs: M,
    ) -> Result<msg::Prep, VdafError> {
        let [prep_share_0, prep_share_1] = inputs
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| VdafError::Uncategorized("unexpected number of prep shares".into()))?;

        let msg::PrepShare {
            verifiers_share: mut verifiers,
            wr_joint_rand_part: wr_joint_rand_part_0,
            vf_joint_rand_part: vf_joint_rand_part_0,
        } = prep_share_0;

        let msg::PrepShare {
            verifiers_share: verifiers_share_1,
            wr_joint_rand_part: wr_joint_rand_part_1,
            vf_joint_rand_part: vf_joint_rand_part_1,
        } = prep_share_1;

        // Check the verifiers.
        {
            // Combine the shares of each verifier.
            for (v, s1) in verifiers.iter_mut().zip(verifiers_share_1.into_iter()) {
                *v += s1;
            }

            for verifier in verifiers.chunks(self.flp.verifier_len()) {
                if !self.flp.decide(verifier)? {
                    return Err(VdafError::Uncategorized("proof check failed".into()));
                }
            }
        }

        let wr_joint_rand_seed = Self::joint_rand_seed(
            &[wr_joint_rand_part_0, wr_joint_rand_part_1],
            USAGE_WR_JOINT_RAND_SEED,
        );

        let vf_joint_rand_seed = Self::joint_rand_seed(
            &[vf_joint_rand_part_0, vf_joint_rand_part_1],
            USAGE_VF_JOINT_RAND_SEED,
        );

        Ok(msg::Prep {
            wr_joint_rand_seed,
            vf_joint_rand_seed,
        })
    }

    fn prepare_next(
        &self,
        state: PinePrepState<F>,
        input: msg::Prep,
    ) -> Result<PrepareTransition<Self, 16, 16>, VdafError> {
        if state.corrected_wr_joint_rand_seed != input.wr_joint_rand_seed {
            return Err(VdafError::Uncategorized(
                "wraparound joint randomness check failed".into(),
            ));
        }

        if state.corrected_vf_joint_rand_seed != input.vf_joint_rand_seed {
            return Err(VdafError::Uncategorized(
                "verification joint randomness check failed".into(),
            ));
        }

        Ok(PrepareTransition::Finish(PineVec(state.gradient_share)))
    }

    /// Aggregates a sequence of output shares into an aggregate share.
    fn aggregate<M: IntoIterator<Item = PineVec<F>>>(
        &self,
        _agg_param: &(),
        out_shares: M,
    ) -> Result<PineVec<F>, VdafError> {
        let mut agg_share = PineVec(vec![F::zero(); self.flp.cfg.dimension]);
        for out_share in out_shares {
            agg_share.accumulate(&out_share)?;
        }
        Ok(agg_share)
    }
}

// Collector

impl<F: FftFriendlyFieldElement, const PROOFS: u8> Collector for Pine<F, PROOFS> {
    fn unshard<M: IntoIterator<Item = PineVec<F>>>(
        &self,
        _agg_param: &(),
        agg_shares: M,
        _num_measurements: usize,
    ) -> Result<Vec<f64>, VdafError> {
        let two_to_frac_bits = f64::from(1 << self.flp.cfg.frac_bits);
        let [mut agg_result, agg_share_1] =
            agg_shares
                .into_iter()
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| VdafError::Uncategorized("unexpected number of agg shares".into()))?;

        for (r, s1) in agg_result.0.iter_mut().zip(agg_share_1.0.into_iter()) {
            *r += s1;
        }

        agg_result
            .0
            .into_iter()
            .map(|r| field_to_f64(r, two_to_frac_bits))
            .collect()
    }
}

#[cfg(test)]
mod tests {

    use prio::{
        codec::Decode,
        field::Field128,
        vdaf::{
            test_utils::{run_vdaf, run_vdaf_prepare},
            xof::Seed,
            Aggregator, Client, Collector,
        },
    };

    use crate::pine::{msg, vdaf::PineVec, Pine128, Pine64};

    use assert_matches::assert_matches;

    #[test]
    fn run_128() {
        let dimension = 100;
        let pine = Pine128::new(1000.0, dimension, 15, 4).unwrap();
        let result = run_vdaf(
            &pine,
            &(),
            [
                vec![1.0; dimension],
                vec![1.0; dimension],
                vec![1.0; dimension],
                vec![1.0; dimension],
                vec![1.0; dimension],
            ],
        )
        .unwrap();
        assert_eq!(result, vec![5.0; dimension]);
    }

    #[test]
    fn run_64() {
        let dimension = 100;
        let pine = Pine64::new(1000.0, dimension, 15, 100).unwrap();
        let result = run_vdaf(
            &pine,
            &(),
            [
                vec![1.0; dimension],
                vec![1.0; dimension],
                vec![1.0; dimension],
                vec![1.0; dimension],
                vec![1.0; dimension],
            ],
        )
        .unwrap();
        assert_eq!(result, vec![5.0; dimension]);
    }

    // Test `Aggregator::aggregate()` for correctness. This method is not normally exercised.
    #[test]
    fn aggregate() {
        let dimension = 100;
        let reports = 5;
        let pine = Pine128::new(1000.0, dimension, 15, 100).unwrap();

        let mut out_shares_0 = Vec::new();
        let mut out_shares_1 = Vec::new();
        for _ in 0..reports {
            let (_, input_shares) = pine.shard(&vec![1.0; dimension], &[0; 16]).unwrap();
            let out_share_0 = match input_shares.first().unwrap() {
                msg::InputShare(msg::InputShareFor::Leader { ref meas_share, .. }) => {
                    PineVec(meas_share[..dimension].to_vec())
                }
                _ => unreachable!(),
            };
            let out_share_1 = match input_shares.get(1).unwrap() {
                msg::InputShare(msg::InputShareFor::Helper { ref meas_share, .. }) => {
                    PineVec(pine.helper_meas_share(meas_share.as_ref())[..dimension].to_vec())
                }
                _ => unreachable!(),
            };
            out_shares_0.push(out_share_0);
            out_shares_1.push(out_share_1);
        }

        let agg_share_0 = pine.aggregate(&(), out_shares_0).unwrap();
        let agg_share_1 = pine.aggregate(&(), out_shares_1).unwrap();
        let agg_result = pine
            .unshard(&(), [agg_share_0, agg_share_1], reports)
            .unwrap();
        assert_eq!(agg_result, vec![1.0 * reports as f64; dimension]);
    }

    #[test]
    fn prep_failure_mutated_pub_share_wr_joint_rand() {
        let dimension = 100;
        let pine = Pine128::new(1000.0, dimension, 15, 4).unwrap();

        let nonce = [0; 16];
        let (mut public_share, input_shares) = pine.shard(&vec![1.0; dimension], &nonce).unwrap();
        assert_matches!(public_share, msg::PublicShare{ ref mut wr_joint_rand_parts, .. }  => wr_joint_rand_parts[0] = Seed::get_decoded(&[0; 16]).unwrap());
        assert!(run_vdaf_prepare(
            &pine,
            &[0; 16],
            &(),
            &nonce,
            public_share.clone(),
            input_shares,
        )
        .is_err());
    }

    #[test]
    fn prep_failure_mutated_pub_share_vf_joint_rand() {
        let dimension = 100;
        let pine = Pine128::new(1000.0, dimension, 15, 4).unwrap();

        let nonce = [0; 16];
        let (mut public_share, input_shares) = pine.shard(&vec![1.0; dimension], &nonce).unwrap();
        assert_matches!(public_share, msg::PublicShare{ wr_joint_rand_parts: _, ref mut vf_joint_rand_parts, .. }  => vf_joint_rand_parts[0] = Seed::get_decoded(&[0; 16]).unwrap());
        assert!(run_vdaf_prepare(
            &pine,
            &[0; 16],
            &(),
            &nonce,
            public_share.clone(),
            input_shares,
        )
        .is_err());
    }

    #[test]
    fn prep_failure_mutated_input_share_proof() {
        let dimension = 100;
        let pine = Pine128::new(1000.0, dimension, 15, 4).unwrap();

        let nonce = [0; 16];
        let (public_share, mut input_shares) = pine.shard(&vec![1.0; dimension], &nonce).unwrap();
        assert_matches!(input_shares[0], msg::InputShare(msg::InputShareFor::Leader{ meas_share: _, ref mut proofs_share, ..}) => proofs_share[0] += Field128::from(1337));
        assert!(run_vdaf_prepare(
            &pine,
            &[0; 16],
            &(),
            &nonce,
            public_share.clone(),
            input_shares,
        )
        .is_err());
    }

    #[test]
    fn prep_failure_mutated_input_share_meas() {
        let dimension = 100;
        let pine = Pine128::new(1000.0, dimension, 15, 4).unwrap();

        let nonce = [0; 16];
        let (public_share, mut input_shares) = pine.shard(&vec![1.0; dimension], &nonce).unwrap();
        assert_matches!(input_shares[0], msg::InputShare(msg::InputShareFor::Leader{ ref mut meas_share, ..}) => meas_share[0] += Field128::from(1337));
        assert!(run_vdaf_prepare(
            &pine,
            &[0; 16],
            &(),
            &nonce,
            public_share.clone(),
            input_shares,
        )
        .is_err());
    }
}
