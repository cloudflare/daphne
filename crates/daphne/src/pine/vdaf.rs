// Copyright (c) 2024 Cloudflare, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of the PINE VDAF.

use std::{borrow::Cow, iter};

use crate::pine::{dst, USAGE_QUERY_RAND};
use prio_draft09::{
    codec::{CodecError, Decode, Encode, ParameterizedDecode},
    field::FftFriendlyFieldElement,
    flp::Type,
    vdaf::{
        xof::{IntoFieldVec, Seed, Xof},
        Aggregatable, Aggregator, Client, Collector, PrepareTransition, Vdaf, VdafError,
    },
};
use rand::prelude::*;

use subtle::{Choice, ConstantTimeEq};

use super::{
    field_to_f64, msg, Pine, USAGE_MEAS_SHARE, USAGE_PROOF_SHARE, USAGE_PROVE_RAND,
    USAGE_VF_JOINT_RAND, USAGE_VF_JOINT_RAND_PART, USAGE_VF_JOINT_RAND_SEED,
    USAGE_WR_JOINT_RAND_PART, USAGE_WR_JOINT_RAND_SEED,
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

impl<F: FftFriendlyFieldElement, X, const SEED_SIZE: usize>
    ParameterizedDecode<(&Pine<F, X, SEED_SIZE>, &())> for PineVec<F>
{
    fn decode_with_param(
        (pine, _agg_param): &(&Pine<F, X, SEED_SIZE>, &()),
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        iter::repeat_with(|| F::decode(bytes))
            .take(pine.flp.dimension)
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

impl<F: FftFriendlyFieldElement, X: Xof<SEED_SIZE>, const SEED_SIZE: usize> Vdaf
    for Pine<F, X, SEED_SIZE>
{
    type Measurement = Vec<f64>;
    type AggregateResult = Vec<f64>;
    type AggregationParam = ();
    type PublicShare = msg::PublicShare<SEED_SIZE>;
    type InputShare = msg::InputShare<F, SEED_SIZE>;
    type OutputShare = PineVec<F>;
    type AggregateShare = PineVec<F>;

    fn algorithm_id(&self) -> u32 {
        self.algorithm_id
    }

    fn num_aggregators(&self) -> usize {
        2
    }
}

impl<F: FftFriendlyFieldElement, X: Xof<SEED_SIZE>, const SEED_SIZE: usize> Pine<F, X, SEED_SIZE> {
    fn joint_rand_part(
        &self,
        agg_id: u8,
        blind: &[u8; SEED_SIZE],
        nonce: &[u8; 16],
        meas_share: &[F],
        usage: u16,
    ) -> Seed<SEED_SIZE> {
        let mut xof = X::init(blind, &dst(self.algorithm_id, usage));
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

    fn joint_rand_seed(
        &self,
        joint_rand_parts: &[Seed<SEED_SIZE>; 2],
        usage: u16,
    ) -> Seed<SEED_SIZE> {
        let mut xof = X::init(&[0; SEED_SIZE], &dst(self.algorithm_id, usage));
        xof.update(joint_rand_parts[0].as_ref());
        xof.update(joint_rand_parts[1].as_ref());
        xof.into_seed()
    }

    fn helper_meas_share(&self, seed: &[u8; SEED_SIZE]) -> Vec<F> {
        let mut xof = X::init(seed, &dst(self.algorithm_id, USAGE_MEAS_SHARE));
        xof.update(&[1]); // agg_id
        xof.into_seed_stream()
            .into_field_vec(self.encoded_input_len)
    }

    fn helper_proof_share(&self, seed: &[u8; SEED_SIZE]) -> Vec<F> {
        let mut xof = X::init(seed, &dst(self.algorithm_id, USAGE_PROOF_SHARE));
        xof.update(&[
            self.num_proofs_sq_norm_equal,
            self.num_proofs,
            1, // agg_id
        ]);
        xof.into_seed_stream().into_field_vec(
            self.flp_sq_norm_equal.proof_len() * usize::from(self.num_proofs_sq_norm_equal)
                + self.flp.proof_len() * usize::from(self.num_proofs),
        )
    }
}

// Client

impl<F: FftFriendlyFieldElement, X: Xof<SEED_SIZE>, const SEED_SIZE: usize> Client<16>
    for Pine<F, X, SEED_SIZE>
{
    fn shard(
        &self,
        gradient: &Vec<f64>,
        nonce: &[u8; 16],
    ) -> Result<
        (
            msg::PublicShare<SEED_SIZE>,
            Vec<msg::InputShare<F, SEED_SIZE>>,
        ),
        VdafError,
    > {
        let mut rng = thread_rng();
        let mut rand = [[0; SEED_SIZE]; NUM_SHARD_RAND_SEEDS];
        for seed in &mut rand {
            rng.fill(&mut seed[..]);
        }
        self.shard_with_rand(gradient, nonce, rand)
    }
}

impl<F: FftFriendlyFieldElement, X: Xof<SEED_SIZE>, const SEED_SIZE: usize> Pine<F, X, SEED_SIZE> {
    pub(crate) fn shard_with_rand(
        &self,
        gradient: &[f64],
        nonce: &[u8; 16],
        rand: [[u8; SEED_SIZE]; NUM_SHARD_RAND_SEEDS],
    ) -> Result<
        (
            msg::PublicShare<SEED_SIZE>,
            Vec<msg::InputShare<F, SEED_SIZE>>,
        ),
        VdafError,
    > {
        let mut meas = Vec::with_capacity(self.flp.input_len());
        self.flp
            .append_encoded_gradient(&mut meas, gradient.iter().copied())?;

        let [meas_share_seed_1, proofs_share_seed_1, wr_blind_1, vf_blind_1, wr_blind_0, vf_blind_0, prove_seed] =
            rand;

        // Begin encoding the Leader's measurement share (up to the wraparound tests). Complete the
        // Helper's measurement share.
        let meas_share_1 = self.helper_meas_share(&meas_share_seed_1);
        let mut meas_share_0 = Vec::with_capacity(self.encoded_input_len);
        for (m, s1) in meas.iter().zip(meas_share_1.iter().take(meas.len())) {
            meas_share_0.push(*m - *s1);
        }
        debug_assert_eq!(meas.len(), self.encoded_gradient_and_sq_norm_len);
        debug_assert_eq!(meas_share_0.len(), self.encoded_gradient_and_sq_norm_len);
        debug_assert_eq!(meas_share_1.len(), self.encoded_input_len);

        let wr_joint_rand_parts = [
            self.joint_rand_part(
                0,
                &wr_blind_0,
                nonce,
                &meas_share_0,
                USAGE_WR_JOINT_RAND_PART,
            ),
            self.joint_rand_part(
                1,
                &wr_blind_1,
                nonce,
                &meas_share_1[..self.encoded_gradient_and_sq_norm_len],
                USAGE_WR_JOINT_RAND_PART,
            ),
        ];

        // Run the wraparound tests and complete the Leader's measurement share.
        {
            let wr_joint_rand_seed =
                self.joint_rand_seed(&wr_joint_rand_parts, USAGE_WR_JOINT_RAND_SEED);

            let i = meas.len();
            let wr_test_results = self
                .flp
                .append_wr_test_results::<X, SEED_SIZE>(&mut meas, &wr_joint_rand_seed)?;

            for (m, s1) in meas[i..].iter().zip(meas_share_1[i..].iter()) {
                meas_share_0.push(*m - *s1);
            }

            meas.extend_from_slice(&wr_test_results);
        }
        debug_assert_eq!(meas.len(), self.flp.input_len());
        debug_assert_eq!(meas_share_0.len(), self.encoded_input_len);

        let vf_joint_rand_parts = [
            self.joint_rand_part(
                0,
                &vf_blind_0,
                nonce,
                &meas_share_0,
                USAGE_VF_JOINT_RAND_PART,
            ),
            self.joint_rand_part(
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
                    self.joint_rand_seed(&vf_joint_rand_parts, USAGE_VF_JOINT_RAND_SEED);

                X::seed_stream(
                    &vf_joint_rand_seed,
                    &dst(self.algorithm_id, USAGE_VF_JOINT_RAND),
                    &[self.num_proofs],
                )
                .into_field_vec(self.flp.joint_rand_len() * usize::from(self.num_proofs))
            };

            let num_proofs_sq_norm_equal = usize::from(self.num_proofs_sq_norm_equal);
            let num_proofs = usize::from(self.num_proofs);

            let prove_rands = {
                let mut xof = X::init(&prove_seed, &dst(self.algorithm_id, USAGE_PROVE_RAND));
                xof.update(&[self.num_proofs_sq_norm_equal, self.num_proofs]);
                xof.into_seed_stream().into_field_vec(
                    self.flp_sq_norm_equal.prove_rand_len() * num_proofs_sq_norm_equal
                        + self.flp.prove_rand_len() * num_proofs,
                )
            };
            let (pr_sq_norm_equal, pr) = prove_rands
                .split_at(self.flp_sq_norm_equal.prove_rand_len() * num_proofs_sq_norm_equal);

            let mut proofs = Vec::with_capacity(
                self.flp_sq_norm_equal.proof_len() * num_proofs_sq_norm_equal
                    + self.flp.proof_len() * num_proofs,
            );

            for prove_rand in pr_sq_norm_equal.chunks_exact(self.flp_sq_norm_equal.prove_rand_len())
            {
                proofs.append(&mut self.flp_sq_norm_equal.prove(&meas, prove_rand, &[])?);
            }

            for (prove_rand, vf_joint_rand) in pr
                .chunks_exact(self.flp.prove_rand_len())
                .zip(vf_joint_rands.chunks_exact(self.flp.joint_rand_len()))
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
pub struct PinePrepState<F, const SEED_SIZE: usize> {
    gradient_share: Vec<F>,
    corrected_wr_joint_rand_seed: Seed<SEED_SIZE>,
    corrected_vf_joint_rand_seed: Seed<SEED_SIZE>,
    pub(crate) verifiers_len: usize,
    meas_share_seed: Option<Seed<SEED_SIZE>>,
}

impl<F: FftFriendlyFieldElement, const SEED_SIZE: usize> Encode for PinePrepState<F, SEED_SIZE> {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        // NOTE This format is not specified in draft-chen-cfrg-vdaf-pine.
        if let Some(ref seed) = self.meas_share_seed {
            // The Helper encodes the seed.
            seed.encode(bytes)?;
        } else {
            // The Leader encodes the vector itself.
            for m in &self.gradient_share {
                m.encode(bytes)?;
            }
        }
        self.corrected_wr_joint_rand_seed.encode(bytes)?;
        self.corrected_vf_joint_rand_seed.encode(bytes)?;
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        let gradient_len = if self.meas_share_seed.is_some() {
            SEED_SIZE
        } else {
            F::ENCODED_SIZE * self.gradient_share.len()
        };
        Some(gradient_len + SEED_SIZE * 2)
    }
}

impl<F, X, const SEED_SIZE: usize> ParameterizedDecode<(&Pine<F, X, SEED_SIZE>, bool)>
    for PinePrepState<F, SEED_SIZE>
where
    F: FftFriendlyFieldElement,
    X: Xof<SEED_SIZE>,
{
    fn decode_with_param(
        (pine, role): &(&Pine<F, X, SEED_SIZE>, bool),
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let (gradient_share, meas_share_seed) = match role {
            true => (
                std::iter::repeat_with(|| F::decode(bytes))
                    .take(pine.flp.dimension)
                    .collect::<Result<Vec<_>, _>>()?,
                None,
            ),
            false => {
                let seed = Seed::decode(bytes)?;
                let mut gradient_share = pine.helper_meas_share(seed.as_ref());
                gradient_share.truncate(pine.flp.dimension);
                (gradient_share, Some(seed))
            }
        };

        Ok(Self {
            gradient_share,
            corrected_wr_joint_rand_seed: Seed::decode(bytes)?,
            corrected_vf_joint_rand_seed: Seed::decode(bytes)?,
            verifiers_len: pine.flp_sq_norm_equal.verifier_len()
                * pine.num_proofs_sq_norm_equal as usize
                + pine.flp.verifier_len() * pine.num_proofs as usize,
            meas_share_seed,
        })
    }
}

impl<F: FftFriendlyFieldElement, const SEED_SIZE: usize> PartialEq for PinePrepState<F, SEED_SIZE> {
    fn eq(&self, other: &Self) -> bool {
        (self.gradient_share.ct_eq(&other.gradient_share)
            & self
                .corrected_wr_joint_rand_seed
                .ct_eq(&other.corrected_wr_joint_rand_seed)
            & self
                .corrected_vf_joint_rand_seed
                .ct_eq(&other.corrected_vf_joint_rand_seed)
            & self.verifiers_len.ct_eq(&other.verifiers_len)
            & match (&self.meas_share_seed, &other.meas_share_seed) {
                (Some(ours), Some(theirs)) => ours.ct_eq(theirs),
                (None, None) => Choice::from(1),
                _ => Choice::from(0),
            })
        .into()
    }
}

impl<F: FftFriendlyFieldElement, const SEED_SIZE: usize> Eq for PinePrepState<F, SEED_SIZE> {}

impl<F: FftFriendlyFieldElement, X: Xof<SEED_SIZE>, const SEED_SIZE: usize>
    Aggregator<SEED_SIZE, 16> for Pine<F, X, SEED_SIZE>
{
    type PrepareState = PinePrepState<F, SEED_SIZE>;
    type PrepareShare = msg::PrepShare<F, SEED_SIZE>;
    type PrepareMessage = msg::Prep<SEED_SIZE>;

    fn prepare_init(
        &self,
        verify_key: &[u8; SEED_SIZE],
        agg_id: usize,
        _agg_param: &(),
        nonce: &[u8; 16],
        public_share: &msg::PublicShare<SEED_SIZE>,
        input_share: &msg::InputShare<F, SEED_SIZE>,
    ) -> Result<(PinePrepState<F, SEED_SIZE>, msg::PrepShare<F, SEED_SIZE>), VdafError> {
        let msg::PublicShare {
            wr_joint_rand_parts,
            vf_joint_rand_parts,
        } = public_share;

        let num_proofs_sq_norm_equal = usize::from(self.num_proofs_sq_norm_equal);
        let num_proofs = usize::from(self.num_proofs);

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
        let (ps_sq_norm_equal, ps) =
            proofs_share.split_at(self.flp_sq_norm_equal.proof_len() * num_proofs_sq_norm_equal);

        let wr_joint_rand_part = self.joint_rand_part(
            agg_id.try_into().unwrap(),
            wr_blind.as_ref(),
            nonce,
            &meas_share[..self.encoded_gradient_and_sq_norm_len],
            USAGE_WR_JOINT_RAND_PART,
        );

        let corrected_wr_joint_rand_seed = {
            let mut corrected_wr_joint_rand_parts = wr_joint_rand_parts.clone();
            corrected_wr_joint_rand_parts[agg_id] = wr_joint_rand_part.clone();
            self.joint_rand_seed(&corrected_wr_joint_rand_parts, USAGE_WR_JOINT_RAND_SEED)
        };

        // Run the wraparound tests.
        {
            let wr_test_results = self.flp.run_wr_tests::<X, SEED_SIZE>(
                &meas_share[..self.flp.dimension],
                &corrected_wr_joint_rand_seed,
            );

            meas_share.extend_from_slice(&wr_test_results);
        }

        let vf_joint_rand_part = self.joint_rand_part(
            agg_id.try_into().unwrap(),
            vf_blind.as_ref(),
            nonce,
            &meas_share[..self.encoded_input_len],
            USAGE_VF_JOINT_RAND_PART,
        );

        let corrected_vf_joint_rand_seed = {
            let mut corrected_vf_joint_rand_parts = vf_joint_rand_parts.clone();
            corrected_vf_joint_rand_parts[agg_id] = vf_joint_rand_part.clone();
            self.joint_rand_seed(&corrected_vf_joint_rand_parts, USAGE_VF_JOINT_RAND_SEED)
        };

        // Query the proofs.
        let verifiers_share = {
            let corrected_vf_joint_rands = {
                X::seed_stream(
                    &corrected_vf_joint_rand_seed,
                    &dst(self.algorithm_id, USAGE_VF_JOINT_RAND),
                    &[self.num_proofs],
                )
                .into_field_vec(self.flp.joint_rand_len() * usize::from(self.num_proofs))
            };

            let query_rands = {
                let mut xof = X::init(verify_key, &dst(self.algorithm_id, USAGE_QUERY_RAND));
                xof.update(&[self.num_proofs_sq_norm_equal, self.num_proofs]);
                xof.update(nonce);
                xof.into_seed_stream().into_field_vec(
                    self.flp_sq_norm_equal.query_rand_len() * num_proofs_sq_norm_equal
                        + self.flp.query_rand_len() * num_proofs,
                )
            };
            let (qr_sq_norm_equal, qr) = query_rands
                .split_at(self.flp_sq_norm_equal.query_rand_len() * num_proofs_sq_norm_equal);

            let mut verifiers_share = Vec::with_capacity(
                self.flp_sq_norm_equal.verifier_len()
                    + num_proofs_sq_norm_equal
                    + self.flp.verifier_len() * num_proofs,
            );

            for (proof_share, query_rand) in ps_sq_norm_equal
                .chunks_exact(self.flp_sq_norm_equal.proof_len())
                .zip(qr_sq_norm_equal.chunks_exact(self.flp_sq_norm_equal.query_rand_len()))
            {
                verifiers_share.append(&mut self.flp_sq_norm_equal.query(
                    &meas_share,
                    proof_share,
                    query_rand,
                    &[],
                    2,
                )?);
            }

            for (proof_share, (vf_joint_rand, query_rand)) in
                ps.chunks_exact(self.flp.proof_len()).zip(
                    corrected_vf_joint_rands
                        .chunks_exact(self.flp.joint_rand_len())
                        .zip(qr.chunks_exact(self.flp.query_rand_len())),
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
                meas_share_seed: match input_share {
                    msg::InputShare(msg::InputShareFor::Helper {
                        meas_share,
                        proofs_share: _,
                        wr_blind: _,
                        vf_blind: _,
                    }) => Some(meas_share.clone()),
                    msg::InputShare(msg::InputShareFor::Leader { .. }) => None,
                },
            },
            msg::PrepShare {
                verifiers_share,
                wr_joint_rand_part,
                vf_joint_rand_part,
            },
        ))
    }

    fn prepare_shares_to_prepare_message<M: IntoIterator<Item = msg::PrepShare<F, SEED_SIZE>>>(
        &self,
        _agg_param: &(),
        inputs: M,
    ) -> Result<msg::Prep<SEED_SIZE>, VdafError> {
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
            let (v_sq_norm_equal, v) = verifiers.split_at(
                self.flp_sq_norm_equal.verifier_len() * usize::from(self.num_proofs_sq_norm_equal),
            );

            for verifier in v_sq_norm_equal.chunks_exact(self.flp_sq_norm_equal.verifier_len()) {
                if !self.flp_sq_norm_equal.decide(verifier)? {
                    return Err(VdafError::Uncategorized(
                        "squared norm equality proof check failed".into(),
                    ));
                }
            }

            for verifier in v.chunks_exact(self.flp.verifier_len()) {
                if !self.flp.decide(verifier)? {
                    return Err(VdafError::Uncategorized("main proof check failed".into()));
                }
            }
        }

        let wr_joint_rand_seed = self.joint_rand_seed(
            &[wr_joint_rand_part_0, wr_joint_rand_part_1],
            USAGE_WR_JOINT_RAND_SEED,
        );

        let vf_joint_rand_seed = self.joint_rand_seed(
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
        state: PinePrepState<F, SEED_SIZE>,
        input: msg::Prep<SEED_SIZE>,
    ) -> Result<PrepareTransition<Self, SEED_SIZE, 16>, VdafError> {
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
        let mut agg_share = PineVec(vec![F::zero(); self.flp.dimension]);
        for out_share in out_shares {
            agg_share.accumulate(&out_share)?;
        }
        Ok(agg_share)
    }
}

// Collector

impl<F: FftFriendlyFieldElement, X: Xof<SEED_SIZE>, const SEED_SIZE: usize> Collector
    for Pine<F, X, SEED_SIZE>
{
    fn unshard<M: IntoIterator<Item = PineVec<F>>>(
        &self,
        _agg_param: &(),
        agg_shares: M,
        _num_measurements: usize,
    ) -> Result<Vec<f64>, VdafError> {
        let two_to_frac_bits = f64::from(1 << self.flp.frac_bits);
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

    use prio_draft09::{
        codec::{Decode, Encode, ParameterizedDecode},
        field::{Field128, Field64},
        vdaf::{
            test_utils::{run_vdaf, run_vdaf_prepare},
            xof::{Seed, XofTurboShake128},
            Aggregator, Client, Collector,
        },
    };

    use crate::pine::{msg, norm_bound_f64_to_u64, vdaf::PineVec, Pine, PineParam};

    use assert_matches::assert_matches;

    use super::PinePrepState;

    #[test]
    fn run_128() {
        let dimension = 100;
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_128(norm_bound, dimension, 15, 4, 10).unwrap();
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
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_64(norm_bound, dimension, 15, 4, 100).unwrap();
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
    fn multiple_sq_norm_equal_proofs() {
        let dimension = 100;
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::<Field64, XofTurboShake128, 16>::new(
            &PineParam {
                norm_bound,
                dimension,
                frac_bits: 15,
                chunk_len: 10,
                chunk_len_sq_norm_equal: 11,
                num_proofs: 2,
                num_proofs_sq_norm_equal: 3,
                num_wr_tests: 128,
                num_wr_successes: 100,
            },
            0xffff_ffff,
        )
        .unwrap();
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
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_128(norm_bound, dimension, 15, 4, 100).unwrap();

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
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_128(norm_bound, dimension, 15, 4, 5).unwrap();

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
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_128(norm_bound, dimension, 15, 4, 5).unwrap();

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
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_128(norm_bound, dimension, 15, 4, 5).unwrap();

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
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_128(norm_bound, dimension, 15, 4, 4).unwrap();

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

    #[test]
    fn roundtrip_prep_state() {
        let dimension = 100;
        let norm_bound = norm_bound_f64_to_u64(1000.0, 15);
        let pine = Pine::new_64(norm_bound, dimension, 15, 4, 4).unwrap();

        let (leader_prep_state, helper_prep_state) = {
            let verify_key = [0; 16];
            let nonce = [0; 16];
            let (public_share, input_shares) = pine.shard(&vec![1.0; dimension], &nonce).unwrap();
            let (leader_prep_state, _leader_prep_share) = pine
                .prepare_init(&verify_key, 0, &(), &nonce, &public_share, &input_shares[0])
                .unwrap();
            let (helper_prep_state, _helper_prep_share) = pine
                .prepare_init(&verify_key, 1, &(), &nonce, &public_share, &input_shares[1])
                .unwrap();
            (leader_prep_state, helper_prep_state)
        };

        let got = PinePrepState::get_decoded_with_param(
            &(&pine, true),
            &leader_prep_state.get_encoded().unwrap(),
        )
        .unwrap();
        assert_eq!(got, leader_prep_state);

        let got = PinePrepState::get_decoded_with_param(
            &(&pine, false),
            &helper_prep_state.get_encoded().unwrap(),
        )
        .unwrap();
        assert_eq!(got, helper_prep_state);
    }
}
