// Copyright (c) 2024 Cloudflare, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! Messages exchanged during VDAF execution.

use std::iter;

use prio::{
    codec::{CodecError, Decode, Encode, ParameterizedDecode},
    field::FftFriendlyFieldElement,
    flp::Type,
    vdaf::xof::Seed,
};

use super::{vdaf::PinePrepState, Pine};

/// The public share sent by the Client to each Aggregator.
#[derive(Clone, Debug)]
pub struct PublicShare<const SEED_SIZE: usize> {
    pub(crate) wr_joint_rand_parts: [Seed<SEED_SIZE>; 2],
    pub(crate) vf_joint_rand_parts: [Seed<SEED_SIZE>; 2],
}

impl<const SEED_SIZE: usize> std::fmt::Display for PublicShare<SEED_SIZE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self
            .get_encoded()
            .map(hex::encode)
            .unwrap_or("unencodable".into());
        write!(f, "PinePublicShare({msg})")
    }
}

impl<const SEED_SIZE: usize> Encode for PublicShare<SEED_SIZE> {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.wr_joint_rand_parts[0].encode(bytes)?;
        self.wr_joint_rand_parts[1].encode(bytes)?;
        self.vf_joint_rand_parts[0].encode(bytes)?;
        self.vf_joint_rand_parts[1].encode(bytes)?;
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(SEED_SIZE * 4)
    }
}

impl<F, X, const SEED_SIZE: usize> ParameterizedDecode<Pine<F, X, SEED_SIZE>>
    for PublicShare<SEED_SIZE>
{
    fn decode_with_param(
        _pine: &Pine<F, X, SEED_SIZE>,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            wr_joint_rand_parts: [Seed::decode(bytes)?, Seed::decode(bytes)?],
            vf_joint_rand_parts: [Seed::decode(bytes)?, Seed::decode(bytes)?],
        })
    }
}

/// An input share sent by the Client to the Leader.
#[derive(Clone, Debug)]
pub struct InputShare<F, const SEED_SIZE: usize>(pub(crate) InputShareFor<F, SEED_SIZE>);

#[derive(Clone, Debug)]
pub(crate) enum InputShareFor<F, const SEED_SIZE: usize> {
    Leader {
        meas_share: Vec<F>,
        proofs_share: Vec<F>,
        wr_blind: Seed<SEED_SIZE>,
        vf_blind: Seed<SEED_SIZE>,
    },

    Helper {
        meas_share: Seed<SEED_SIZE>,
        proofs_share: Seed<SEED_SIZE>,
        wr_blind: Seed<SEED_SIZE>,
        vf_blind: Seed<SEED_SIZE>,
    },
}

impl<F: FftFriendlyFieldElement, const SEED_SIZE: usize> std::fmt::Display
    for InputShare<F, SEED_SIZE>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self
            .get_encoded()
            .map(hex::encode)
            .unwrap_or("unencodable".into());
        match self.0 {
            InputShareFor::Leader { .. } => write!(f, "PineLeaderInputShare({msg})"),
            InputShareFor::Helper { .. } => write!(f, "PineHelperInputShare({msg})"),
        }
    }
}

impl<F: FftFriendlyFieldElement, const SEED_SIZE: usize> Encode for InputShare<F, SEED_SIZE> {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.0 {
            InputShareFor::Leader {
                meas_share,
                proofs_share,
                wr_blind,
                vf_blind,
            } => {
                for m in meas_share {
                    m.encode(bytes)?;
                }
                for p in proofs_share {
                    p.encode(bytes)?;
                }
                wr_blind.encode(bytes)?;
                vf_blind.encode(bytes)?;
            }
            InputShareFor::Helper {
                meas_share,
                proofs_share,
                wr_blind,
                vf_blind,
            } => {
                meas_share.encode(bytes)?;
                proofs_share.encode(bytes)?;
                wr_blind.encode(bytes)?;
                vf_blind.encode(bytes)?;
            }
        }
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        match &self.0 {
            InputShareFor::Leader {
                meas_share,
                proofs_share,
                ..
            } => Some(
                meas_share.len() * F::ENCODED_SIZE
                    + proofs_share.len() * F::ENCODED_SIZE
                    + SEED_SIZE * 2,
            ),
            InputShareFor::Helper { .. } => Some(SEED_SIZE * 4),
        }
    }
}

impl<F: FftFriendlyFieldElement, X, const SEED_SIZE: usize>
    ParameterizedDecode<(&Pine<F, X, SEED_SIZE>, usize)> for InputShare<F, SEED_SIZE>
{
    fn decode_with_param(
        (pine, agg_id): &(&Pine<F, X, SEED_SIZE>, usize),
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match agg_id {
            // Expect to decode the Leader's input share.
            0 => Ok(Self(InputShareFor::Leader {
                meas_share: iter::repeat_with(|| F::decode(bytes))
                    .take(pine.encoded_input_len)
                    .collect::<Result<Vec<_>, _>>()?,
                proofs_share: iter::repeat_with(|| F::decode(bytes))
                    .take(
                        pine.flp_sq_norm_equal.proof_len()
                            + pine.flp.proof_len() * usize::from(pine.num_proofs),
                    )
                    .collect::<Result<Vec<_>, _>>()?,
                wr_blind: Seed::decode(bytes)?,
                vf_blind: Seed::decode(bytes)?,
            })),
            // Expect to decode the Helper's input share.
            1 => Ok(Self(InputShareFor::Helper {
                meas_share: Seed::decode(bytes)?,
                proofs_share: Seed::decode(bytes)?,
                wr_blind: Seed::decode(bytes)?,
                vf_blind: Seed::decode(bytes)?,
            })),
            _ => Err(CodecError::Other(
                format!("unrecognized aggregator id {agg_id}").into(),
            )),
        }
    }
}

/// A prep share broadcast by one of the Aggregators.
#[derive(Clone, Debug)]
pub struct PrepShare<F, const SEED_SIZE: usize> {
    pub(crate) verifiers_share: Vec<F>,
    pub(crate) wr_joint_rand_part: Seed<SEED_SIZE>,
    pub(crate) vf_joint_rand_part: Seed<SEED_SIZE>,
}

impl<F: FftFriendlyFieldElement, const SEED_SIZE: usize> std::fmt::Display
    for PrepShare<F, SEED_SIZE>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self
            .get_encoded()
            .map(hex::encode)
            .unwrap_or("unencodable".into());
        write!(f, "PinePrepShare({msg})")
    }
}

impl<F: FftFriendlyFieldElement, const SEED_SIZE: usize> Encode for PrepShare<F, SEED_SIZE> {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        for v in &self.verifiers_share {
            v.encode(bytes)?;
        }
        self.wr_joint_rand_part.encode(bytes)?;
        self.vf_joint_rand_part.encode(bytes)?;
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.verifiers_share.len() * F::ENCODED_SIZE + SEED_SIZE * 2)
    }
}

impl<F: FftFriendlyFieldElement, const SEED_SIZE: usize>
    ParameterizedDecode<PinePrepState<F, SEED_SIZE>> for PrepShare<F, SEED_SIZE>
{
    fn decode_with_param(
        state: &PinePrepState<F, SEED_SIZE>,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            verifiers_share: iter::repeat_with(|| F::decode(bytes))
                .take(state.verifiers_len)
                .collect::<Result<Vec<_>, _>>()?,
            wr_joint_rand_part: Seed::decode(bytes)?,
            vf_joint_rand_part: Seed::decode(bytes)?,
        })
    }
}

/// The prep message combined from the prep shares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prep<const SEED_SIZE: usize> {
    pub(crate) wr_joint_rand_seed: Seed<SEED_SIZE>,
    pub(crate) vf_joint_rand_seed: Seed<SEED_SIZE>,
}

impl<const SEED_SIZE: usize> std::fmt::Display for Prep<SEED_SIZE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self
            .get_encoded()
            .map(hex::encode)
            .unwrap_or("unencodable".into());
        write!(f, "PinePrep({msg})")
    }
}

impl<const SEED_SIZE: usize> Encode for Prep<SEED_SIZE> {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.wr_joint_rand_seed.encode(bytes)?;
        self.vf_joint_rand_seed.encode(bytes)?;
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(SEED_SIZE * 2)
    }
}

impl<F, const SEED_SIZE: usize> ParameterizedDecode<PinePrepState<F, SEED_SIZE>>
    for Prep<SEED_SIZE>
{
    fn decode_with_param(
        _state: &PinePrepState<F, SEED_SIZE>,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            wr_joint_rand_seed: Seed::decode(bytes)?,
            vf_joint_rand_seed: Seed::decode(bytes)?,
        })
    }
}
