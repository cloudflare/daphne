// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Verifiable, Distributed Aggregation Functions
//! ([VDAFs](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)).

pub mod prio2;
pub mod prio3;

use crate::{
    error::DapAbort,
    vdaf::{prio2::prio2_decode_prep_state, prio3::prio3_decode_prep_state},
    DapError, Prio3Config, VdafConfig,
};
#[cfg(any(test, feature = "test-utils"))]
use prio::field::FieldElement;
use prio::{
    codec::{CodecError, Encode, ParameterizedDecode},
    field::{Field128, Field64, FieldPrio2},
    vdaf::{
        prio2::{Prio2PrepareShare, Prio2PrepareState},
        prio3::{Prio3PrepareShare, Prio3PrepareState},
    },
};
use rand::prelude::*;
use ring::hkdf::KeyType;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub(crate) enum VdafError {
    #[error("{0}")]
    Codec(#[from] CodecError),
    #[error("{0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("{0}")]
    Uncategorized(String),
}

/// A VDAF verification key.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    any(test, feature = "test-utils"),
    derive(deepsize::DeepSizeOf, PartialEq, Debug)
)]
pub enum VdafVerifyKey {
    /// Prio3 with the standard XOF.
    Prio3(#[serde(with = "hex")] [u8; 16]),

    /// Prio3 with XofHmacSha256Aes128.
    Prio3HmacSha256Aes128(#[serde(with = "hex")] [u8; 32]),

    /// Prio2.
    Prio2(#[serde(with = "hex")] [u8; 32]),
}

impl KeyType for VdafVerifyKey {
    fn len(&self) -> usize {
        match self {
            Self::Prio3(bytes) => bytes.len(),
            Self::Prio3HmacSha256Aes128(bytes) | Self::Prio2(bytes) => bytes.len(),
        }
    }
}

impl AsRef<[u8]> for VdafVerifyKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Prio3(bytes) => &bytes[..],
            Self::Prio3HmacSha256Aes128(bytes) | Self::Prio2(bytes) => &bytes[..],
        }
    }
}

impl AsMut<[u8]> for VdafVerifyKey {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Prio3(bytes) => &mut bytes[..],
            Self::Prio3HmacSha256Aes128(bytes) | Self::Prio2(bytes) => &mut bytes[..],
        }
    }
}

/// VDAF preparation state.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, Eq, PartialEq))]
pub enum VdafPrepState {
    Prio2(Prio2PrepareState),
    Prio3Field64(Prio3PrepareState<Field64, 16>),
    Prio3Field64HmacSha256Aes128(Prio3PrepareState<Field64, 32>),
    Prio3Field128(Prio3PrepareState<Field128, 16>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafPrepState {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        // This method is, as documented, an estimation of the size of the children. Since it can't
        // be known for this type due to it's encapsulation, I will count the size of it as 0.
        //
        // This happens to be correct for helpers but not for leaders
        match self {
            VdafPrepState::Prio2(_)
            | VdafPrepState::Prio3Field64(_)
            | VdafPrepState::Prio3Field64HmacSha256Aes128(_)
            | VdafPrepState::Prio3Field128(_) => 0,
        }
    }
}

impl Encode for VdafPrepState {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::Prio3Field64(state) => state.encode(bytes),
            Self::Prio3Field64HmacSha256Aes128(state) => state.encode(bytes),
            Self::Prio3Field128(state) => state.encode(bytes),
            Self::Prio2(state) => state.encode(bytes),
        }
    }
}

impl<'a> ParameterizedDecode<(&'a VdafConfig, bool /* is_leader */)> for VdafPrepState {
    fn decode_with_param(
        (vdaf_config, is_leader): &(&VdafConfig, bool),
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let agg_id = usize::from(!is_leader);
        match vdaf_config {
            VdafConfig::Prio3(ref prio3_config) => {
                Ok(prio3_decode_prep_state(prio3_config, agg_id, bytes)
                    .map_err(|e| CodecError::Other(Box::new(e)))?)
            }
            VdafConfig::Prio2 { dimension } => {
                Ok(prio2_decode_prep_state(*dimension, agg_id, bytes)
                    .map_err(|e| CodecError::Other(Box::new(e)))?)
            }
        }
    }
}

/// VDAF preparation message.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug))]
pub enum VdafPrepMessage {
    Prio2Share(Prio2PrepareShare),
    Prio3ShareField64(Prio3PrepareShare<Field64, 16>),
    Prio3ShareField64HmacSha256Aes128(Prio3PrepareShare<Field64, 32>),
    Prio3ShareField128(Prio3PrepareShare<Field128, 16>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafPrepMessage {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        match self {
            // The Prio2 prep share consists of three field elements.
            Self::Prio2Share(_msg) => 3 * FieldPrio2::ENCODED_SIZE,
            // The Prio3 prep share consists of an optional XOF seed for the Aggregator's joint
            // randomness part and a sequence of field elements for the Aggregator's verifier
            // share. The length of the verifier share depends on the Prio3 type, which we don't
            // know at this point. Likewise, whether the XOF seed is present depends on the Prio3
            // type.
            Self::Prio3ShareField64(..)
            | Self::Prio3ShareField64HmacSha256Aes128(..)
            | Self::Prio3ShareField128(..) => 0,
        }
    }
}

impl Encode for VdafPrepMessage {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::Prio3ShareField64(share) => share.encode(bytes),
            Self::Prio3ShareField64HmacSha256Aes128(share) => share.encode(bytes),
            Self::Prio3ShareField128(share) => share.encode(bytes),
            Self::Prio2Share(share) => share.encode(bytes),
        }
    }
}

impl ParameterizedDecode<VdafPrepState> for VdafPrepMessage {
    fn decode_with_param(
        state: &VdafPrepState,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match state {
            VdafPrepState::Prio3Field64(state) => Ok(VdafPrepMessage::Prio3ShareField64(
                Prio3PrepareShare::decode_with_param(state, bytes)?,
            )),
            VdafPrepState::Prio3Field64HmacSha256Aes128(state) => {
                Ok(VdafPrepMessage::Prio3ShareField64HmacSha256Aes128(
                    Prio3PrepareShare::decode_with_param(state, bytes)?,
                ))
            }
            VdafPrepState::Prio3Field128(state) => Ok(VdafPrepMessage::Prio3ShareField128(
                Prio3PrepareShare::decode_with_param(state, bytes)?,
            )),
            VdafPrepState::Prio2(state) => Ok(VdafPrepMessage::Prio2Share(
                Prio2PrepareShare::decode_with_param(state, bytes)?,
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VdafAggregateShare {
    Field64(prio::vdaf::AggregateShare<Field64>),
    Field128(prio::vdaf::AggregateShare<Field128>),
    FieldPrio2(prio::vdaf::AggregateShare<FieldPrio2>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafAggregateShare {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        match self {
            VdafAggregateShare::Field64(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::Field128(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::FieldPrio2(s) => std::mem::size_of_val(s.as_ref()),
        }
    }
}

impl Encode for VdafAggregateShare {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            VdafAggregateShare::Field64(agg_share) => agg_share.encode(bytes),
            VdafAggregateShare::Field128(agg_share) => agg_share.encode(bytes),
            VdafAggregateShare::FieldPrio2(agg_share) => agg_share.encode(bytes),
        }
    }
}

impl VdafConfig {
    pub(crate) fn uninitialized_verify_key(&self) -> VdafVerifyKey {
        match self {
            Self::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 { .. }) => {
                VdafVerifyKey::Prio3HmacSha256Aes128([0; 32])
            }
            Self::Prio3(..) => VdafVerifyKey::Prio3([0; 16]),
            Self::Prio2 { .. } => VdafVerifyKey::Prio2([0; 32]),
        }
    }

    /// Parse a verification key from raw bytes.
    pub fn get_decoded_verify_key(&self, bytes: &[u8]) -> Result<VdafVerifyKey, DapError> {
        match self {
            Self::Prio3(..) => Ok(VdafVerifyKey::Prio3(<[u8; 16]>::try_from(bytes).map_err(
                |e| DapAbort::from_codec_error(CodecError::Other(Box::new(e)), None),
            )?)),
            Self::Prio2 { .. } => {
                Ok(VdafVerifyKey::Prio2(<[u8; 32]>::try_from(bytes).map_err(
                    |e| DapAbort::from_codec_error(CodecError::Other(Box::new(e)), None),
                )?))
            }
        }
    }

    /// Generate the Aggregators' shared verification parameters.
    pub fn gen_verify_key(&self) -> VdafVerifyKey {
        let mut rng = thread_rng();
        let mut verify_key = self.uninitialized_verify_key();
        rng.fill(verify_key.as_mut());
        verify_key
    }

    /// Checks if the provided aggregation parameter is valid for the underling VDAF being
    /// executed.
    pub fn is_valid_agg_param(&self, agg_param: &[u8]) -> bool {
        match self {
            Self::Prio3(..) | Self::Prio2 { .. } => agg_param.is_empty(),
        }
    }
}
