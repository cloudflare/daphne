// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Verifiable, Distributed Aggregation Functions
//! ([VDAFs](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)).

#[cfg(feature = "experimental")]
pub(crate) mod mastic;
#[cfg(feature = "experimental")]
pub(crate) mod pine;
pub(crate) mod prio2;
pub(crate) mod prio3;

#[cfg(feature = "experimental")]
use crate::pine::vdaf::PinePrepState;
use crate::{
    fatal_error,
    vdaf::{prio2::prio2_decode_prep_state, prio3::prio3_decode_prep_state},
    DapError,
};
#[cfg(any(test, feature = "test-utils", feature = "experimental"))]
use prio::field::FieldElement;
use prio::{
    codec::{CodecError, Encode, ParameterizedDecode},
    field::{Field128, Field64, FieldPrio2},
    vdaf::{
        prio2::{Prio2PrepareShare, Prio2PrepareState},
        prio3::{Prio3PrepareShare, Prio3PrepareState},
        Aggregator, Client, Collector, PrepareTransition, Vdaf,
    },
};
use rand::prelude::*;
use ring::hkdf::KeyType;
use serde::{Deserialize, Serialize};
#[cfg(feature = "experimental")]
use std::io::Read;

#[cfg(feature = "experimental")]
pub use self::{mastic::MasticWeightConfig, pine::PineConfig};

#[derive(Debug, thiserror::Error)]
pub(crate) enum VdafError {
    #[error("{0}")]
    Codec(#[from] CodecError),
    #[error("{0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("{0}")]
    Dap(DapError),
}

/// Specification of a concrete VDAF.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum VdafConfig {
    Prio3(Prio3Config),
    Prio2 {
        dimension: usize,
    },
    #[cfg(feature = "experimental")]
    Mastic {
        /// Length of each input, in number of bytes.
        input_size: usize,

        /// The type of each weight.
        weight_config: MasticWeightConfig,
    },
    #[cfg(feature = "experimental")]
    Pine(PineConfig),
}

impl std::str::FromStr for VdafConfig {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl std::fmt::Display for VdafConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VdafConfig::Prio3(prio3_config) => write!(f, "Prio3({prio3_config})"),
            VdafConfig::Prio2 { dimension } => write!(f, "Prio2({dimension})"),
            #[cfg(feature = "experimental")]
            VdafConfig::Mastic {
                input_size,
                weight_config,
            } => write!(f, "Mastic({input_size}, {weight_config})"),
            #[cfg(feature = "experimental")]
            VdafConfig::Pine(pine_config) => write!(f, "{pine_config}"),
        }
    }
}

/// Supported data types for prio3.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum Prio3Config {
    /// A 64-bit counter. The aggregate is the sum of the measurements, where each measurement is
    /// equal to `0` or `1`.
    Count,

    /// The sum of 64-bit, unsigned integers. Each measurement is an integer in range `[0,
    /// 2^bits)`.
    Sum { bits: usize },

    /// A histogram for estimating the distribution of 64-bit, unsigned integers where each
    /// measurement is a bucket index in range `[0, len)`.
    Histogram { length: usize, chunk_length: usize },

    /// The element-wise sum of vectors. Each vector has `len` elements.
    /// Each element is a 64-bit unsigned integer in range `[0,2^bits)`.
    SumVec {
        bits: usize,
        length: usize,
        chunk_length: usize,
    },

    /// A variant of `SumVec` that uses a smaller field (`Field64`), multiple proofs, and a custom
    /// XOF (`XofHmacSha256Aes128`).
    SumVecField64MultiproofHmacSha256Aes128 {
        bits: usize,
        length: usize,
        chunk_length: usize,
        num_proofs: u8,
    },
}

impl std::fmt::Display for Prio3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Prio3Config::Count => write!(f, "Count"),
            Prio3Config::Histogram {
                length,
                chunk_length,
            } => write!(f, "Histogram({length},{chunk_length})"),
            Prio3Config::Sum { bits } => write!(f, "Sum({bits})"),
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            } => write!(f, "SumVec({bits},{length},{chunk_length})"),
            Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                bits,
                length,
                chunk_length,
                num_proofs,
            } => write!(f, "SumVecField64MultiproofHmacSha256Aes128({bits},{length},{chunk_length},{num_proofs})"),
        }
    }
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
    L16(#[serde(with = "hex")] [u8; 16]),

    /// Prio2 and Prio3 with `XofHmacSha256Aes128`.
    L32(#[serde(with = "hex")] [u8; 32]),
}

impl KeyType for VdafVerifyKey {
    fn len(&self) -> usize {
        match self {
            Self::L16(bytes) => bytes.len(),
            Self::L32(bytes) => bytes.len(),
        }
    }
}

impl AsRef<[u8]> for VdafVerifyKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::L16(bytes) => &bytes[..],
            Self::L32(bytes) => &bytes[..],
        }
    }
}

impl AsMut<[u8]> for VdafVerifyKey {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::L16(bytes) => &mut bytes[..],
            Self::L32(bytes) => &mut bytes[..],
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
    #[cfg(feature = "experimental")]
    Mastic {
        out_share: Vec<Field64>,
    },
    #[cfg(feature = "experimental")]
    Pine128(PinePrepState<Field128>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafPrepState {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        // This method is, as documented, an estimation of the size of the children. Since it can't
        // be known for this type due to it's encapsulation, I will count the size of it as 0.
        //
        // This happens to be correct for helpers but not for leaders
        match self {
            Self::Prio2(_)
            | Self::Prio3Field64(_)
            | Self::Prio3Field64HmacSha256Aes128(_)
            | Self::Prio3Field128(_) => 0,
            #[cfg(feature = "experimental")]
            Self::Mastic { .. } | Self::Pine128(_) => 0,
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
            #[cfg(feature = "experimental")]
            Self::Mastic { .. } | Self::Pine128(_) => {
                unreachable!("encoding of prep state is not implemented")
            }
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
            #[cfg(feature = "experimental")]
            VdafConfig::Mastic { .. } | VdafConfig::Pine(..) => {
                unreachable!("decoding of prep state is not implemented")
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
    #[cfg(feature = "experimental")]
    MasticShare(Field64),
    #[cfg(feature = "experimental")]
    Pine128Share(crate::pine::msg::PrepShare<Field128>),
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
            #[cfg(feature = "experimental")]
            Self::MasticShare(..) | Self::Pine128Share(_) => 0,
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
            #[cfg(feature = "experimental")]
            Self::MasticShare(share) => share.encode(bytes),
            #[cfg(feature = "experimental")]
            Self::Pine128Share(share) => share.encode(bytes),
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
            #[cfg(feature = "experimental")]
            VdafPrepState::Mastic { .. } => {
                todo!("mastic: decoding of prep messages is not implemented")
            }
            #[cfg(feature = "experimental")]
            VdafPrepState::Pine128(state) => Ok(VdafPrepMessage::Pine128Share(
                crate::pine::msg::PrepShare::decode_with_param(state, bytes)?,
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
            Self::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 { .. })
            | Self::Prio2 { .. } => VdafVerifyKey::L32([0; 32]),
            Self::Prio3(..) => VdafVerifyKey::L16([0; 16]),
            #[cfg(feature = "experimental")]
            Self::Mastic { .. } | Self::Pine(..) => VdafVerifyKey::L16([0; 16]),
        }
    }

    /// Parse a verification key from raw bytes.
    pub fn get_decoded_verify_key(&self, bytes: &[u8]) -> Result<VdafVerifyKey, CodecError> {
        match self {
            Self::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 { .. })
            | Self::Prio2 { .. } => Ok(VdafVerifyKey::L32(
                <[u8; 32]>::try_from(bytes).map_err(|e| CodecError::Other(Box::new(e)))?,
            )),
            Self::Prio3(..) => Ok(VdafVerifyKey::L16(
                <[u8; 16]>::try_from(bytes).map_err(|e| CodecError::Other(Box::new(e)))?,
            )),
            #[cfg(feature = "experimental")]
            Self::Mastic { .. } | Self::Pine(..) => Ok(VdafVerifyKey::L16(
                <[u8; 16]>::try_from(bytes).map_err(|e| CodecError::Other(Box::new(e)))?,
            )),
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
            #[cfg(feature = "experimental")]
            Self::Mastic { .. } => true,
            #[cfg(feature = "experimental")]
            Self::Pine(..) => agg_param.is_empty(),
        }
    }
}

#[cfg(feature = "experimental")]
pub(crate) fn decode_field_vec<F: FieldElement>(
    bytes: &[u8],
    len: usize,
) -> Result<Vec<F>, CodecError> {
    debug_assert!(F::ENCODED_SIZE < 64);
    let mut buf = [0; 64];
    let mut r = std::io::Cursor::new(bytes);
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        r.read_exact(&mut buf[..F::ENCODED_SIZE])?;
        v.push(F::get_decoded(&buf[..F::ENCODED_SIZE])?);
    }
    Ok(v)
}

fn shard_then_encode<V: Vdaf + Client<16>>(
    vdaf: &V,
    measurement: &V::Measurement,
    nonce: &[u8; 16],
) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
    let (public_share, input_shares) = vdaf.shard(measurement, nonce)?;

    Ok((
        public_share.get_encoded()?,
        input_shares
            .iter()
            .map(|input_share| input_share.get_encoded())
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|e: Vec<_>| {
                VdafError::Dap(fatal_error!(
                    err = format!("expected 2 input shares got {}", e.len())
                ))
            })?,
    ))
}

fn prep_finish_from_shares<V, const VERIFY_KEY_SIZE: usize, const NONCE_SIZE: usize>(
    vdaf: &V,
    agg_id: usize,
    host_state: V::PrepareState,
    host_share: V::PrepareShare,
    peer_share_data: &[u8],
) -> Result<(V::OutputShare, Vec<u8>), VdafError>
where
    V: Vdaf<AggregationParam = ()> + Aggregator<VERIFY_KEY_SIZE, NONCE_SIZE>,
{
    // Decode the Helper's inbound message.
    let peer_share = V::PrepareShare::get_decoded_with_param(&host_state, peer_share_data)?;

    // Preprocess the inbound messages.
    let message = vdaf.prepare_shares_to_prepare_message(
        &(),
        if agg_id == 0 {
            [host_share, peer_share]
        } else {
            [peer_share, host_share]
        },
    )?;
    let message_data = message.get_encoded()?;

    // Compute the host's output share.
    match vdaf.prepare_next(host_state, message)? {
        PrepareTransition::Continue(..) => Err(VdafError::Dap(fatal_error!(
            err = format!("prep_finish_from_shares: unexpected transition")
        ))),
        PrepareTransition::Finish(out_share) => Ok((out_share, message_data)),
    }
}

fn prep_finish<V, const VERIFY_KEY_SIZE: usize, const NONCE_SIZE: usize>(
    vdaf: &V,
    host_state: V::PrepareState,
    peer_message_data: &[u8],
) -> Result<V::OutputShare, VdafError>
where
    V: Vdaf + Aggregator<VERIFY_KEY_SIZE, NONCE_SIZE>,
{
    // Decode the inbound message from the peer, which contains the preprocessed prepare message.
    let peer_message = V::PrepareMessage::get_decoded_with_param(&host_state, peer_message_data)?;

    // Compute the host's output share.
    match vdaf.prepare_next(host_state, peer_message)? {
        PrepareTransition::Continue(..) => Err(VdafError::Dap(fatal_error!(
            err = format!("prep_finish: unexpected transition"),
        ))),
        PrepareTransition::Finish(out_share) => Ok(out_share),
    }
}

fn unshard<V, M>(
    vdaf: &V,
    num_measurements: usize,
    agg_shares: M,
) -> Result<V::AggregateResult, VdafError>
where
    V: Vdaf<AggregationParam = ()> + Collector,
    M: IntoIterator<Item = Vec<u8>>,
{
    let mut agg_shares_vec = Vec::with_capacity(vdaf.num_aggregators());
    for data in agg_shares {
        let agg_share = V::AggregateShare::get_decoded_with_param(&(vdaf, &()), data.as_ref())?;
        agg_shares_vec.push(agg_share);
    }
    Ok(vdaf.unshard(&(), agg_shares_vec, num_measurements)?)
}
