// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Verifiable, Distributed Aggregation Functions
//! ([VDAFs](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)).

pub(crate) mod draft09;
#[cfg(feature = "experimental")]
pub(crate) mod mastic;
pub(crate) mod pine;
pub(crate) mod prio2;
pub(crate) mod prio3;

use crate::pine::vdaf::PinePrepState;
use crate::{fatal_error, messages::TaskId, DapError};
use crate::{DapAggregateResult, DapAggregationParam, DapMeasurement, DapVersion};
use pine::PineConfig;
use prio::{
    codec::{CodecError, Encode, ParameterizedDecode},
    field::{Field128, Field64, FieldPrio2},
    vdaf::{
        prio2::{Prio2PrepareShare, Prio2PrepareState},
        prio3::{Prio3PrepareShare, Prio3PrepareState},
        AggregateShare, Aggregator, Client, Collector, PrepareTransition, Vdaf,
    },
};

#[cfg(any(test, feature = "test-utils", feature = "experimental"))]
use prio::field::FieldElement;
use prio_draft09::{
    codec::{CodecError as CodecErrorDraft09, Encode as EncodeDraft09},
    field::{
        Field128 as Field128Draft09, Field64 as Field64Draft09, FieldPrio2 as FieldPrio2Draft09,
    },
    vdaf::{
        prio3::{
            Prio3PrepareShare as Prio3Draft09PrepareShare,
            Prio3PrepareState as Prio3Draft09PrepareState,
        },
        AggregateShare as AggregateShareDraft09,
    },
};
use rand::prelude::*;
use ring::hkdf::KeyType;
use serde::{Deserialize, Serialize};
#[cfg(feature = "experimental")]
use std::io::Read;

#[cfg(feature = "experimental")]
pub use self::mastic::MasticWeightConfig;
use crate::constants::DapAggregatorRole;
use prio_draft09::codec::ParameterizedDecode as _;

const CTX_STRING_PREFIX: &[u8] = b"dap-13";

impl DapAggregatorRole {
    /// The numeric identifier of the role of the aggregator decoding the vdaf.
    fn as_aggregator_id(self) -> usize {
        match self {
            DapAggregatorRole::Leader => 0,
            DapAggregatorRole::Helper => 1,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum VdafError {
    #[error("{0}")]
    CodecDraft09(#[from] CodecErrorDraft09),
    #[error("{0}")]
    VdafDraft09(#[from] prio_draft09::vdaf::VdafError),
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
            VdafConfig::Pine(pine_config) => write!(f, "{pine_config}"),
        }
    }
}

impl VdafConfig {
    pub(crate) fn shard(
        &self,
        measurement: DapMeasurement,
        nonce: &[u8; 16],
        task_id: TaskId,
        version: DapVersion,
    ) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
        match (version, self) {
            (_, Self::Prio2 { dimension }) => prio2::prio2_shard(*dimension, measurement, nonce),
            (_, Self::Prio3(prio3_config)) => {
                prio3_config.shard(version, measurement, nonce, task_id)
            }
            (DapVersion::Draft09, Self::Pine(pine_config)) => pine_config.shard(measurement, nonce),
            #[cfg(feature = "experimental")]
            (
                DapVersion::Latest,
                VdafConfig::Mastic {
                    input_size,
                    weight_config,
                },
            ) => Ok(mastic::mastic_shard(
                *input_size,
                *weight_config,
                measurement,
            )?),
            _ => Err(VdafError::Dap(fatal_error!(
                err = format!("{self:?} is not supported in DAP {version}")
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prep_init(
        &self,
        version: DapVersion,
        verify_key: &VdafVerifyKey,
        task_id: TaskId,
        agg_id: usize,
        // This is used by Mastic, which for the moment is behind the "experimental" flag.
        #[cfg_attr(not(feature = "experimental"), expect(unused_variables))]
        agg_param: &DapAggregationParam,
        nonce: &[u8; 16],
        public_share_data: &[u8],
        input_share_data: &[u8],
    ) -> Result<(VdafPrepState, VdafPrepShare), VdafError> {
        match (version, self) {
            (_, VdafConfig::Prio2 { dimension }) => prio2::prio2_prep_init(
                *dimension,
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            ),
            (_, Self::Prio3(prio3_config)) => prio3_config.prep_init(
                version,
                verify_key,
                task_id,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            ),
            (DapVersion::Draft09, Self::Pine(pine)) => pine.prep_init(
                verify_key,
                agg_id,
                nonce,
                public_share_data,
                input_share_data,
            ),
            #[cfg(feature = "experimental")]
            (
                DapVersion::Latest,
                Self::Mastic {
                    input_size,
                    weight_config,
                },
            ) => mastic::mastic_prep_init(
                *input_size,
                *weight_config,
                verify_key,
                agg_param,
                public_share_data,
                input_share_data,
            ),
            _ => Err(VdafError::Dap(fatal_error!(
                err = format!("{self:?} is not supported in DAP {version}")
            ))),
        }
    }

    pub(crate) fn prep_finish_from_shares(
        &self,
        version: DapVersion,
        agg_id: usize,
        task_id: TaskId,
        host_state: VdafPrepState,
        host_share: VdafPrepShare,
        peer_share_data: &[u8],
    ) -> Result<(VdafAggregateShare, Vec<u8>), VdafError> {
        match (version, self) {
            (_, Self::Prio2 { dimension }) => prio2::prio2_prep_finish_from_shares(
                *dimension,
                host_state,
                host_share,
                peer_share_data,
            ),
            (_, Self::Prio3(prio3_config)) => prio3_config.prep_finish_from_shares(
                version,
                agg_id,
                task_id,
                host_state,
                host_share,
                peer_share_data,
            ),
            (DapVersion::Draft09, Self::Pine(pine_config)) => {
                pine_config.prep_finish_from_shares(agg_id, host_state, host_share, peer_share_data)
            }
            #[cfg(feature = "experimental")]
            (
                DapVersion::Latest,
                Self::Mastic {
                    input_size: _,
                    weight_config,
                },
            ) => mastic::mastic_prep_finish_from_shares(
                *weight_config,
                host_state,
                host_share,
                peer_share_data,
            ),
            _ => Err(VdafError::Dap(fatal_error!(
                err = format!("{self:?} is not supported in DAP {version}")
            ))),
        }
    }

    pub(crate) fn prep_finish(
        &self,
        host_state: VdafPrepState,
        peer_message_data: &[u8],
        task_id: TaskId,
        version: DapVersion,
    ) -> Result<VdafAggregateShare, VdafError> {
        match (version, self) {
            (_, Self::Prio2 { dimension }) => {
                prio2::prio2_prep_finish(*dimension, host_state, peer_message_data)
            }
            (_, Self::Prio3(prio3_config)) => {
                prio3_config.prep_finish(host_state, peer_message_data, task_id, version)
            }
            (DapVersion::Draft09, Self::Pine(pine_config)) => {
                pine_config.prep_finish(host_state, peer_message_data)
            }
            #[cfg(feature = "experimental")]
            (DapVersion::Latest, Self::Mastic { .. }) => {
                mastic::mastic_prep_finish(host_state, peer_message_data)
            }
            _ => Err(VdafError::Dap(fatal_error!(
                err = format!("{self:?} is not supported in DAP {version}")
            ))),
        }
    }

    pub(crate) fn unshard<M: IntoIterator<Item = Vec<u8>>>(
        &self,
        version: DapVersion,
        // This is used by Mastic, which for the moment is behind the "experimental" flag.
        #[cfg_attr(not(feature = "experimental"), expect(unused_variables))]
        agg_param: &DapAggregationParam,
        num_measurements: usize,
        agg_shares: M,
    ) -> Result<DapAggregateResult, VdafError> {
        match (version, self) {
            (_, Self::Prio2 { dimension }) => {
                prio2::prio2_unshard(*dimension, num_measurements, agg_shares)
            }
            (_, Self::Prio3(prio3_config)) => {
                prio3_config.unshard(version, num_measurements, agg_shares)
            }
            (DapVersion::Draft09, Self::Pine(pine_config)) => {
                pine_config.unshard(num_measurements, agg_shares)
            }
            #[cfg(feature = "experimental")]
            (
                DapVersion::Latest,
                Self::Mastic {
                    input_size: _,
                    weight_config,
                },
            ) => mastic::mastic_unshard(*weight_config, agg_param, agg_shares),
            _ => Err(VdafError::Dap(fatal_error!(
                err = format!("{self:?} is not supported in DAP {version}")
            ))),
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
    /// max_measurement]`.
    Sum { max_measurement: u64 },

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
    /// XOF (`XofHmacSha256Aes128`). This VDAF is only supported in DAP-09.
    //
    // Ensure the serialization of this type is backwards compatible.
    #[serde(rename = "sum_vec_field64_multiproof_hmac_sha256_aes128")]
    Draft09SumVecField64MultiproofHmacSha256Aes128 {
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
            Prio3Config::Sum { max_measurement } => write!(f, "Sum({max_measurement})"),
            Prio3Config::SumVec {
                bits,
                length,
                chunk_length,
            } => write!(f, "SumVec({bits},{length},{chunk_length})"),
            Prio3Config::Draft09SumVecField64MultiproofHmacSha256Aes128 {
                bits,
                length,
                chunk_length,
                num_proofs,
            } => write!(f, "Draft09SumVecField64MultiproofHmacSha256Aes128({bits},{length},{chunk_length},{num_proofs})"),
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
pub struct VdafVerifyKey(#[serde(with = "hex")] pub(crate) [u8; 32]);

impl KeyType for VdafVerifyKey {
    fn len(&self) -> usize {
        32
    }
}

impl AsRef<[u8]> for VdafVerifyKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for VdafVerifyKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

fn upgrade_codec_error(error: CodecErrorDraft09) -> CodecError {
    match error {
        CodecErrorDraft09::Io(error) => CodecError::Io(error),
        CodecErrorDraft09::BytesLeftOver(n) => CodecError::BytesLeftOver(n),
        CodecErrorDraft09::LengthPrefixTooBig(n) => CodecError::LengthPrefixTooBig(n),
        CodecErrorDraft09::LengthPrefixOverflow => CodecError::LengthPrefixOverflow,
        CodecErrorDraft09::Other(error) => CodecError::Other(error),
        _ => CodecError::UnexpectedValue,
    }
}

/// VDAF preparation state.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, Eq, PartialEq))]
pub enum VdafPrepState {
    Prio2(Prio2PrepareState),
    Prio3Draft09Field64HmacSha256Aes128(Prio3Draft09PrepareState<Field64Draft09, 32>),
    Prio3Field64(Prio3PrepareState<Field64, 32>),
    Prio3Field128(Prio3PrepareState<Field128, 32>),
    #[cfg(feature = "experimental")]
    Mastic {
        out_share: Vec<Field64>,
    },
    Pine64HmacSha256Aes128(PinePrepState<Field64Draft09, 32>),
    Pine32HmacSha256Aes128(PinePrepState<FieldPrio2Draft09, 32>),
}

impl Encode for VdafPrepState {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::Prio3Draft09Field64HmacSha256Aes128(state) => {
                state.encode(bytes).map_err(upgrade_codec_error)
            }

            Self::Prio3Field64(state) => state.encode(bytes),
            Self::Prio3Field128(state) => state.encode(bytes),

            Self::Prio2(state) => state.encode(bytes),
            Self::Pine64HmacSha256Aes128(state) => state.encode(bytes).map_err(upgrade_codec_error),
            Self::Pine32HmacSha256Aes128(state) => state.encode(bytes).map_err(upgrade_codec_error),
            #[cfg(feature = "experimental")]
            Self::Mastic { .. } => todo!("encoding of prep state is not implemented"),
        }
    }
}

impl ParameterizedDecode<(&VdafConfig, DapAggregatorRole)> for VdafPrepState {
    fn decode_with_param(
        (vdaf_config, role): &(&VdafConfig, DapAggregatorRole),
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match vdaf_config {
            VdafConfig::Prio3(prio3_config) => prio3::decode_prep_state(prio3_config, *role, bytes),
            VdafConfig::Prio2 { dimension } => prio2::decode_prep_state(*dimension, *role, bytes),
            VdafConfig::Pine(config) => pine::decode_prep_state(config, *role, bytes),
            #[cfg(feature = "experimental")]
            VdafConfig::Mastic { .. } => {
                todo!("decoding of mastic prep state is not implemented")
            }
        }
        .map_err(|e| CodecError::Other(Box::new(e)))
    }
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
            | Self::Prio3Draft09Field64HmacSha256Aes128(_)
            | Self::Prio3Field64(_)
            | Self::Prio3Field128(_)
            | Self::Pine64HmacSha256Aes128(_)
            | Self::Pine32HmacSha256Aes128(_) => 0,
            #[cfg(feature = "experimental")]
            Self::Mastic { .. } => 0,
        }
    }
}

/// VDAF preparation message.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug))]
pub enum VdafPrepShare {
    Prio2(Prio2PrepareShare),
    Prio3Draft09Field64HmacSha256Aes128(Prio3Draft09PrepareShare<Field64Draft09, 32>),
    Prio3Field64(Prio3PrepareShare<Field64, 32>),
    Prio3Field128(Prio3PrepareShare<Field128, 32>),
    #[cfg(feature = "experimental")]
    Mastic(Field64),
    Pine64HmacSha256Aes128(crate::pine::msg::PrepShare<Field64Draft09, 32>),
    Pine32HmacSha256Aes128(crate::pine::msg::PrepShare<FieldPrio2Draft09, 32>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafPrepShare {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        match self {
            // The Prio2 prep share consists of three field elements.
            Self::Prio2(_msg) => 3 * FieldPrio2::ENCODED_SIZE,
            // The Prio3 prep share consists of an optional XOF seed for the Aggregator's joint
            // randomness part and a sequence of field elements for the Aggregator's verifier
            // share. The length of the verifier share depends on the Prio3 type, which we don't
            // know at this point. Likewise, whether the XOF seed is present depends on the Prio3
            // type.
            Self::Prio3Draft09Field64HmacSha256Aes128(..)
            | Self::Prio3Field64(..)
            | Self::Prio3Field128(..)
            | Self::Pine64HmacSha256Aes128(_)
            | Self::Pine32HmacSha256Aes128(_) => 0,
            #[cfg(feature = "experimental")]
            Self::Mastic(..) => 0,
        }
    }
}

impl Encode for VdafPrepShare {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::Prio3Draft09Field64HmacSha256Aes128(share) => {
                share.encode(bytes).map_err(upgrade_codec_error)
            }
            Self::Prio3Field64(share) => share.encode(bytes),
            Self::Prio3Field128(share) => share.encode(bytes),
            Self::Prio2(share) => share.encode(bytes),
            #[cfg(feature = "experimental")]
            Self::Mastic(share) => share.encode(bytes),
            Self::Pine64HmacSha256Aes128(share) => share.encode(bytes).map_err(upgrade_codec_error),
            Self::Pine32HmacSha256Aes128(share) => share.encode(bytes).map_err(upgrade_codec_error),
        }
    }
}

impl ParameterizedDecode<VdafPrepState> for VdafPrepShare {
    fn decode_with_param(
        state: &VdafPrepState,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match state {
            VdafPrepState::Prio3Draft09Field64HmacSha256Aes128(state) => {
                Ok(VdafPrepShare::Prio3Draft09Field64HmacSha256Aes128(
                    Prio3Draft09PrepareShare::decode_with_param(state, bytes)
                        .map_err(upgrade_codec_error)?,
                ))
            }
            VdafPrepState::Prio3Field64(state) => Ok(VdafPrepShare::Prio3Field64(
                Prio3PrepareShare::decode_with_param(state, bytes)?,
            )),
            VdafPrepState::Prio3Field128(state) => Ok(VdafPrepShare::Prio3Field128(
                Prio3PrepareShare::decode_with_param(state, bytes)?,
            )),
            VdafPrepState::Prio2(state) => Ok(VdafPrepShare::Prio2(
                Prio2PrepareShare::decode_with_param(state, bytes)?,
            )),
            #[cfg(feature = "experimental")]
            VdafPrepState::Mastic { .. } => {
                todo!("mastic: decoding of prep messages is not implemented")
            }
            VdafPrepState::Pine64HmacSha256Aes128(state) => {
                Ok(VdafPrepShare::Pine64HmacSha256Aes128(
                    crate::pine::msg::PrepShare::decode_with_param(state, bytes)
                        .map_err(upgrade_codec_error)?,
                ))
            }
            VdafPrepState::Pine32HmacSha256Aes128(state) => {
                Ok(VdafPrepShare::Pine32HmacSha256Aes128(
                    crate::pine::msg::PrepShare::decode_with_param(state, bytes)
                        .map_err(upgrade_codec_error)?,
                ))
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VdafAggregateShare {
    Field32Draft09(AggregateShareDraft09<FieldPrio2Draft09>),
    Field64Draft09(AggregateShareDraft09<Field64Draft09>),
    Field128Draft09(AggregateShareDraft09<Field128Draft09>),
    Field32(AggregateShare<FieldPrio2>),
    Field64(AggregateShare<Field64>),
    Field128(AggregateShare<Field128>),
}

#[cfg(any(test, feature = "test-utils"))]
impl deepsize::DeepSizeOf for VdafAggregateShare {
    fn deep_size_of_children(&self, _context: &mut deepsize::Context) -> usize {
        match self {
            VdafAggregateShare::Field32Draft09(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::Field64Draft09(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::Field128Draft09(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::Field32(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::Field64(s) => std::mem::size_of_val(s.as_ref()),
            VdafAggregateShare::Field128(s) => std::mem::size_of_val(s.as_ref()),
        }
    }
}

impl Encode for VdafAggregateShare {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            VdafAggregateShare::Field32Draft09(agg_share) => {
                agg_share.encode(bytes).map_err(upgrade_codec_error)
            }
            VdafAggregateShare::Field64Draft09(agg_share) => {
                agg_share.encode(bytes).map_err(upgrade_codec_error)
            }
            VdafAggregateShare::Field128Draft09(agg_share) => {
                agg_share.encode(bytes).map_err(upgrade_codec_error)
            }
            VdafAggregateShare::Field32(agg_share) => agg_share.encode(bytes),
            VdafAggregateShare::Field64(agg_share) => agg_share.encode(bytes),
            VdafAggregateShare::Field128(agg_share) => agg_share.encode(bytes),
        }
    }
}

impl VdafConfig {
    /// Parse a verification key from raw bytes.
    pub fn get_decoded_verify_key(&self, bytes: &[u8]) -> Result<VdafVerifyKey, CodecError> {
        Ok(VdafVerifyKey(
            <[u8; 32]>::try_from(bytes).map_err(|_| CodecError::UnexpectedValue)?,
        ))
    }

    /// Generate the Aggregators' shared verification parameters.
    pub fn gen_verify_key(&self) -> VdafVerifyKey {
        let mut rng = thread_rng();
        let mut verify_key = VdafVerifyKey([0; 32]);
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
    task_id: TaskId,
    measurement: &V::Measurement,
    nonce: &[u8; 16],
) -> Result<(Vec<u8>, [Vec<u8>; 2]), VdafError> {
    let mut ctx = [0; CTX_STRING_PREFIX.len() + 32];
    ctx[..CTX_STRING_PREFIX.len()].copy_from_slice(CTX_STRING_PREFIX);
    ctx[CTX_STRING_PREFIX.len()..].copy_from_slice(&task_id.0);
    let (public_share, input_shares) = vdaf.shard(&ctx, measurement, nonce)?;

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
    task_id: TaskId,
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

    let mut ctx = [0; CTX_STRING_PREFIX.len() + 32];
    ctx[..CTX_STRING_PREFIX.len()].copy_from_slice(CTX_STRING_PREFIX);
    ctx[CTX_STRING_PREFIX.len()..].copy_from_slice(&task_id.0);

    // Preprocess the inbound messages.
    let message = vdaf.prepare_shares_to_prepare_message(
        &ctx,
        &(),
        if agg_id == 0 {
            [host_share, peer_share]
        } else {
            [peer_share, host_share]
        },
    )?;
    let message_data = message.get_encoded()?;

    // Compute the host's output share.
    match vdaf.prepare_next(&ctx, host_state, message)? {
        PrepareTransition::Continue(..) => Err(VdafError::Dap(fatal_error!(
            err = format!("prep_finish_from_shares: unexpected transition")
        ))),
        PrepareTransition::Finish(out_share) => Ok((out_share, message_data)),
    }
}

fn prep_finish<V, const VERIFY_KEY_SIZE: usize, const NONCE_SIZE: usize>(
    vdaf: &V,
    task_id: TaskId,
    host_state: V::PrepareState,
    peer_message_data: &[u8],
) -> Result<V::OutputShare, VdafError>
where
    V: Vdaf + Aggregator<VERIFY_KEY_SIZE, NONCE_SIZE>,
{
    // Decode the inbound message from the peer, which contains the preprocessed prepare message.
    let peer_message = V::PrepareMessage::get_decoded_with_param(&host_state, peer_message_data)?;

    let mut ctx = [0; CTX_STRING_PREFIX.len() + 32];
    ctx[..CTX_STRING_PREFIX.len()].copy_from_slice(CTX_STRING_PREFIX);
    ctx[CTX_STRING_PREFIX.len()..].copy_from_slice(&task_id.0);
    // Compute the host's output share.

    match vdaf.prepare_next(&ctx, host_state, peer_message)? {
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
