// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! draft-wang-ppm-dap-taskprov: Messages for the taskrpov extension for DAP.

use crate::messages::{
    decode_u16_bytes, encode_u16_bytes, Duration, Time, BATCH_MODE_LEADER_SELECTED,
    BATCH_MODE_TIME_INTERVAL,
};
use crate::pine::PineParam;
use crate::{DapError, DapVersion};
use prio::codec::{
    decode_u16_items, decode_u8_items, encode_u16_items, encode_u8_items, CodecError, Decode,
    Encode, ParameterizedDecode, ParameterizedEncode,
};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::num::NonZeroU32;

use super::{
    decode_base64url_vec, decode_u16_prefixed, encode_base64url, encode_u16_prefixed, TaskId,
};
use crate::error::DapAbort;
use crate::taskprov::compute_task_id;

// VDAF type codes.
const VDAF_TYPE_PRIO2: u32 = 0xFFFF_0000;
pub(crate) const VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128: u32 = 0xFFFF_1003;
pub(crate) const VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128: u32 = 0xffff_1004;
pub(crate) const VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128: u32 = 0xffff_1005;

// Differential privacy mechanism types.
const DP_MECHANISM_NONE: u8 = 0x01;

/// A VDAF type along with its type-specific data.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum VdafConfig {
    Prio2 {
        dimension: u32,
    },
    Prio3SumVecField64MultiproofHmacSha256Aes128 {
        length: u32,
        bits: u8,
        chunk_length: u32,
        num_proofs: u8,
    },
    Pine32HmacSha256Aes128 {
        param: PineParam,
    },
    Pine64HmacSha256Aes128 {
        param: PineParam,
    },
    NotImplemented {
        typ: u32,
        param: Vec<u8>,
    },
}

impl Encode for PineParam {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        let Self {
            norm_bound,
            frac_bits,
            dimension,
            chunk_len,
            chunk_len_sq_norm_equal,
            num_proofs,
            num_proofs_sq_norm_equal,
            num_wr_tests,
            num_wr_successes,
        } = *self;

        norm_bound.encode(bytes)?; // l2_norm_bound
        u32::try_from(frac_bits)
            .map_err(|_| CodecError::UnexpectedValue)?
            .encode(bytes)?; // num_frac_bits
        u32::try_from(dimension)
            .map_err(|_| CodecError::UnexpectedValue)?
            .encode(bytes)?; // length
        u32::try_from(chunk_len)
            .map_err(|_| CodecError::UnexpectedValue)?
            .encode(bytes)?; // chunk_length
        u32::try_from(chunk_len_sq_norm_equal)
            .map_err(|_| CodecError::UnexpectedValue)?
            .encode(bytes)?; // chunk_length_norm_equality
        num_proofs.encode(bytes)?;
        num_proofs_sq_norm_equal.encode(bytes)?;
        u16::try_from(num_wr_tests)
            .map_err(|_| CodecError::UnexpectedValue)?
            .encode(bytes)?; // num_wr_checks
        u16::try_from(num_wr_successes)
            .map_err(|_| CodecError::UnexpectedValue)?
            .encode(bytes)?;
        Ok(())
    }
}

impl Decode for PineParam {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let l2_norm_bound = u64::decode(bytes)?;
        let num_frac_bits = u32::decode(bytes)?;
        let length = u32::decode(bytes)?;
        let chunk_length = u32::decode(bytes)?;
        let chunk_length_norm_equality = u32::decode(bytes)?;
        let num_proofs = u8::decode(bytes)?;
        let num_proofs_sq_norm_equal = u8::decode(bytes)?;
        let num_wr_checks = u16::decode(bytes)?;
        let num_wr_successes = u16::decode(bytes)?;
        Ok(Self {
            norm_bound: l2_norm_bound,
            dimension: length
                .try_into()
                .map_err(|_| CodecError::Other("length is too large for usize".into()))?,
            frac_bits: num_frac_bits
                .try_into()
                .map_err(|_| CodecError::Other("num_frac_bits is too large for usize".into()))?,
            chunk_len: chunk_length
                .try_into()
                .map_err(|_| CodecError::Other("chunk_length is too large for usize".into()))?,
            chunk_len_sq_norm_equal: chunk_length_norm_equality.try_into().map_err(|_| {
                CodecError::Other("chunk_length_norm_equality is too large for usize".into())
            })?,
            num_proofs,
            num_proofs_sq_norm_equal,
            num_wr_tests: num_wr_checks.into(),
            num_wr_successes: num_wr_successes.into(),
        })
    }
}

impl ParameterizedEncode<DapVersion> for VdafConfig {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match version {
            DapVersion::Draft09 => match self {
                Self::Prio2 { dimension } => {
                    VDAF_TYPE_PRIO2.encode(bytes)?;
                    dimension.encode(bytes)?;
                }
                Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                    length,
                    bits,
                    chunk_length,
                    num_proofs,
                } => {
                    VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128.encode(bytes)?;
                    length.encode(bytes)?;
                    bits.encode(bytes)?;
                    chunk_length.encode(bytes)?;
                    num_proofs.encode(bytes)?;
                }
                Self::Pine32HmacSha256Aes128 { param } => {
                    VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128.encode(bytes)?;
                    param.encode(bytes)?;
                }
                Self::Pine64HmacSha256Aes128 { param } => {
                    VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128.encode(bytes)?;
                    param.encode(bytes)?;
                }
                Self::NotImplemented { typ, param } => {
                    typ.encode(bytes)?;
                    bytes.extend_from_slice(param);
                }
            },
            DapVersion::Latest => match self {
                Self::Prio2 { dimension } => {
                    VDAF_TYPE_PRIO2.encode(bytes)?;
                    encode_u16_prefixed(*version, bytes, |_version, bytes| {
                        dimension.encode(bytes)?;
                        Ok(())
                    })?;
                }
                Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                    length,
                    bits,
                    chunk_length,
                    num_proofs,
                } => {
                    VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128.encode(bytes)?;
                    encode_u16_prefixed(*version, bytes, |_version, bytes| {
                        length.encode(bytes)?;
                        bits.encode(bytes)?;
                        chunk_length.encode(bytes)?;
                        num_proofs.encode(bytes)?;
                        Ok(())
                    })?;
                }
                Self::Pine32HmacSha256Aes128 { param } => {
                    VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128.encode(bytes)?;
                    encode_u16_prefixed(*version, bytes, |_version, bytes| {
                        param.encode(bytes)?;
                        Ok(())
                    })?;
                }
                Self::Pine64HmacSha256Aes128 { param } => {
                    VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128.encode(bytes)?;
                    encode_u16_prefixed(*version, bytes, |_version, bytes| {
                        param.encode(bytes)?;
                        Ok(())
                    })?;
                }
                Self::NotImplemented { typ, param } => {
                    typ.encode(bytes)?;
                    encode_u16_prefixed(*version, bytes, |_version, bytes| {
                        bytes.extend_from_slice(param);
                        Ok(())
                    })?;
                }
            },
        };
        Ok(())
    }
}

impl ParameterizedDecode<(DapVersion, Option<usize>)> for VdafConfig {
    fn decode_with_param(
        (version, bytes_left): &(DapVersion, Option<usize>),
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match version {
            DapVersion::Draft09 => match (bytes_left, u32::decode(bytes)?) {
                (.., VDAF_TYPE_PRIO2) => Ok(Self::Prio2 {
                    dimension: u32::decode(bytes)?,
                }),
                (.., VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128) => {
                    Ok(Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                        length: u32::decode(bytes)?,
                        bits: u8::decode(bytes)?,
                        chunk_length: u32::decode(bytes)?,
                        num_proofs: u8::decode(bytes)?,
                    })
                }
                (.., VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128) => {
                    Ok(Self::Pine32HmacSha256Aes128 {
                        param: PineParam::decode(bytes)?,
                    })
                }
                (.., VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128) => {
                    Ok(Self::Pine64HmacSha256Aes128 {
                        param: PineParam::decode(bytes)?,
                    })
                }
                (Some(bytes_left), typ) => {
                    let mut param = vec![0; bytes_left - 4];
                    bytes.read_exact(&mut param)?;
                    Ok(Self::NotImplemented { typ, param })
                }
                (None, ..) => Err(CodecError::Other(
                    "cannot decode VdafConfig variant without knowing the length of the remainder"
                        .into(),
                )),
            },
            DapVersion::Latest => match u32::decode(bytes)? {
                VDAF_TYPE_PRIO2 => {
                    decode_u16_prefixed(*version, bytes, |_version, bytes, _bytes_left| {
                        Ok(Self::Prio2 {
                            dimension: u32::decode(bytes)?,
                        })
                    })
                }
                VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128 => {
                    decode_u16_prefixed(*version, bytes, |_version, bytes, _bytes_left| {
                        Ok(Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                            length: u32::decode(bytes)?,
                            bits: u8::decode(bytes)?,
                            chunk_length: u32::decode(bytes)?,
                            num_proofs: u8::decode(bytes)?,
                        })
                    })
                }
                VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128 => {
                    decode_u16_prefixed(*version, bytes, |_version, bytes, _bytes_left| {
                        Ok(Self::Pine32HmacSha256Aes128 {
                            param: PineParam::decode(bytes)?,
                        })
                    })
                }
                VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128 => {
                    decode_u16_prefixed(*version, bytes, |_version, bytes, _bytes_left| {
                        Ok(Self::Pine64HmacSha256Aes128 {
                            param: PineParam::decode(bytes)?,
                        })
                    })
                }
                typ => Ok(Self::NotImplemented {
                    typ,
                    param: decode_u16_bytes(bytes)?,
                }),
            },
        }
    }
}

/// A differential privacy mechanism.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum DpConfig {
    None,
    NotImplemented { typ: u8, param: Vec<u8> },
}

impl Encode for DpConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::None => {
                DP_MECHANISM_NONE.encode(bytes)?;
            }
            Self::NotImplemented { typ, param } => {
                typ.encode(bytes)?;
                bytes.extend_from_slice(param);
            }
        };
        Ok(())
    }
}

impl ParameterizedDecode<(DapVersion, Option<usize>)> for DpConfig {
    fn decode_with_param(
        (_version, bytes_left): &(DapVersion, Option<usize>),
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let dp_mechanism = u8::decode(bytes)?;
        match (bytes_left, dp_mechanism) {
            (.., DP_MECHANISM_NONE) => Ok(Self::None),
            (Some(bytes_left), ..) => {
                let mut param = vec![0; bytes_left - 1];
                bytes.read_exact(&mut param)?;
                Ok(Self::NotImplemented {
                    typ: dp_mechanism,
                    param,
                })
            }
            (None, ..) => Err(CodecError::Other(
                "cannot decode DpConfig variant without knowing the length of the remainder".into(),
            )),
        }
    }
}

/// A URL encode / decode helper struct, essentially a box for
/// a `Vec<u8>`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UrlBytes {
    pub bytes: Vec<u8>,
}

impl Encode for UrlBytes {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_u16_bytes(bytes, &self.bytes)
    }
}

impl Decode for UrlBytes {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            bytes: decode_u16_bytes(bytes)?,
        })
    }
}

/// A `QueryConfig` type and its associated task configuration data.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum QueryConfig {
    TimeInterval,
    LeaderSelected {
        draft09_max_batch_size: Option<NonZeroU32>,
    },
    NotImplemented {
        mode: u8,
        param: Vec<u8>,
    },
}

impl ParameterizedEncode<DapVersion> for QueryConfig {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match version {
            DapVersion::Draft09 => match self {
                Self::TimeInterval => {
                    BATCH_MODE_TIME_INTERVAL.encode(bytes)?;
                }
                Self::LeaderSelected {
                    draft09_max_batch_size,
                } => {
                    BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                    match draft09_max_batch_size {
                        Some(ref max_batch_size) => max_batch_size.get().encode(bytes)?,
                        None => 0_u32.encode(bytes)?,
                    }
                }
                Self::NotImplemented { mode, ref param } => {
                    mode.encode(bytes)?;
                    bytes.extend_from_slice(param);
                }
            },
            DapVersion::Latest => match self {
                Self::TimeInterval => {
                    BATCH_MODE_TIME_INTERVAL.encode(bytes)?;
                    encode_u16_prefixed(*version, bytes, |_, _| Ok(()))?;
                }
                Self::LeaderSelected {
                    draft09_max_batch_size: None,
                } => {
                    BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                    encode_u16_prefixed(*version, bytes, |_, _| Ok(()))?;
                }
                Self::LeaderSelected {
                    draft09_max_batch_size: Some(_),
                } => {
                    return Err(CodecError::Other(
                        "expected max batch size to not be set".into(),
                    ))
                }
                Self::NotImplemented { mode, ref param } => {
                    mode.encode(bytes)?;
                    encode_u16_bytes(bytes, param)?;
                }
            },
        }
        Ok(())
    }
}

impl ParameterizedDecode<(DapVersion, Option<usize>)> for QueryConfig {
    fn decode_with_param(
        (version, bytes_left): &(DapVersion, Option<usize>),
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match (version, bytes_left) {
            (DapVersion::Draft09, Some(bytes_left)) => match u8::decode(bytes)? {
                BATCH_MODE_TIME_INTERVAL => Ok(Self::TimeInterval),
                BATCH_MODE_LEADER_SELECTED => Ok(Self::LeaderSelected {
                    draft09_max_batch_size: NonZeroU32::new(u32::decode(bytes)?),
                }),
                mode => {
                    let mut param = vec![0; *bytes_left - 1];
                    bytes.read_exact(&mut param)?;
                    Ok(Self::NotImplemented { mode, param })
                }
            },
            (DapVersion::Draft09, None) => Err(CodecError::Other(
                "draft 09: can't decode query config without knowing the number of bytes remaining"
                    .into(),
            )),
            (DapVersion::Latest, _) => match u8::decode(bytes)? {
                BATCH_MODE_TIME_INTERVAL => {
                    decode_u16_prefixed(*version, bytes, |_, _, _| Ok(()))?;
                    Ok(Self::TimeInterval)
                }
                BATCH_MODE_LEADER_SELECTED => {
                    decode_u16_prefixed(*version, bytes, |_, _, _| Ok(()))?;
                    Ok(Self::LeaderSelected {
                        draft09_max_batch_size: None,
                    })
                }
                mode => Ok(Self::NotImplemented {
                    mode,
                    param: decode_u16_bytes(bytes)?,
                }),
            },
        }
    }
}

/// Task lifetime parameters.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum TaskLifetime {
    Latest {
        /// Task start time.
        start: Time,
        /// Task duration.
        duration: Duration,
    },
    /// draft09 compatibility: Previously the DAP task parameters (and thus Taskprov) only
    /// expressed an end time and not a start time.
    Draft09 { expiration: Time },
}

impl TaskLifetime {
    pub(crate) fn from_validity_range(
        version: DapVersion,
        not_before: Time,
        not_after: Time,
    ) -> Self {
        match version {
            DapVersion::Draft09 => Self::Draft09 {
                expiration: not_after,
            },
            DapVersion::Latest => Self::Latest {
                start: not_before,
                duration: not_after - not_before,
            },
        }
    }
}

/// Taskprov extensions.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum TaskprovExtension {
    NotImplemented { typ: u16, payload: Vec<u8> },
}

impl Encode for TaskprovExtension {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::NotImplemented { typ, payload } => {
                typ.encode(bytes)?;
                encode_u16_bytes(bytes, payload)?;
            }
        };
        Ok(())
    }
}

impl Decode for TaskprovExtension {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self::NotImplemented {
            typ: u16::decode(bytes)?,
            payload: decode_u16_bytes(bytes)?,
        })
    }
}

/// A DAP task configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TaskprovAdvertisement {
    pub task_info: Vec<u8>,
    pub leader_url: UrlBytes,
    pub helper_url: UrlBytes,
    pub time_precision: Duration,
    pub min_batch_size: u32,
    pub query_config: QueryConfig,
    pub lifetime: TaskLifetime,
    pub vdaf_config: VdafConfig,
    pub extensions: Vec<TaskprovExtension>,
    pub draft09_max_batch_query_count: Option<u16>,
    pub draft09_dp_config: Option<DpConfig>,
}

impl TaskprovAdvertisement {
    /// Check for a taskprov extension in the report, and return it if found.
    pub fn parse_taskprov_advertisement(
        taskprov_advertisement: &str,
        task_id: &TaskId,
        version: DapVersion,
    ) -> Result<TaskprovAdvertisement, DapAbort> {
        let taskprov_data = decode_base64url_vec(taskprov_advertisement).ok_or_else(|| {
            DapAbort::BadRequest(
                r#"Invalid advertisement in "dap-taskprov" header: base64url parsing failed"#
                    .to_string(),
            )
        })?;

        if compute_task_id(taskprov_data.as_ref()) != *task_id {
            // Return unrecognizedTask following section 5.1 of the taskprov draft.
            return Err(DapAbort::UnrecognizedTask { task_id: *task_id });
        }

        // Return unrecognizedMessage if parsing fails following section 5.1 of the taskprov draft.
        let task_config =
            TaskprovAdvertisement::get_decoded_with_param(&version, taskprov_data.as_ref())
                .map_err(|e| DapAbort::from_codec_error(e, *task_id))?;

        Ok(task_config)
    }

    pub fn serialize_to_header_value(&self, version: DapVersion) -> Result<String, DapError> {
        let encoded = self
            .get_encoded_with_param(&version)
            .map_err(DapError::encoding)?;
        Ok(encode_base64url(encoded))
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn compute_task_id(&self, version: DapVersion) -> TaskId {
        compute_task_id(&self.get_encoded_with_param(&version).unwrap())
    }
}

impl ParameterizedEncode<DapVersion> for TaskprovAdvertisement {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match version {
            DapVersion::Draft09 => {
                encode_u8_items(bytes, &(), &self.task_info)?;
                self.leader_url.encode(bytes)?;
                self.helper_url.encode(bytes)?;
                encode_u16_prefixed(*version, bytes, |version, bytes| {
                    self.time_precision.encode(bytes)?;
                    let Some(max_batch_query_count) = self.draft09_max_batch_query_count else {
                        return Err(CodecError::Other(
                            "max batch query count should be set".into(),
                        ));
                    };
                    max_batch_query_count.encode(bytes)?;
                    self.min_batch_size.encode(bytes)?;
                    self.query_config.encode_with_param(&version, bytes)?;
                    Ok(())
                })?;
                let TaskLifetime::Draft09 { expiration } = self.lifetime else {
                    return Err(CodecError::Other("task expiration should be set".into()));
                };
                expiration.encode(bytes)?;
                encode_u16_prefixed(*version, bytes, |version, bytes| {
                    encode_u16_prefixed(version, bytes, |_version, bytes| {
                        let Some(ref dp_config) = self.draft09_dp_config else {
                            return Err(CodecError::Other("dp config should be set".into()));
                        };
                        dp_config.encode(bytes)?;
                        Ok(())
                    })?;
                    self.vdaf_config.encode_with_param(&version, bytes)
                })?;
                if !self.extensions.is_empty() {
                    return Err(CodecError::Other("extensions field should be empty".into()));
                }
            }

            DapVersion::Latest => {
                encode_u8_items(bytes, &(), &self.task_info)?;
                self.leader_url.encode(bytes)?;
                self.helper_url.encode(bytes)?;
                self.time_precision.encode(bytes)?;
                self.min_batch_size.encode(bytes)?;
                self.query_config.encode_with_param(version, bytes)?;
                let TaskLifetime::Latest { start, duration } = self.lifetime else {
                    return Err(CodecError::Other(
                        "task start time and duration should be set".into(),
                    ));
                };
                start.encode(bytes)?;
                duration.encode(bytes)?;
                self.vdaf_config.encode_with_param(version, bytes)?;
                encode_u16_items(bytes, &(), &self.extensions)?;
            }
        }
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for TaskprovAdvertisement {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match version {
            DapVersion::Draft09 => {
                let task_info = decode_u8_items(&(), bytes)?;
                let leader_url = UrlBytes::decode(bytes)?;
                let helper_url = UrlBytes::decode(bytes)?;
                let (time_precision, draft09_max_batch_query_count, min_batch_size, query_config) =
                    decode_u16_prefixed(*version, bytes, |version, bytes, mut bytes_left| {
                        let time_precision = Time::decode(bytes)?;
                        let max_batch_query_count = u16::decode(bytes)?;
                        let min_batch_size = u32::decode(bytes)?;
                        // We need to know the length of the `QueryConfig` in order to decode variants we don't
                        // recognize. Likewise for `VdafConfig` below.
                        //
                        // Ideally the message can be decoded without knowing the length of the remainder. This
                        // is not possible because of taskprov's choice to prefix the `QueryConfig` with its
                        // length, rather than prefix the variant part (everything after the "select"). We
                        // could modify taskprov so that the length prefix immediately precedes the bits that
                        // we don't know how to parse. This would be consistent with other protocols that use
                        // TLS syntax. We could also consider dropping TLS syntax in the DAP spec in favor of a
                        // format that is better at being self-describing.
                        bytes_left = bytes_left.map(|l| l - 14);
                        let query_config =
                            QueryConfig::decode_with_param(&(version, bytes_left), bytes)?;
                        Ok((
                            time_precision,
                            Some(max_batch_query_count),
                            min_batch_size,
                            query_config,
                        ))
                    })?;
                let lifetime = TaskLifetime::Draft09 {
                    expiration: Time::decode(bytes)?,
                };
                let (draft09_dp_config, vdaf_config) =
                    decode_u16_prefixed(*version, bytes, |version, bytes, mut bytes_left| {
                        let dp_config_bytes = decode_u16_bytes(bytes)?;
                        let dp_config = DpConfig::get_decoded_with_param(
                            &(version, Some(dp_config_bytes.len())),
                            &dp_config_bytes,
                        )?;
                        bytes_left = bytes_left.map(|len| len - dp_config_bytes.len());
                        let vdaf_config =
                            VdafConfig::decode_with_param(&(version, bytes_left), bytes)?;
                        Ok((Some(dp_config), vdaf_config))
                    })?;

                Ok(TaskprovAdvertisement {
                    task_info,
                    leader_url,
                    helper_url,
                    time_precision,
                    min_batch_size,
                    query_config,
                    lifetime,
                    vdaf_config,
                    extensions: Vec::new(),
                    draft09_dp_config,
                    draft09_max_batch_query_count,
                })
            }

            DapVersion::Latest => {
                let task_info = decode_u8_items(&(), bytes)?;
                let leader_url = UrlBytes::decode(bytes)?;
                let helper_url = UrlBytes::decode(bytes)?;
                let time_precision = Duration::decode(bytes)?;
                let min_batch_size = u32::decode(bytes)?;
                let query_config = QueryConfig::decode_with_param(&(*version, None), bytes)?;
                let lifetime = TaskLifetime::Latest {
                    start: Time::decode(bytes)?,
                    duration: Duration::decode(bytes)?,
                };
                let vdaf_config = VdafConfig::decode_with_param(&(*version, None), bytes)?;
                let extensions = decode_u16_items(&(), bytes)?;

                Ok(TaskprovAdvertisement {
                    task_info,
                    leader_url,
                    helper_url,
                    time_precision,
                    min_batch_size,
                    query_config,
                    lifetime,
                    vdaf_config,
                    extensions,
                    draft09_dp_config: None,
                    draft09_max_batch_query_count: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_versions;

    use super::*;

    fn read_task_config(version: DapVersion) {
        let want = TaskprovAdvertisement {
            task_info: b"this is a cool task!".to_vec(),
            leader_url: UrlBytes {
                bytes: b"http://exmaple.com/v02".to_vec(),
            },
            helper_url: UrlBytes {
                bytes: b"https://someservice.cloudflareresearch.com".to_vec(),
            },
            time_precision: 12_341_234,
            min_batch_size: 55,
            query_config: QueryConfig::LeaderSelected {
                draft09_max_batch_size: match version {
                    DapVersion::Draft09 => Some(NonZeroU32::new(57).unwrap()),
                    DapVersion::Latest => None,
                },
            },
            lifetime: TaskLifetime::from_validity_range(version, 23_232_232_232, 23_232_232_232),
            vdaf_config: VdafConfig::Prio2 { dimension: 99_999 },
            extensions: match version {
                DapVersion::Latest => vec![
                    TaskprovExtension::NotImplemented {
                        typ: 1337,
                        payload: b"collecter.com".to_vec(),
                    },
                    TaskprovExtension::NotImplemented {
                        typ: 42,
                        payload: b"hey, don't forget the differential privacy!!".to_vec(),
                    },
                ],
                DapVersion::Draft09 => Vec::new(),
            },
            draft09_max_batch_query_count: match version {
                DapVersion::Draft09 => Some(1337),
                DapVersion::Latest => None,
            },
            draft09_dp_config: match version {
                DapVersion::Draft09 => Some(DpConfig::None),
                DapVersion::Latest => None,
            },
        };
        println!("want {:?}", want.get_encoded_with_param(&version).unwrap());

        let task_config_bytes = match version {
            DapVersion::Draft09 => [
                20, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 99, 111, 111, 108, 32, 116, 97,
                115, 107, 33, 0, 22, 104, 116, 116, 112, 58, 47, 47, 101, 120, 109, 97, 112, 108,
                101, 46, 99, 111, 109, 47, 118, 48, 50, 0, 42, 104, 116, 116, 112, 115, 58, 47, 47,
                115, 111, 109, 101, 115, 101, 114, 118, 105, 99, 101, 46, 99, 108, 111, 117, 100,
                102, 108, 97, 114, 101, 114, 101, 115, 101, 97, 114, 99, 104, 46, 99, 111, 109, 0,
                19, 0, 0, 0, 0, 0, 188, 79, 242, 5, 57, 0, 0, 0, 55, 2, 0, 0, 0, 57, 0, 0, 0, 5,
                104, 191, 187, 40, 0, 11, 0, 1, 1, 255, 255, 0, 0, 0, 1, 134, 159,
            ]
            .as_slice(),
            DapVersion::Latest => [
                20, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 99, 111, 111, 108, 32, 116, 97,
                115, 107, 33, 0, 22, 104, 116, 116, 112, 58, 47, 47, 101, 120, 109, 97, 112, 108,
                101, 46, 99, 111, 109, 47, 118, 48, 50, 0, 42, 104, 116, 116, 112, 115, 58, 47, 47,
                115, 111, 109, 101, 115, 101, 114, 118, 105, 99, 101, 46, 99, 108, 111, 117, 100,
                102, 108, 97, 114, 101, 114, 101, 115, 101, 97, 114, 99, 104, 46, 99, 111, 109, 0,
                0, 0, 0, 0, 188, 79, 242, 0, 0, 0, 55, 2, 0, 0, 0, 0, 0, 5, 104, 191, 187, 40, 0,
                0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 4, 0, 1, 134, 159, 0, 65, 5, 57, 0, 13, 99,
                111, 108, 108, 101, 99, 116, 101, 114, 46, 99, 111, 109, 0, 42, 0, 44, 104, 101,
                121, 44, 32, 100, 111, 110, 39, 116, 32, 102, 111, 114, 103, 101, 116, 32, 116,
                104, 101, 32, 100, 105, 102, 102, 101, 114, 101, 110, 116, 105, 97, 108, 32, 112,
                114, 105, 118, 97, 99, 121, 33, 33,
            ]
            .as_slice(),
        };
        let got =
            TaskprovAdvertisement::get_decoded_with_param(&version, task_config_bytes).unwrap();
        assert_eq!(got, want);
    }

    test_versions! { read_task_config }

    fn roundtrip_query_config(version: DapVersion) {
        let query_config = QueryConfig::TimeInterval;
        let encoded = query_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            QueryConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
            query_config
        );

        let query_config = QueryConfig::LeaderSelected {
            draft09_max_batch_size: match version {
                DapVersion::Draft09 => Some(NonZeroU32::new(12_345_678).unwrap()),
                DapVersion::Latest => None,
            },
        };
        let encoded = query_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            QueryConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
            query_config
        );
    }

    test_versions! { roundtrip_query_config }

    fn roundtrip_query_config_not_implemented(version: DapVersion) {
        let query_config = QueryConfig::NotImplemented {
            mode: 0,
            param: b"query config param".to_vec(),
        };
        let encoded = query_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            QueryConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded,)
                .unwrap(),
            query_config
        );
    }

    test_versions! { roundtrip_query_config_not_implemented }

    fn roundtrip_dp_config(version: DapVersion) {
        let dp_config = DpConfig::None;
        let encoded = dp_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            DpConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
            dp_config
        );
    }

    test_versions! { roundtrip_dp_config }

    fn roundtrip_dp_config_not_implemented(version: DapVersion) {
        let dp_config = DpConfig::NotImplemented {
            typ: 0,
            param: b"dp mechanism param".to_vec(),
        };
        let encoded = dp_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            DpConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded,).unwrap(),
            dp_config
        );
    }

    test_versions! { roundtrip_dp_config_not_implemented }

    fn roundtrip_vdaf_config_prio2(version: DapVersion) {
        let vdaf_config = VdafConfig::Prio2 { dimension: 1337 };
        assert_eq!(
            VdafConfig::get_decoded_with_param(
                &(version, None),
                &vdaf_config.get_encoded_with_param(&version).unwrap()
            )
            .unwrap(),
            vdaf_config
        );
    }

    test_versions! { roundtrip_vdaf_config_prio2 }

    fn roundtrip_vdaf_config_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
        version: DapVersion,
    ) {
        let vdaf_config = VdafConfig::Prio3SumVecField64MultiproofHmacSha256Aes128 {
            bits: 23,
            length: 1337,
            chunk_length: 42,
            num_proofs: 99,
        };
        let encoded = vdaf_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            VdafConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
            vdaf_config
        );
    }

    test_versions! { roundtrip_vdaf_config_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128 }

    fn roundtrip_vdaf_config_pine32_hmac_sha256_aes128(version: DapVersion) {
        let vdaf_config = VdafConfig::Pine32HmacSha256Aes128 {
            param: PineParam {
                norm_bound: 1337,
                dimension: 1_000_000,
                frac_bits: 15,
                chunk_len: 999,
                chunk_len_sq_norm_equal: 1400,
                num_proofs: 15,
                num_proofs_sq_norm_equal: 1,
                num_wr_tests: 50,
                num_wr_successes: 17,
            },
        };
        let encoded = vdaf_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            VdafConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
            vdaf_config
        );
    }

    test_versions! { roundtrip_vdaf_config_pine32_hmac_sha256_aes128 }

    fn roundtrip_vdaf_config_pine64_hmac_sha256_aes128(version: DapVersion) {
        let vdaf_config = VdafConfig::Pine64HmacSha256Aes128 {
            param: PineParam {
                norm_bound: 1337,
                dimension: 1_000_000,
                frac_bits: 15,
                chunk_len: 999,
                chunk_len_sq_norm_equal: 1400,
                num_proofs: 15,
                num_proofs_sq_norm_equal: 17,
                num_wr_tests: 50,
                num_wr_successes: 17,
            },
        };
        let encoded = vdaf_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            VdafConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
            vdaf_config
        );
    }

    test_versions! { roundtrip_vdaf_config_pine64_hmac_sha256_aes128 }

    fn roundtrip_taskprov_advertisement(version: DapVersion) {
        let taskprov_advertisement = TaskprovAdvertisement {
            task_info: b"this is a cool task!".to_vec(),
            leader_url: UrlBytes {
                bytes: b"http://exmaple.com/v02".to_vec(),
            },
            helper_url: UrlBytes {
                bytes: b"https://someservice.cloudflareresearch.com".to_vec(),
            },
            time_precision: 12_341_234,
            min_batch_size: 55,
            query_config: QueryConfig::LeaderSelected {
                draft09_max_batch_size: match version {
                    DapVersion::Draft09 => Some(NonZeroU32::new(57).unwrap()),
                    DapVersion::Latest => None,
                },
            },
            lifetime: TaskLifetime::from_validity_range(version, 23_232_232_232, 23_232_232_232),
            vdaf_config: VdafConfig::Prio2 { dimension: 99_999 },
            extensions: Vec::new(),
            draft09_max_batch_query_count: match version {
                DapVersion::Draft09 => Some(1337),
                DapVersion::Latest => None,
            },

            draft09_dp_config: match version {
                DapVersion::Draft09 => Some(DpConfig::None),
                DapVersion::Latest => None,
            },
        };

        assert_eq!(
            taskprov_advertisement,
            TaskprovAdvertisement::parse_taskprov_advertisement(
                &taskprov_advertisement
                    .serialize_to_header_value(version)
                    .unwrap(),
                &taskprov_advertisement.compute_task_id(version),
                version,
            )
            .unwrap()
        );
    }

    test_versions! { roundtrip_taskprov_advertisement }

    fn roundtrip_vdaf_config_not_implemented(version: DapVersion) {
        let vdaf_config = VdafConfig::NotImplemented {
            typ: 1337,
            param: b"vdaf type param".to_vec(),
        };
        let encoded = vdaf_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            VdafConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
            vdaf_config
        );
    }

    test_versions! { roundtrip_vdaf_config_not_implemented }

    fn parse_taskprov_advertisement_with_wrong_task_id(version: DapVersion) {
        let taskprov_advertisement = TaskprovAdvertisement {
            task_info: b"this is a cool task!".to_vec(),
            leader_url: UrlBytes {
                bytes: b"http://exmaple.com/v02".to_vec(),
            },
            helper_url: UrlBytes {
                bytes: b"https://someservice.cloudflareresearch.com".to_vec(),
            },
            time_precision: 12_341_234,
            min_batch_size: 55,
            query_config: QueryConfig::LeaderSelected {
                draft09_max_batch_size: match version {
                    DapVersion::Draft09 => Some(NonZeroU32::new(57).unwrap()),
                    DapVersion::Latest => None,
                },
            },
            lifetime: TaskLifetime::from_validity_range(version, 23_232_232_232, 23_232_232_232),
            vdaf_config: VdafConfig::Prio2 { dimension: 99_999 },
            extensions: Vec::new(),
            draft09_max_batch_query_count: match version {
                DapVersion::Draft09 => Some(1337),
                DapVersion::Latest => None,
            },
            draft09_dp_config: match version {
                DapVersion::Draft09 => Some(DpConfig::None),
                DapVersion::Latest => None,
            },
        };

        let err = TaskprovAdvertisement::parse_taskprov_advertisement(
            &taskprov_advertisement
                .serialize_to_header_value(version)
                .unwrap(),
            &TaskId([1; 32]),
            version,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DapAbort::UnrecognizedTask {
                task_id: TaskId([1; 32]),
            }
        );
    }

    test_versions! { parse_taskprov_advertisement_with_wrong_task_id }
}
