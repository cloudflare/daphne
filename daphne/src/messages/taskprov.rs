// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Messages in the taskprov extension to the DAP protocol, as
//! defined in draft-wang-ppm-dap-taskprov-02.

use crate::messages::{
    decode_u16_bytes, encode_u16_bytes, Duration, Time, QUERY_TYPE_FIXED_SIZE,
    QUERY_TYPE_TIME_INTERVAL,
};
use crate::vdaf::VDAF_VERIFY_KEY_SIZE_PRIO2;
use crate::DapVersion;
use prio::codec::{
    decode_u16_items, decode_u8_items, encode_u16_items, encode_u8_items, CodecError, Decode,
    Encode, ParameterizedDecode, ParameterizedEncode,
};
use ring::hkdf::KeyType;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

// VDAF type codes.
const VDAF_TYPE_PRIO2: u32 = 0xFFFF_0000;

// Differential privacy mechanism types.
const DP_MECHANISM_NONE: u8 = 0x01;

/// A VDAF type.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VdafType {
    Prio2,
    NotImplemented(u32),
}

impl KeyType for VdafType {
    fn len(&self) -> usize {
        match self {
            VdafType::Prio2 => VDAF_VERIFY_KEY_SIZE_PRIO2,
            VdafType::NotImplemented(_) => panic!("tried to get key length for undefined VDAF"),
        }
    }
}

/// A VDAF type along with its type-specific data.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum VdafTypeVar {
    Prio2 {
        dimension: u32,
    },
    #[cfg(test)]
    NotImplemented(u32),
}

impl Encode for VdafTypeVar {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match &self {
            VdafTypeVar::Prio2 { dimension } => {
                VDAF_TYPE_PRIO2.encode(bytes);
                dimension.encode(bytes);
            }
            #[cfg(test)]
            VdafTypeVar::NotImplemented(x) => {
                x.encode(bytes);
            }
        }
    }
}

impl Decode for VdafTypeVar {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let x = u32::decode(bytes)?;
        match x {
            VDAF_TYPE_PRIO2 => Ok(Self::Prio2 {
                dimension: u32::decode(bytes)?,
            }),
            // We don't recognize the VDAF type, which means there may be parameters that follow
            // and we don't know how many bytes to parse.
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

impl From<VdafTypeVar> for VdafType {
    fn from(var: VdafTypeVar) -> Self {
        match var {
            VdafTypeVar::Prio2 { .. } => VdafType::Prio2,
            #[cfg(test)]
            VdafTypeVar::NotImplemented(x) => VdafType::NotImplemented(x),
        }
    }
}

/// A differential privacy mechanism.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum DpConfig {
    None,
}

impl Encode for DpConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::None => DP_MECHANISM_NONE.encode(bytes),
        }
    }
}

impl Decode for DpConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            DP_MECHANISM_NONE => Ok(Self::None),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// A VDAF configuration, made up from a differential privacy configuration,
/// a VDAF type, and type-specific configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VdafConfig {
    pub dp_config: DpConfig,
    pub var: VdafTypeVar,
}

impl Encode for VdafConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.dp_config.encode(bytes);
        self.var.encode(bytes);
    }
}

impl Decode for VdafConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            dp_config: DpConfig::decode(bytes)?,
            var: VdafTypeVar::decode(bytes)?,
        })
    }
}

/// A URL encode / decode helper struct, essentially a box for
/// a `Vec<u8>`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UrlBytes {
    pub bytes: Vec<u8>,
}

impl Encode for UrlBytes {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_bytes(bytes, &self.bytes);
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
pub enum QueryConfigVar {
    TimeInterval,
    FixedSize { max_batch_size: u32 },
}

// There is no Encode or Decode for QueryConfigVar as we have to split the query type and
// the associated configuration data in the message format, so we must do all of the work
// in QueryConfig's Encode and Decode.  If the spec is revised to allow these fields
// to be encoded and decoded contiguously, then we will revise this code.

/// A query configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct QueryConfig {
    pub time_precision: Duration,
    pub max_batch_query_count: u16,
    pub min_batch_size: u32,
    pub var: QueryConfigVar,
}

impl QueryConfig {
    fn encode_query_type(&self, bytes: &mut Vec<u8>) {
        match &self.var {
            QueryConfigVar::TimeInterval => {
                QUERY_TYPE_TIME_INTERVAL.encode(bytes);
            }
            QueryConfigVar::FixedSize { .. } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes);
            }
        }
    }
}

impl ParameterizedEncode<DapVersion> for QueryConfig {
    fn encode_with_param(&self, _version: &DapVersion, bytes: &mut Vec<u8>) {
        self.encode_query_type(bytes);
        self.time_precision.encode(bytes);
        self.max_batch_query_count.encode(bytes);
        self.min_batch_size.encode(bytes);
        match &self.var {
            QueryConfigVar::TimeInterval => (),
            QueryConfigVar::FixedSize { max_batch_size } => {
                max_batch_size.encode(bytes);
            }
        }
    }
}

impl ParameterizedDecode<DapVersion> for QueryConfig {
    fn decode_with_param(
        _version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let query_type = u8::decode(bytes)?;
        let time_precision = Duration::decode(bytes)?;
        let max_batch_query_count = u16::decode(bytes)?;
        let min_batch_size = u32::decode(bytes)?;
        let var = match query_type {
            QUERY_TYPE_TIME_INTERVAL => Ok(QueryConfigVar::TimeInterval),
            QUERY_TYPE_FIXED_SIZE => Ok(QueryConfigVar::FixedSize {
                max_batch_size: u32::decode(bytes)?,
            }),
            _ => Err(CodecError::UnexpectedValue),
        }?;
        Ok(Self {
            time_precision,
            max_batch_query_count,
            min_batch_size,
            var,
        })
    }
}

/// A DAP task configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TaskConfig {
    pub task_info: Vec<u8>,
    pub leader_url: UrlBytes,
    pub helper_url: UrlBytes,
    pub query_config: QueryConfig,
    pub task_expiration: Time,
    pub vdaf_config: VdafConfig,
}

impl ParameterizedEncode<DapVersion> for TaskConfig {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        encode_u8_items(bytes, &(), &self.task_info);
        match version {
            DapVersion::Draft02 => encode_u16_items(
                bytes,
                &(),
                &[self.leader_url.clone(), self.helper_url.clone()],
            ),
            DapVersion::Draft07 => {
                self.leader_url.encode(bytes);
                self.helper_url.encode(bytes);
            }
        }
        self.query_config.encode_with_param(version, bytes);
        self.task_expiration.encode(bytes);
        self.vdaf_config.encode(bytes);
    }
}

impl ParameterizedDecode<DapVersion> for TaskConfig {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let task_info = decode_u8_items(&(), bytes)?;
        let [leader_url, helper_url] = match version {
            DapVersion::Draft02 => decode_u16_items(&(), bytes)?
                .try_into()
                .map_err(|_| CodecError::UnexpectedValue)?, // Expect exactly two Aggregator endpoints.
            DapVersion::Draft07 => [UrlBytes::decode(bytes)?, UrlBytes::decode(bytes)?],
        };

        Ok(TaskConfig {
            task_info,
            leader_url,
            helper_url,
            query_config: QueryConfig::decode_with_param(version, bytes)?,
            task_expiration: Time::decode(bytes)?,
            vdaf_config: VdafConfig::decode(bytes)?,
        })
    }
}
