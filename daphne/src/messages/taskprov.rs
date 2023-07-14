// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Messages in the taskprov extension to the DAP protocol, as
//! defined in draft-wang-ppm-dap-taskprov-02.

use crate::messages::{
    decode_u16_bytes, encode_u16_bytes, Duration, Time, QUERY_TYPE_FIXED_SIZE,
    QUERY_TYPE_TIME_INTERVAL,
};
use crate::taskprov::TaskprovVersion;
use prio::codec::{
    decode_u16_items, decode_u8_items, encode_u16_items, encode_u8_items, CodecError, Decode,
    Encode, ParameterizedDecode, ParameterizedEncode,
};
use ring::hkdf::KeyType;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

// VDAF type codes.
const VDAF_TYPE_PRIO3_AES128_COUNT: u32 = 0x00000000;
const VDAF_TYPE_PRIO3_AES128_SUM: u32 = 0x00000001;
const VDAF_TYPE_PRIO3_AES128_HISTOGRAM: u32 = 0x00000002;
const VDAF_TYPE_POPLAR1_AES128: u32 = 0x00001000; // The gap from the previous constant is intentional

// Differential privacy mechanism types.
const DP_MECHANISM_NONE: u8 = 0x01;

/// A VDAF type.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VdafType {
    Prio3Aes128Count,
    Prio3Aes128Sum,
    Prio3Aes128Histogram,
    Poplar1Aes128,
    NotImplemented(u32),
}

impl KeyType for VdafType {
    fn len(&self) -> usize {
        match self {
            VdafType::Prio3Aes128Count => 16,
            VdafType::Prio3Aes128Sum => 16,
            VdafType::Prio3Aes128Histogram => 16,
            VdafType::Poplar1Aes128 => 16,
            _ => panic!("tried to get key length for undefined VDAF"),
        }
    }
}

/// A VDAF type along with its type-specific data.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum VdafTypeVar {
    Prio3Aes128Count,
    Prio3Aes128Sum { bit_length: u8 },
    // NOTE: this doesn't comply with the TaskProv spec, which doesn't match the VDAF-06 spec.
    // Tracking the issue here: https://github.com/wangshan/draft-wang-ppm-dap-taskprov/issues/33.
    Prio3Aes128Histogram { len: u32 },
    Poplar1Aes128 { bit_length: u16 },
    NotImplemented(u32),
}

impl Encode for VdafTypeVar {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match &self {
            VdafTypeVar::Prio3Aes128Count => VDAF_TYPE_PRIO3_AES128_COUNT.encode(bytes),
            VdafTypeVar::Prio3Aes128Sum { bit_length } => {
                VDAF_TYPE_PRIO3_AES128_SUM.encode(bytes);
                bit_length.encode(bytes);
            }
            VdafTypeVar::Prio3Aes128Histogram { len } => {
                VDAF_TYPE_PRIO3_AES128_HISTOGRAM.encode(bytes);
                len.encode(bytes);
            }
            VdafTypeVar::Poplar1Aes128 { bit_length } => {
                VDAF_TYPE_POPLAR1_AES128.encode(bytes);
                bit_length.encode(bytes);
            }
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
            VDAF_TYPE_PRIO3_AES128_COUNT => Ok(Self::Prio3Aes128Count),
            VDAF_TYPE_PRIO3_AES128_SUM => Ok(Self::Prio3Aes128Sum {
                bit_length: u8::decode(bytes)?,
            }),
            VDAF_TYPE_PRIO3_AES128_HISTOGRAM => Ok(Self::Prio3Aes128Histogram {
                len: u32::decode(bytes)?,
            }),
            VDAF_TYPE_POPLAR1_AES128 => Ok(Self::Poplar1Aes128 {
                bit_length: u16::decode(bytes)?,
            }),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

impl From<VdafTypeVar> for VdafType {
    fn from(var: VdafTypeVar) -> Self {
        match var {
            VdafTypeVar::Prio3Aes128Count => VdafType::Prio3Aes128Count,
            VdafTypeVar::Prio3Aes128Histogram { .. } => VdafType::Prio3Aes128Histogram,
            VdafTypeVar::Prio3Aes128Sum { .. } => VdafType::Prio3Aes128Sum,
            VdafTypeVar::Poplar1Aes128 { .. } => VdafType::Poplar1Aes128,
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

/// A QueryConfig type and its associated task configuration data.
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

impl ParameterizedEncode<TaskprovVersion> for QueryConfig {
    fn encode_with_param(&self, _encoding_parameter: &TaskprovVersion, bytes: &mut Vec<u8>) {
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

impl ParameterizedDecode<TaskprovVersion> for QueryConfig {
    fn decode_with_param(
        _decoding_parameter: &TaskprovVersion,
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
    pub aggregator_endpoints: Vec<UrlBytes>,
    pub query_config: QueryConfig,
    pub task_expiration: Time,
    pub vdaf_config: VdafConfig,
}

impl ParameterizedEncode<TaskprovVersion> for TaskConfig {
    fn encode_with_param(&self, encoding_parameter: &TaskprovVersion, bytes: &mut Vec<u8>) {
        encode_u8_items(bytes, &(), &self.task_info);
        encode_u16_items(bytes, &(), &self.aggregator_endpoints);
        self.query_config
            .encode_with_param(encoding_parameter, bytes);
        self.task_expiration.encode(bytes);
        self.vdaf_config.encode(bytes);
    }
}

impl ParameterizedDecode<TaskprovVersion> for TaskConfig {
    fn decode_with_param(
        decoding_parameter: &TaskprovVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(TaskConfig {
            task_info: decode_u8_items(&(), bytes)?,
            aggregator_endpoints: decode_u16_items(&(), bytes)?,
            query_config: QueryConfig::decode_with_param(decoding_parameter, bytes)?,
            task_expiration: Time::decode(bytes)?,
            vdaf_config: VdafConfig::decode(bytes)?,
        })
    }
}
