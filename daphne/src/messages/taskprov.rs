// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Messages in the taskprov extension to the DAP protocol, as
//! defined in draft-wang-ppm-dap-taskprov-00.

use crate::messages::{
    decode_u16_bytes, encode_u16_bytes, Duration, Id, Time, QUERY_TYPE_FIXED_SIZE,
    QUERY_TYPE_TIME_INTERVAL,
};
use prio::codec::{
    decode_u16_items, decode_u24_items, decode_u8_items, encode_u16_items, encode_u24_items,
    encode_u8_items, CodecError, Decode, Encode,
};
use ring::{
    hmac::HMAC_SHA256,
    hmac::{sign, Key},
};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

// VDAF type codes.
const VDAF_TYPE_PRIO3_AES128_COUNT: u32 = 0x00000000;
const VDAF_TYPE_PRIO3_AES128_SUM: u32 = 0x00000001;
const VDAF_TYPE_PRIO3_AES128_HISTOGRAM: u32 = 0x00000002;
const VDAF_TYPE_POPLAR1_AES128: u32 = 0x00001000; // The gap from the previous constant is intentional

// Differential privacy mechanism types.
const DP_MECHANISM_RESERVED: u8 = 0x00;
const DP_MECHANISM_NONE: u8 = 0x01;

/// A VDAF type along with its type-specific data.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum VdafTypeVar {
    Prio3Aes128Count,
    Prio3Aes128Sum { bit_length: u8 },
    Prio3Aes128Histogram { buckets: Vec<u64> },
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
            VdafTypeVar::Prio3Aes128Histogram { buckets } => {
                VDAF_TYPE_PRIO3_AES128_HISTOGRAM.encode(bytes);
                encode_u24_items(bytes, &(), buckets);
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
                buckets: decode_u24_items(&(), bytes)?,
            }),
            VDAF_TYPE_POPLAR1_AES128 => Ok(Self::Poplar1Aes128 {
                bit_length: u16::decode(bytes)?,
            }),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// A differential privacy mechanism.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum DpMechanism {
    Reserved,
    None,
    NotImplemented(u8),
}

impl From<DpMechanism> for u8 {
    fn from(dp_mech: DpMechanism) -> Self {
        match dp_mech {
            DpMechanism::Reserved => DP_MECHANISM_RESERVED,
            DpMechanism::None => DP_MECHANISM_NONE,
            DpMechanism::NotImplemented(x) => x,
        }
    }
}

impl Encode for DpMechanism {
    fn encode(&self, bytes: &mut Vec<u8>) {
        u8::from(*self).encode(bytes);
    }
}

impl Decode for DpMechanism {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            x if x == DP_MECHANISM_RESERVED => Ok(Self::Reserved),
            x if x == DP_MECHANISM_NONE => Ok(Self::None),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// A differential privacy configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DpConfig {
    pub mechanism: DpMechanism,
}

impl Encode for DpConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.mechanism.encode(bytes);
    }
}

impl Decode for DpConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            mechanism: DpMechanism::decode(bytes)?,
        })
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
/// a Vec<u8>.
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

impl Encode for QueryConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match &self.var {
            QueryConfigVar::TimeInterval => {
                QUERY_TYPE_TIME_INTERVAL.encode(bytes);
            }
            QueryConfigVar::FixedSize { .. } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes);
            }
        }
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

impl Decode for QueryConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
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

impl TaskConfig {
    pub fn compute_task_id(&self) -> Id {
        // SHA-256 of "dap-taskprov-00"
        let task_prov_salt: Vec<u8> = vec![
            0x4d, 0x63, 0x1a, 0xeb, 0xa8, 0xdf, 0xe0, 0x1b, 0x34, 0x4c, 0x29, 0x2d, 0x17, 0xba,
            0x34, 0x9a, 0x78, 0x97, 0xbf, 0x64, 0x88, 0x00, 0x55, 0x1c, 0x0d, 0x75, 0x32, 0xab,
            0x61, 0x4b, 0xe2, 0x21,
        ];
        let key = Key::new(HMAC_SHA256, &task_prov_salt);
        let encoded = self.get_encoded();
        let digest = sign(&key, &encoded);
        let mut b: [u8; 32] = [0; 32];
        let d = digest.as_ref();
        b[..32].copy_from_slice(&d[..32]);
        Id(b)
    }
}

impl Encode for TaskConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u8_items(bytes, &(), &self.task_info);
        encode_u16_items(bytes, &(), &self.aggregator_endpoints);
        self.query_config.encode(bytes);
        self.task_expiration.encode(bytes);
        self.vdaf_config.encode(bytes);
    }
}

impl Decode for TaskConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(TaskConfig {
            task_info: decode_u8_items(&(), bytes)?,
            aggregator_endpoints: decode_u16_items(&(), bytes)?,
            query_config: QueryConfig::decode(bytes)?,
            task_expiration: Time::decode(bytes)?,
            vdaf_config: VdafConfig::decode(bytes)?,
        })
    }
}
