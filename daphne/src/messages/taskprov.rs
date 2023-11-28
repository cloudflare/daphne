// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Messages in the taskprov extension to the DAP protocol, as
//! defined in draft-wang-ppm-dap-taskprov-02.

use crate::messages::{
    decode_u16_bytes, encode_u16_bytes, Duration, Time, QUERY_TYPE_FIXED_SIZE,
    QUERY_TYPE_TIME_INTERVAL,
};
use crate::DapVersion;
use prio::codec::{
    decode_u16_items, decode_u8_items, encode_u16_items, encode_u8_items, CodecError, Decode,
    Encode, ParameterizedDecode, ParameterizedEncode,
};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

// VDAF type codes.
const VDAF_TYPE_PRIO2: u32 = 0xFFFF_0000;

// Differential privacy mechanism types.
const DP_MECHANISM_NONE: u8 = 0x01;

/// A VDAF type along with its type-specific data.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum VdafTypeVar {
    Prio2 { dimension: u32 },
    NotImplemented { typ: u32, param: Vec<u8> },
}

impl ParameterizedEncode<DapVersion> for VdafTypeVar {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        match &self {
            Self::Prio2 { dimension } => {
                VDAF_TYPE_PRIO2.encode(bytes);
                if *version != DapVersion::Draft02 {
                    4_u16.encode(bytes);
                }
                dimension.encode(bytes);
            }
            Self::NotImplemented { typ, param } => {
                typ.encode(bytes);
                if *version != DapVersion::Draft02 {
                    u16::try_from(param.len()).unwrap().encode(bytes);
                }
                bytes.extend_from_slice(param);
            }
        }
    }
}

impl ParameterizedDecode<DapVersion> for VdafTypeVar {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let vdaf_type = u32::decode(bytes)?;
        let vdaf_type_param_len = match version {
            DapVersion::Draft07 => Some(u16::decode(bytes)?.try_into().unwrap()),
            DapVersion::Draft02 => None,
        };
        match (vdaf_type, vdaf_type_param_len) {
            (VDAF_TYPE_PRIO2, _) => Ok(Self::Prio2 {
                dimension: u32::decode(bytes)?,
            }),
            (_, Some(len)) => {
                let mut param = vec![0; len];
                bytes.read_exact(&mut param)?;
                Ok(Self::NotImplemented {
                    typ: vdaf_type,
                    param,
                })
            }
            // draft02 compatibility: We don't recognize the VDAF type, which means the rest of
            // this message is not decodable. We must abort.
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// A differential privacy mechanism.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum DpConfig {
    None,
    NotImplemented { typ: u8, param: Vec<u8> },
}

impl ParameterizedEncode<DapVersion> for DpConfig {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        match self {
            Self::None => {
                DP_MECHANISM_NONE.encode(bytes);
                if *version != DapVersion::Draft02 {
                    0_u16.encode(bytes);
                }
            }
            Self::NotImplemented { typ, param } => {
                typ.encode(bytes);
                if *version != DapVersion::Draft02 {
                    u16::try_from(param.len()).unwrap().encode(bytes);
                }
                bytes.extend_from_slice(param);
            }
        }
    }
}

impl ParameterizedDecode<DapVersion> for DpConfig {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let dp_mechanism = u8::decode(bytes)?;
        let dp_mechanism_param_len = match version {
            DapVersion::Draft07 => Some(u16::decode(bytes)?.try_into().unwrap()),
            DapVersion::Draft02 => None,
        };
        match (dp_mechanism, dp_mechanism_param_len) {
            (DP_MECHANISM_NONE, _) => Ok(Self::None),
            (_, Some(len)) => {
                let mut param = vec![0; len];
                bytes.read_exact(&mut param)?;
                Ok(Self::NotImplemented {
                    typ: dp_mechanism,
                    param,
                })
            }
            // draft02 compatibility: We must abort because unimplemented DP mechansims can't be
            // decoded.
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

impl ParameterizedEncode<DapVersion> for VdafConfig {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        self.dp_config.encode_with_param(version, bytes);
        self.var.encode_with_param(version, bytes);
    }
}

impl ParameterizedDecode<DapVersion> for VdafConfig {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            dp_config: DpConfig::decode_with_param(version, bytes)?,
            var: VdafTypeVar::decode_with_param(version, bytes)?,
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
    NotImplemented { typ: u8, param: Vec<u8> },
}

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
            QueryConfigVar::NotImplemented { typ, .. } => {
                typ.encode(bytes);
            }
        }
    }
}

impl ParameterizedEncode<DapVersion> for QueryConfig {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        if *version == DapVersion::Draft02 {
            self.encode_query_type(bytes);
        }
        self.time_precision.encode(bytes);
        self.max_batch_query_count.encode(bytes);
        self.min_batch_size.encode(bytes);
        match &self.var {
            QueryConfigVar::TimeInterval => {
                if *version == DapVersion::Draft07 {
                    QUERY_TYPE_TIME_INTERVAL.encode(bytes);
                    0_u16.encode(bytes);
                }
            }
            QueryConfigVar::FixedSize { max_batch_size } => {
                if *version == DapVersion::Draft07 {
                    QUERY_TYPE_FIXED_SIZE.encode(bytes);
                    4_u16.encode(bytes);
                }
                max_batch_size.encode(bytes);
            }
            QueryConfigVar::NotImplemented { typ, param } => {
                if *version == DapVersion::Draft07 {
                    typ.encode(bytes);
                    u16::try_from(param.len()).unwrap().encode(bytes);
                }
                bytes.extend_from_slice(param);
            }
        }
    }
}

impl ParameterizedDecode<DapVersion> for QueryConfig {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match version {
            DapVersion::Draft07 => {
                let time_precision = Duration::decode(bytes)?;
                let max_batch_query_count = u16::decode(bytes)?;
                let min_batch_size = u32::decode(bytes)?;
                let query_type = u8::decode(bytes)?;
                let query_type_param_len = u16::decode(bytes)?.try_into().unwrap();
                let var = match query_type {
                    QUERY_TYPE_TIME_INTERVAL => QueryConfigVar::TimeInterval,
                    QUERY_TYPE_FIXED_SIZE => QueryConfigVar::FixedSize {
                        max_batch_size: u32::decode(bytes)?,
                    },
                    _ => {
                        let mut query_type_param = vec![0; query_type_param_len];
                        bytes.read_exact(&mut query_type_param)?;
                        QueryConfigVar::NotImplemented {
                            typ: query_type,
                            param: query_type_param,
                        }
                    }
                };
                Ok(Self {
                    time_precision,
                    max_batch_query_count,
                    min_batch_size,
                    var,
                })
            }
            DapVersion::Draft02 => {
                let query_type = u8::decode(bytes)?;
                let time_precision = Duration::decode(bytes)?;
                let max_batch_query_count = u16::decode(bytes)?;
                let min_batch_size = u32::decode(bytes)?;
                let var = match query_type {
                    QUERY_TYPE_TIME_INTERVAL => QueryConfigVar::TimeInterval,
                    QUERY_TYPE_FIXED_SIZE => QueryConfigVar::FixedSize {
                        max_batch_size: u32::decode(bytes)?,
                    },
                    // draft02 compatibility: Unrecognized query types are not decodable, so we're
                    // forced to abort at this point.
                    _ => return Err(CodecError::UnexpectedValue),
                };
                Ok(Self {
                    time_precision,
                    max_batch_query_count,
                    min_batch_size,
                    var,
                })
            }
        }
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
        self.vdaf_config.encode_with_param(version, bytes);
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
            vdaf_config: VdafConfig::decode_with_param(version, bytes)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::test_versions;

    use super::*;

    fn roundtrip_query_config(version: DapVersion) {
        let query_config = QueryConfig {
            time_precision: 12_345_678,
            max_batch_query_count: 1337,
            min_batch_size: 12_345_678,
            var: QueryConfigVar::TimeInterval,
        };
        assert_eq!(
            QueryConfig::get_decoded_with_param(
                &version,
                &query_config.get_encoded_with_param(&version)
            )
            .unwrap(),
            query_config
        );

        let query_config = QueryConfig {
            time_precision: 12_345_678,
            max_batch_query_count: 1337,
            min_batch_size: 12_345_678,
            var: QueryConfigVar::FixedSize {
                max_batch_size: 12_345_678,
            },
        };
        assert_eq!(
            QueryConfig::get_decoded_with_param(
                &version,
                &query_config.get_encoded_with_param(&version)
            )
            .unwrap(),
            query_config
        );
    }

    test_versions! { roundtrip_query_config }

    #[test]
    fn roundtrip_query_config_not_implemented_draft07() {
        let query_config = QueryConfig {
            time_precision: 12_345_678,
            max_batch_query_count: 1337,
            min_batch_size: 12_345_678,
            var: QueryConfigVar::NotImplemented {
                typ: 0,
                param: b"query config param".to_vec(),
            },
        };
        assert_eq!(
            QueryConfig::get_decoded_with_param(
                &DapVersion::Draft07,
                &query_config.get_encoded_with_param(&DapVersion::Draft07)
            )
            .unwrap(),
            query_config
        );
    }

    #[test]
    fn roundtrip_query_config_not_implemented_draft02() {
        let query_config = QueryConfig {
            time_precision: 12_345_678,
            max_batch_query_count: 1337,
            min_batch_size: 12_345_678,
            var: QueryConfigVar::NotImplemented {
                typ: 0,
                param: b"query config param".to_vec(),
            },
        };

        // Expect error because unimplemented query types aren't decodable.
        assert!(QueryConfig::get_decoded_with_param(
            &DapVersion::Draft02,
            &query_config.get_encoded_with_param(&DapVersion::Draft02)
        )
        .is_err());
    }

    fn roundtrip_dp_config(version: DapVersion) {
        let dp_config = DpConfig::None;
        assert_eq!(
            DpConfig::get_decoded_with_param(&version, &dp_config.get_encoded_with_param(&version))
                .unwrap(),
            dp_config
        );
    }

    test_versions! { roundtrip_dp_config }

    #[test]
    fn roundtrip_dp_config_not_implemented_draft07() {
        let dp_config = DpConfig::NotImplemented {
            typ: 0,
            param: b"dp mechanism param".to_vec(),
        };
        assert_eq!(
            DpConfig::get_decoded_with_param(
                &DapVersion::Draft07,
                &dp_config.get_encoded_with_param(&DapVersion::Draft07)
            )
            .unwrap(),
            dp_config
        );
    }

    #[test]
    fn roundtrip_dp_config_not_implemented_draft02() {
        let dp_config = DpConfig::NotImplemented {
            typ: 0,
            param: b"dp mechanism param".to_vec(),
        };

        // Expect error because unimplemented query types aren't decodable.
        assert!(DpConfig::get_decoded_with_param(
            &DapVersion::Draft02,
            &dp_config.get_encoded_with_param(&DapVersion::Draft02)
        )
        .is_err());
    }

    fn roundtrip_vdaf_config(version: DapVersion) {
        let vdaf_config = VdafConfig {
            dp_config: DpConfig::None,
            var: VdafTypeVar::Prio2 { dimension: 1337 },
        };
        assert_eq!(
            VdafConfig::get_decoded_with_param(
                &version,
                &vdaf_config.get_encoded_with_param(&version)
            )
            .unwrap(),
            vdaf_config
        );
    }

    test_versions! { roundtrip_vdaf_config }

    #[test]
    fn roundtrip_vdaf_config_not_implemented_draft07() {
        let vdaf_config = VdafConfig {
            dp_config: DpConfig::None,
            var: VdafTypeVar::NotImplemented {
                typ: 1337,
                param: b"vdaf type param".to_vec(),
            },
        };

        assert_eq!(
            VdafConfig::get_decoded_with_param(
                &DapVersion::Draft07,
                &vdaf_config.get_encoded_with_param(&DapVersion::Draft07)
            )
            .unwrap(),
            vdaf_config
        );
    }

    #[test]
    fn roundtrip_vdaf_config_not_implemented_draft02() {
        let vdaf_config = VdafConfig {
            dp_config: DpConfig::None,
            var: VdafTypeVar::NotImplemented {
                typ: 1337,
                param: b"vdaf type param".to_vec(),
            },
        };

        // Expect error because unimplemented query types aren't decodable.
        assert!(VdafConfig::get_decoded_with_param(
            &DapVersion::Draft02,
            &vdaf_config.get_encoded_with_param(&DapVersion::Draft02)
        )
        .is_err());
    }
}
