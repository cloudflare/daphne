// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! draft-wang-ppm-dap-taskprov: Messages for the taskrpov extension for DAP.

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
use std::io::Cursor;

use super::{decode_u16_prefixed, encode_u16_prefixed};

// VDAF type codes.
const VDAF_TYPE_PRIO2: u32 = 0xFFFF_0000;
pub(crate) const VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128: u32 = 0xFFFF_1003;

// Differential privacy mechanism types.
const DP_MECHANISM_NONE: u8 = 0x01;

/// A VDAF type along with its type-specific data.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum VdafTypeVar {
    Prio2 {
        dimension: u32,
    },
    Prio3SumVecField64MultiproofHmacSha256Aes128 {
        bits: u8,
        length: u32,
        chunk_length: u32,
        num_proofs: u8,
    },
    NotImplemented {
        typ: u32,
        param: Vec<u8>,
    },
}

impl ParameterizedEncode<DapVersion> for VdafTypeVar {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        match self {
            Self::Prio2 { dimension } => {
                VDAF_TYPE_PRIO2.encode(bytes);
                taskprov_encode_u16_prefixed(*version, bytes, |_version, inner| {
                    dimension.encode(inner);
                });
            }
            Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                bits,
                length,
                chunk_length,
                num_proofs,
            } => {
                VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128.encode(bytes);
                taskprov_encode_u16_prefixed(*version, bytes, |_version, inner| {
                    bits.encode(inner);
                    length.encode(inner);
                    chunk_length.encode(inner);
                    num_proofs.encode(inner);
                });
            }
            Self::NotImplemented { typ, param } => {
                typ.encode(bytes);
                taskprov_encode_u16_prefixed(*version, bytes, |_version, inner| {
                    inner.extend_from_slice(param);
                });
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
        match (version, vdaf_type) {
            (.., VDAF_TYPE_PRIO2) => {
                taskprov_decode_u16_prefixed(*version, bytes, |_version, inner| {
                    Ok(Self::Prio2 {
                        dimension: u32::decode(inner)?,
                    })
                })
            }
            (.., VDAF_TYPE_PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128) => {
                taskprov_decode_u16_prefixed(*version, bytes, |_version, inner| {
                    Ok(Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                        bits: u8::decode(inner)?,
                        length: u32::decode(inner)?,
                        chunk_length: u32::decode(inner)?,
                        num_proofs: u8::decode(inner)?,
                    })
                })
            }
            (DapVersion::DraftLatest, ..) => Ok(Self::NotImplemented {
                typ: vdaf_type,
                param: decode_u16_bytes(bytes)?,
            }),
            // draft02 compatibility: We don't recognize the VDAF type, which means the rest of
            // this message is not decodable. We must abort.
            (DapVersion::Draft02, ..) => Err(CodecError::UnexpectedValue),
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
                taskprov_encode_u16_prefixed(*version, bytes, |_, _| ());
            }

            Self::NotImplemented { typ, param } => {
                typ.encode(bytes);
                taskprov_encode_u16_prefixed(*version, bytes, |_version, inner| {
                    inner.extend_from_slice(param);
                });
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
        match (version, dp_mechanism) {
            (.., DP_MECHANISM_NONE) => {
                taskprov_decode_u16_prefixed::<()>(*version, bytes, |_version, inner| {
                    <()>::decode(inner)
                })?;
                Ok(Self::None)
            }
            (DapVersion::DraftLatest, ..) => Ok(Self::NotImplemented {
                typ: dp_mechanism,
                param: decode_u16_bytes(bytes)?,
            }),
            // draft02 compatibility: We must abort because unimplemented DP mechansims can't be
            // decoded.
            (DapVersion::Draft02, ..) => Err(CodecError::UnexpectedValue),
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
        if *version == DapVersion::DraftLatest {
            self.encode_query_type(bytes);
        }
        match &self.var {
            QueryConfigVar::TimeInterval => {
                taskprov_encode_u16_prefixed(*version, bytes, |_, _| ());
            }
            QueryConfigVar::FixedSize { max_batch_size } => {
                taskprov_encode_u16_prefixed(*version, bytes, |_version, inner| {
                    max_batch_size.encode(inner);
                });
            }
            QueryConfigVar::NotImplemented { typ: _, param } => {
                taskprov_encode_u16_prefixed(*version, bytes, |_version, inner| {
                    inner.extend_from_slice(param);
                });
            }
        }
    }
}

impl ParameterizedDecode<DapVersion> for QueryConfig {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let query_type = match version {
            DapVersion::DraftLatest => None,
            DapVersion::Draft02 => Some(Ok(u8::decode(bytes)?)),
        };
        let time_precision = Duration::decode(bytes)?;
        let max_batch_query_count = u16::decode(bytes)?;
        let min_batch_size = u32::decode(bytes)?;
        let query_type = query_type.unwrap_or_else(|| u8::decode(bytes))?;
        let var = match (version, query_type) {
            (.., QUERY_TYPE_TIME_INTERVAL) => {
                taskprov_decode_u16_prefixed::<()>(*version, bytes, |_version, inner| {
                    <()>::decode(inner)
                })?;
                QueryConfigVar::TimeInterval
            }
            (.., QUERY_TYPE_FIXED_SIZE) => {
                taskprov_decode_u16_prefixed(*version, bytes, |_version, inner| {
                    Ok(QueryConfigVar::FixedSize {
                        max_batch_size: u32::decode(inner)?,
                    })
                })?
            }
            (DapVersion::DraftLatest, ..) => QueryConfigVar::NotImplemented {
                typ: query_type,
                param: decode_u16_bytes(bytes)?,
            },
            // draft02 compatibility: We must abort because unimplemented query configurations
            // can't be decoded.
            (DapVersion::Draft02, ..) => return Err(CodecError::UnexpectedValue),
        };

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
            DapVersion::DraftLatest => {
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
            DapVersion::DraftLatest => [UrlBytes::decode(bytes)?, UrlBytes::decode(bytes)?],
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

fn taskprov_encode_u16_prefixed(
    version: DapVersion,
    bytes: &mut Vec<u8>,
    e: impl Fn(DapVersion, &mut Vec<u8>),
) {
    match version {
        DapVersion::DraftLatest => encode_u16_prefixed(version, bytes, e),
        // draft02 compatibility: No length prefix is used.
        DapVersion::Draft02 => e(version, bytes),
    }
}

fn taskprov_decode_u16_prefixed<O>(
    version: DapVersion,
    bytes: &mut Cursor<&[u8]>,
    d: impl Fn(DapVersion, &mut Cursor<&[u8]>) -> Result<O, CodecError>,
) -> Result<O, CodecError> {
    match version {
        DapVersion::DraftLatest => decode_u16_prefixed(version, bytes, d),
        // draft02 compatibility: No length prefix is used.
        DapVersion::Draft02 => d(version, bytes),
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
    fn roundtrip_query_config_not_implemented_draft09() {
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
                &DapVersion::DraftLatest,
                &query_config.get_encoded_with_param(&DapVersion::DraftLatest)
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
    fn roundtrip_dp_config_not_implemented_draft09() {
        let dp_config = DpConfig::NotImplemented {
            typ: 0,
            param: b"dp mechanism param".to_vec(),
        };
        assert_eq!(
            DpConfig::get_decoded_with_param(
                &DapVersion::DraftLatest,
                &dp_config.get_encoded_with_param(&DapVersion::DraftLatest)
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

    fn roundtrip_vdaf_config_prio2(version: DapVersion) {
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

    test_versions! { roundtrip_vdaf_config_prio2 }

    fn roundtrip_vdaf_config_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128(
        version: DapVersion,
    ) {
        let vdaf_config = VdafConfig {
            dp_config: DpConfig::None,
            var: VdafTypeVar::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                bits: 23,
                length: 1337,
                chunk_length: 42,
                num_proofs: 99,
            },
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

    test_versions! { roundtrip_vdaf_config_prio3_sum_vec_field64_multiproof_hmac_sha256_aes128 }

    #[test]
    fn roundtrip_vdaf_config_not_implemented_draft09() {
        let vdaf_config = VdafConfig {
            dp_config: DpConfig::None,
            var: VdafTypeVar::NotImplemented {
                typ: 1337,
                param: b"vdaf type param".to_vec(),
            },
        };

        assert_eq!(
            VdafConfig::get_decoded_with_param(
                &DapVersion::DraftLatest,
                &vdaf_config.get_encoded_with_param(&DapVersion::DraftLatest)
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
