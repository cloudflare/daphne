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
use std::io::{Cursor, Read};

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
        length: u32,
        bits: u8,
        chunk_length: u32,
        num_proofs: u8,
    },
    NotImplemented {
        typ: u32,
        param: Vec<u8>,
    },
}

impl ParameterizedEncode<DapVersion> for VdafTypeVar {
    fn encode_with_param(
        &self,
        _version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match self {
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
            Self::NotImplemented { typ, param } => {
                typ.encode(bytes)?;
                bytes.extend_from_slice(param);
            }
        };
        Ok(())
    }
}

impl ParameterizedDecode<(DapVersion, Option<usize>)> for VdafTypeVar {
    fn decode_with_param(
        (version, bytes_left): &(DapVersion, Option<usize>),
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let vdaf_type = u32::decode(bytes)?;
        match (version, bytes_left, vdaf_type) {
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
            (DapVersion::Draft09 | DapVersion::Latest, Some(bytes_left), ..) => {
                let mut param = vec![0; bytes_left - 4];
                bytes.read_exact(&mut param)?;
                Ok(Self::NotImplemented {
                    typ: vdaf_type,
                    param,
                })
            }
            // draft02 compatibility: We don't recognize the VDAF type, which means the rest of
            // this message is not decodable. We must abort.
            (DapVersion::Draft02, ..) | (DapVersion::Draft09 | DapVersion::Latest, None, ..) => {
                Err(CodecError::UnexpectedValue)
            }
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
        (version, bytes_left): &(DapVersion, Option<usize>),
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let dp_mechanism = u8::decode(bytes)?;
        match (version, bytes_left, dp_mechanism) {
            (.., DP_MECHANISM_NONE) => Ok(Self::None),
            (DapVersion::Draft09 | DapVersion::Latest, Some(bytes_left), ..) => {
                let mut param = vec![0; bytes_left - 1];
                bytes.read_exact(&mut param)?;
                Ok(Self::NotImplemented {
                    typ: dp_mechanism,
                    param,
                })
            }
            // draft02 compatibility: We must abort because unimplemented DP mechansims can't be
            // decoded.
            (DapVersion::Draft02, ..) | (DapVersion::Draft09 | DapVersion::Latest, None, ..) => {
                Err(CodecError::UnexpectedValue)
            }
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
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        taskprov_encode_u16_prefixed(*version, bytes, |_version, inner| {
            self.dp_config.encode(inner)
        })?;
        self.var.encode_with_param(version, bytes)?;
        Ok(())
    }
}

impl ParameterizedDecode<(DapVersion, Option<usize>)> for VdafConfig {
    fn decode_with_param(
        (version, bytes_left): &(DapVersion, Option<usize>),
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let prefix_start = bytes.position();
        let dp_config =
            taskprov_decode_u16_prefixed(*version, bytes, |version, inner, bytes_left| {
                // We need to know the length of the `DpConfig` in order to decode variants we don't
                // recognize.
                DpConfig::decode_with_param(&(version, bytes_left), inner)
            })?;
        let prefix_len = usize::try_from(bytes.position() - prefix_start)
            .map_err(|e| CodecError::Other(e.into()))?;
        let bytes_left = bytes_left.map(|l| l - prefix_len);
        Ok(Self {
            dp_config,
            var: VdafTypeVar::decode_with_param(&(*version, bytes_left), bytes)?,
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
    fn encode_query_type(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.var {
            QueryConfigVar::TimeInterval => {
                QUERY_TYPE_TIME_INTERVAL.encode(bytes)?;
            }
            QueryConfigVar::FixedSize { .. } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes)?;
            }
            QueryConfigVar::NotImplemented { typ, .. } => {
                typ.encode(bytes)?;
            }
        };
        Ok(())
    }
}

impl ParameterizedEncode<DapVersion> for QueryConfig {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        if *version == DapVersion::Draft02 {
            self.encode_query_type(bytes)?;
        }
        self.time_precision.encode(bytes)?;
        self.max_batch_query_count.encode(bytes)?;
        self.min_batch_size.encode(bytes)?;
        if matches!(version, DapVersion::Draft09 | DapVersion::Latest) {
            self.encode_query_type(bytes)?;
        }
        match &self.var {
            QueryConfigVar::TimeInterval => (),
            QueryConfigVar::FixedSize { max_batch_size } => {
                max_batch_size.encode(bytes)?;
            }
            QueryConfigVar::NotImplemented { typ: _, param } => {
                bytes.extend_from_slice(param);
            }
        };
        Ok(())
    }
}

impl ParameterizedDecode<(DapVersion, Option<usize>)> for QueryConfig {
    fn decode_with_param(
        (version, bytes_left): &(DapVersion, Option<usize>),
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let query_type = match version {
            DapVersion::Draft09 | DapVersion::Latest => None,
            DapVersion::Draft02 => Some(Ok(u8::decode(bytes)?)),
        };
        let time_precision = Duration::decode(bytes)?;
        let max_batch_query_count = u16::decode(bytes)?;
        let min_batch_size = u32::decode(bytes)?;
        let query_type = query_type.unwrap_or_else(|| u8::decode(bytes))?;
        let var = match (version, bytes_left, query_type) {
            (.., QUERY_TYPE_TIME_INTERVAL) => QueryConfigVar::TimeInterval,
            (.., QUERY_TYPE_FIXED_SIZE) => QueryConfigVar::FixedSize {
                max_batch_size: u32::decode(bytes)?,
            },
            (DapVersion::Draft09 | DapVersion::Latest, Some(bytes_left), ..) => {
                let mut param = vec![0; bytes_left - 15];
                bytes.read_exact(&mut param)?;

                QueryConfigVar::NotImplemented {
                    typ: query_type,
                    param,
                }
            }
            // draft02 compatibility: We must abort because unimplemented query configurations
            // can't be decoded.
            (DapVersion::Draft02, ..) | (DapVersion::Draft09 | DapVersion::Latest, None, ..) => {
                return Err(CodecError::UnexpectedValue)
            }
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
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        encode_u8_items(bytes, &(), &self.task_info)?;
        match version {
            DapVersion::Draft02 => encode_u16_items(
                bytes,
                &(),
                &[self.leader_url.clone(), self.helper_url.clone()],
            )?,
            DapVersion::Draft09 | DapVersion::Latest => {
                self.leader_url.encode(bytes)?;
                self.helper_url.encode(bytes)?;
            }
        }
        taskprov_encode_u16_prefixed(*version, bytes, |version, inner| {
            self.query_config.encode_with_param(&version, inner)
        })?;
        self.task_expiration.encode(bytes)?;
        taskprov_encode_u16_prefixed(*version, bytes, |version, inner| {
            self.vdaf_config.encode_with_param(&version, inner)
        })?;
        Ok(())
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
            DapVersion::Draft09 | DapVersion::Latest => {
                [UrlBytes::decode(bytes)?, UrlBytes::decode(bytes)?]
            }
        };
        let query_config = taskprov_decode_u16_prefixed(*version, bytes, |version, inner, len| {
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
            QueryConfig::decode_with_param(&(version, len), inner)
        })?;
        let task_expiration = Time::decode(bytes)?;
        let vdaf_config = taskprov_decode_u16_prefixed(*version, bytes, |version, inner, len| {
            VdafConfig::decode_with_param(&(version, len), inner)
        })?;

        Ok(TaskConfig {
            task_info,
            leader_url,
            helper_url,
            query_config,
            task_expiration,
            vdaf_config,
        })
    }
}

fn taskprov_encode_u16_prefixed(
    version: DapVersion,
    bytes: &mut Vec<u8>,
    e: impl Fn(DapVersion, &mut Vec<u8>) -> Result<(), CodecError>,
) -> Result<(), CodecError> {
    match version {
        DapVersion::Draft09 | DapVersion::Latest => encode_u16_prefixed(version, bytes, e),
        // draft02 compatibility: No length prefix is used.
        DapVersion::Draft02 => e(version, bytes),
    }
}

fn taskprov_decode_u16_prefixed<O>(
    version: DapVersion,
    bytes: &mut Cursor<&[u8]>,
    d: impl Fn(DapVersion, &mut Cursor<&[u8]>, Option<usize>) -> Result<O, CodecError>,
) -> Result<O, CodecError> {
    match version {
        DapVersion::Draft09 | DapVersion::Latest => decode_u16_prefixed(version, bytes, d),
        // draft02 compatibility: No length prefix is used.
        DapVersion::Draft02 => d(version, bytes, None),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_versions;

    use super::*;

    #[test]
    fn regression_task_config_draft02() {
        let want = TaskConfig {
            task_info: b"this is a cool task!".to_vec(),
            leader_url: UrlBytes {
                bytes: b"http://exmaple.com/v02".to_vec(),
            },
            helper_url: UrlBytes {
                bytes: b"https://someservice.cloudflareresearch.com".to_vec(),
            },
            query_config: QueryConfig {
                time_precision: 12_341_234,
                max_batch_query_count: 1337,
                min_batch_size: 55,
                var: QueryConfigVar::FixedSize { max_batch_size: 57 },
            },
            task_expiration: 23_232_232_232,
            vdaf_config: VdafConfig {
                dp_config: DpConfig::None,
                var: VdafTypeVar::Prio2 { dimension: 99_999 },
            },
        };

        let task_config_bytes = [
            20, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 99, 111, 111, 108, 32, 116, 97, 115,
            107, 33, 0, 68, 0, 22, 104, 116, 116, 112, 58, 47, 47, 101, 120, 109, 97, 112, 108,
            101, 46, 99, 111, 109, 47, 118, 48, 50, 0, 42, 104, 116, 116, 112, 115, 58, 47, 47,
            115, 111, 109, 101, 115, 101, 114, 118, 105, 99, 101, 46, 99, 108, 111, 117, 100, 102,
            108, 97, 114, 101, 114, 101, 115, 101, 97, 114, 99, 104, 46, 99, 111, 109, 2, 0, 0, 0,
            0, 0, 188, 79, 242, 5, 57, 0, 0, 0, 55, 0, 0, 0, 57, 0, 0, 0, 5, 104, 191, 187, 40, 1,
            255, 255, 0, 0, 0, 1, 134, 159,
        ];
        let got =
            TaskConfig::get_decoded_with_param(&DapVersion::Draft02, &task_config_bytes).unwrap();
        assert_eq!(got, want);
    }

    fn roundtrip_query_config(version: DapVersion) {
        let query_config = QueryConfig {
            time_precision: 12_345_678,
            max_batch_query_count: 1337,
            min_batch_size: 12_345_678,
            var: QueryConfigVar::TimeInterval,
        };
        let encoded = query_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            QueryConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
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
        let encoded = query_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            QueryConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
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
        let encoded = query_config
            .get_encoded_with_param(&DapVersion::Draft09)
            .unwrap();

        assert_eq!(
            QueryConfig::get_decoded_with_param(
                &(DapVersion::Draft09, Some(encoded.len())),
                &encoded,
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
            &(DapVersion::Draft02, None),
            &query_config
                .get_encoded_with_param(&DapVersion::Draft02)
                .unwrap()
        )
        .is_err());
    }

    fn roundtrip_dp_config(version: DapVersion) {
        let dp_config = DpConfig::None;
        let encoded = dp_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            DpConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
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
        let encoded = dp_config
            .get_encoded_with_param(&DapVersion::Draft09)
            .unwrap();

        assert_eq!(
            DpConfig::get_decoded_with_param(
                &(DapVersion::Draft09, Some(encoded.len())),
                &encoded,
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
            &(DapVersion::Draft02, None),
            &dp_config
                .get_encoded_with_param(&DapVersion::Draft02)
                .unwrap()
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
        let vdaf_config = VdafConfig {
            dp_config: DpConfig::None,
            var: VdafTypeVar::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                bits: 23,
                length: 1337,
                chunk_length: 42,
                num_proofs: 99,
            },
        };
        let encoded = vdaf_config.get_encoded_with_param(&version).unwrap();

        assert_eq!(
            VdafConfig::get_decoded_with_param(&(version, Some(encoded.len())), &encoded).unwrap(),
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
        let encoded = vdaf_config
            .get_encoded_with_param(&DapVersion::Draft09)
            .unwrap();

        assert_eq!(
            VdafConfig::get_decoded_with_param(
                &(DapVersion::Draft09, Some(encoded.len())),
                &encoded
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
        let encoded = vdaf_config
            .get_encoded_with_param(&DapVersion::Draft02)
            .unwrap();

        // Expect error because unimplemented query types aren't decodable.
        assert!(
            VdafConfig::get_decoded_with_param(&(DapVersion::Draft02, None), &encoded,).is_err()
        );
    }
}
