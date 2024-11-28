// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Messages in the DAP protocol.

pub mod request;
pub mod taskprov;

use crate::{
    hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId},
    DapVersion,
};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use hpke_rs::HpkePublicKey;
use prio::codec::{
    decode_u16_items, decode_u32_items, encode_u16_items, encode_u32_items, CodecError, Decode,
    Encode, ParameterizedDecode, ParameterizedEncode,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt,
    io::{Cursor, Read},
};

// Batch modes
const BATCH_MODE_TIME_INTERVAL: u8 = 0x01;
const BATCH_MODE_LEADER_SELECTED: u8 = 0x02;

// LeaderSelected batch submodes
// This is a slight misnomer, as these code points only exist in draft-09
// where "leader selected" batches were still called fixed size queries.
const LEADER_SELECTED_BATCH_MODE_BY_BATCH_ID: u8 = 0x00;
const LEADER_SELECTED_BATCH_MODE_CURRENT_BATCH: u8 = 0x01;

// Known extension types.
const EXTENSION_TASKPROV: u16 = 0xff00;

pub trait Base64Encode {
    /// Encode to URL-safe base64.
    fn to_base64url(&self) -> String;

    /// Decode from URL-safe, base64.
    fn try_from_base64url<T: AsRef<str>>(id_base64url: T) -> Option<Self>
    where
        Self: Sized;
}

// Serde doesn't support derivations from const generics properly, so we have to use a macro.
macro_rules! id_struct {
    ($sname:ident, $len:expr, $doc:expr) => {
        #[doc=$doc]
        #[derive(
            Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
        pub struct $sname(#[serde(with = "base64url_bytes")] pub [u8; $len]);

        impl $crate::messages::Base64Encode for $sname {
            /// Return the URL-safe, base64 encoding of the ID.
            fn to_base64url(&self) -> String {
                encode_base64url(self.0)
            }

            /// Decode from URL-safe, base64.
            fn try_from_base64url<T: AsRef<str>>(id_base64url: T) -> Option<Self> {
                Some($sname(decode_base64url(id_base64url.as_ref())?))
            }
        }

        impl Encode for $sname {
            fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
                bytes.extend_from_slice(&self.0);
                Ok(())
            }

            fn encoded_len(&self) -> Option<usize> {
                Some(self.0.len())
            }
        }

        impl Decode for $sname {
            fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
                let mut data = [0; $len];
                bytes.read_exact(&mut data[..])?;
                Ok($sname(data))
            }
        }

        impl AsRef<[u8]> for $sname {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsRef<[u8; $len]> for $sname {
            fn as_ref(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Display for $sname {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.to_base64url())
            }
        }

        impl fmt::Debug for $sname {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", ::std::stringify!($sname))
            }
        }
    };
}

id_struct!(AggregationJobId, 16, "Aggregation Job ID");
id_struct!(BatchId, 32, "Batch ID");
id_struct!(CollectionJobId, 16, "Collection Job ID");
id_struct!(ReportId, 16, "Report ID");
id_struct!(TaskId, 32, "Task ID");

/// module to serialize and deserialize types ids into base64
mod base64url_bytes {
    use serde::{de, ser};

    use crate::messages::decode_base64url;

    use super::encode_base64url;

    pub fn serialize<I, S>(id: &I, serializer: S) -> Result<S::Ok, S::Error>
    where
        I: AsRef<[u8]>,
        S: ser::Serializer,
    {
        serializer.serialize_str(&encode_base64url(id))
    }

    pub fn deserialize<'de, const N: usize, O, D>(deserializer: D) -> Result<O, D::Error>
    where
        D: de::Deserializer<'de>,
        D::Error: de::Error,
        O: From<[u8; N]>,
    {
        struct Visitor<const N: usize, O>(std::marker::PhantomData<[O; N]>);
        impl<const N: usize, O> de::Visitor<'_> for Visitor<N, O>
        where
            O: From<[u8; N]>,
        {
            type Value = O;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 encoded value")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                decode_base64url(v)
                    .map(|v| O::from(v))
                    .ok_or_else(|| E::custom("invalid base64"))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }
        }
        deserializer.deserialize_str(Visitor::<N, O>(std::marker::PhantomData))
    }
}

/// A duration in seconds.
pub type Duration = u64;

/// The timestamp sent in a [`Report`] in seconds.
pub type Time = u64;

/// Report extensions.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum Extension {
    Taskprov,
    NotImplemented { typ: u16, payload: Vec<u8> },
}

impl Extension {
    /// Return the type code associated with the extension
    pub(crate) fn type_code(&self) -> u16 {
        match self {
            Self::Taskprov { .. } => EXTENSION_TASKPROV,
            Self::NotImplemented { typ, .. } => *typ,
        }
    }
}

impl ParameterizedEncode<DapVersion> for Extension {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match self {
            Self::Taskprov => {
                EXTENSION_TASKPROV.encode(bytes)?;
                encode_u16_prefixed(*version, bytes, |_, _| Ok(()))?;
            }
            Self::NotImplemented { typ, payload } => {
                typ.encode(bytes)?;
                encode_u16_bytes(bytes, payload)?;
            }
        };
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for Extension {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let typ = u16::decode(bytes)?;
        match typ {
            EXTENSION_TASKPROV => {
                decode_u16_prefixed(*version, bytes, |_version, inner, _len| <()>::decode(inner))?;
                Ok(Self::Taskprov)
            }
            _ => Ok(Self::NotImplemented {
                typ,
                payload: decode_u16_bytes(bytes)?,
            }),
        }
    }
}

/// Report metadata.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct ReportMetadata {
    pub id: ReportId,
    pub time: Time,
}

impl ParameterizedEncode<DapVersion> for ReportMetadata {
    fn encode_with_param(
        &self,
        _version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.id.encode(bytes)?;
        self.time.encode(bytes)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for ReportMetadata {
    fn decode_with_param(
        _version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let metadata = Self {
            id: ReportId::decode(bytes)?,
            time: Time::decode(bytes)?,
        };

        Ok(metadata)
    }
}

/// A report generated by a client.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct Report {
    pub report_metadata: ReportMetadata,
    pub public_share: Vec<u8>,
    pub encrypted_input_shares: [HpkeCiphertext; 2],
}

impl ParameterizedEncode<DapVersion> for Report {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.report_metadata.encode_with_param(version, bytes)?;
        encode_u32_bytes(bytes, &self.public_share)?;
        self.encrypted_input_shares[0].encode(bytes)?;
        self.encrypted_input_shares[1].encode(bytes)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for Report {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            report_metadata: ReportMetadata::decode_with_param(version, bytes)?,
            public_share: decode_u32_bytes(bytes)?,
            encrypted_input_shares: [
                HpkeCiphertext::decode(bytes)?,
                HpkeCiphertext::decode(bytes)?,
            ],
        })
    }
}

/// An initial aggregate sub-request sent in an [`AggregationJobInitReq`]. The contents of this
/// structure pertain to a single report.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct ReportShare {
    pub report_metadata: ReportMetadata,
    pub public_share: Vec<u8>,
    pub encrypted_input_share: HpkeCiphertext,
}

impl ParameterizedEncode<DapVersion> for ReportShare {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.report_metadata.encode_with_param(version, bytes)?;
        encode_u32_bytes(bytes, &self.public_share)?;
        self.encrypted_input_share.encode(bytes)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for ReportShare {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            report_metadata: ReportMetadata::decode_with_param(version, bytes)?,
            public_share: decode_u32_bytes(bytes)?,
            encrypted_input_share: HpkeCiphertext::decode(bytes)?,
        })
    }
}

/// Batch parameter conveyed to the Helper by the Leader in the aggregation sub-protocol. Used to
/// identify which batch the reports in the [`AggregationJobInitReq`] are intended for.
#[derive(Clone, Debug, Eq, Deserialize, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum PartialBatchSelector {
    TimeInterval,
    LeaderSelectedByBatchId { batch_id: BatchId },
}

impl std::fmt::Display for PartialBatchSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeInterval => write!(f, "time_interval"),
            Self::LeaderSelectedByBatchId { .. } => write!(f, "leader_selected"),
        }
    }
}

impl From<BatchSelector> for PartialBatchSelector {
    fn from(batch_sel: BatchSelector) -> Self {
        match batch_sel {
            BatchSelector::TimeInterval { .. } => Self::TimeInterval,
            BatchSelector::LeaderSelectedByBatchId { batch_id } => {
                Self::LeaderSelectedByBatchId { batch_id }
            }
        }
    }
}

impl ParameterizedEncode<DapVersion> for PartialBatchSelector {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match version {
            DapVersion::Draft09 => {
                match self {
                    Self::TimeInterval => BATCH_MODE_TIME_INTERVAL.encode(bytes)?,
                    Self::LeaderSelectedByBatchId { batch_id } => {
                        BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                        batch_id.encode(bytes)?;
                    }
                };
                Ok(())
            }
            DapVersion::Latest => {
                match self {
                    Self::TimeInterval => {
                        BATCH_MODE_TIME_INTERVAL.encode(bytes)?;
                        encode_u16_bytes(bytes, &Vec::new())?;
                    }
                    Self::LeaderSelectedByBatchId { batch_id } => {
                        BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                        let config = &mut Vec::new();
                        batch_id.encode(config)?;
                        encode_u16_bytes(bytes, config)?;
                    }
                };
                Ok(())
            }
        }
    }
}

impl ParameterizedDecode<DapVersion> for PartialBatchSelector {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match version {
            DapVersion::Draft09 => match u8::decode(bytes)? {
                BATCH_MODE_TIME_INTERVAL => Ok(Self::TimeInterval),
                BATCH_MODE_LEADER_SELECTED => Ok(Self::LeaderSelectedByBatchId {
                    batch_id: BatchId::decode(bytes)?,
                }),
                _ => Err(CodecError::UnexpectedValue),
            },
            DapVersion::Latest => match u8::decode(bytes)? {
                BATCH_MODE_TIME_INTERVAL => {
                    let config = decode_u16_bytes(bytes)?;
                    if config.is_empty() {
                        Ok(Self::TimeInterval)
                    } else {
                        Err(CodecError::UnexpectedValue)
                    }
                }
                BATCH_MODE_LEADER_SELECTED => {
                    let config = decode_u16_bytes(bytes)?;
                    let batch_id = BatchId::decode(&mut Cursor::new(config.as_slice()))?;
                    Ok(Self::LeaderSelectedByBatchId { batch_id })
                }
                _ => Err(CodecError::UnexpectedValue),
            },
        }
    }
}

/// A batch selector issued by the Leader in an aggregate-share request.
#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum BatchSelector {
    TimeInterval { batch_interval: Interval },
    LeaderSelectedByBatchId { batch_id: BatchId },
}

impl std::fmt::Display for BatchSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeInterval { .. } => write!(f, "time_interval"),
            Self::LeaderSelectedByBatchId { batch_id } => {
                write!(
                    f,
                    "leader_selected_by_batch_id({})",
                    batch_id.to_base64url()
                )
            }
        }
    }
}

impl ParameterizedEncode<DapVersion> for BatchSelector {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match version {
            DapVersion::Draft09 => {
                match self {
                    Self::TimeInterval { batch_interval } => {
                        BATCH_MODE_TIME_INTERVAL.encode(bytes)?;
                        batch_interval.encode(bytes)?;
                    }
                    Self::LeaderSelectedByBatchId { batch_id } => {
                        BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                        batch_id.encode(bytes)?;
                    }
                };
                Ok(())
            }
            DapVersion::Latest => {
                match self {
                    Self::TimeInterval { batch_interval } => {
                        BATCH_MODE_TIME_INTERVAL.encode(bytes)?;
                        let config = &mut Vec::new();
                        batch_interval.encode(config)?;
                        encode_u16_bytes(bytes, config)?;
                    }
                    Self::LeaderSelectedByBatchId { batch_id } => {
                        BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                        let config = &mut Vec::new();
                        batch_id.encode(config)?;
                        encode_u16_bytes(bytes, config)?;
                    }
                };
                Ok(())
            }
        }
    }
}

impl ParameterizedDecode<DapVersion> for BatchSelector {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match version {
            DapVersion::Draft09 => match u8::decode(bytes)? {
                BATCH_MODE_TIME_INTERVAL => Ok(Self::TimeInterval {
                    batch_interval: Interval::decode(bytes)?,
                }),
                BATCH_MODE_LEADER_SELECTED => Ok(Self::LeaderSelectedByBatchId {
                    batch_id: BatchId::decode(bytes)?,
                }),
                _ => Err(CodecError::UnexpectedValue),
            },
            DapVersion::Latest => match u8::decode(bytes)? {
                BATCH_MODE_TIME_INTERVAL => {
                    let config = decode_u16_bytes(bytes)?;
                    Ok(Self::TimeInterval {
                        batch_interval: Interval::decode(&mut Cursor::new(config.as_slice()))?,
                    })
                }
                BATCH_MODE_LEADER_SELECTED => {
                    let config = decode_u16_bytes(bytes)?;
                    Ok(Self::LeaderSelectedByBatchId {
                        batch_id: BatchId::decode(&mut Cursor::new(config.as_slice()))?,
                    })
                }
                _ => Err(CodecError::UnexpectedValue),
            },
        }
    }
}
impl Default for BatchSelector {
    fn default() -> Self {
        Self::TimeInterval {
            batch_interval: Interval::default(),
        }
    }
}

/// The `PrepareInit` message consisting of the report share and the Leader's initial prep share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct PrepareInit {
    pub report_share: ReportShare,
    pub payload: Vec<u8>,
}

impl ParameterizedEncode<DapVersion> for PrepareInit {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.report_share.encode_with_param(version, bytes)?;
        encode_u32_bytes(bytes, &self.payload)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for PrepareInit {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let report_share = ReportShare::decode_with_param(version, bytes)?;
        let payload = decode_u32_bytes(bytes)?;

        Ok(Self {
            report_share,
            payload,
        })
    }
}

/// Aggregate initialization request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationJobInitReq {
    pub agg_param: Vec<u8>,
    pub part_batch_sel: PartialBatchSelector,
    pub prep_inits: Vec<PrepareInit>,
}

impl ParameterizedEncode<DapVersion> for AggregationJobInitReq {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        encode_u32_bytes(bytes, &self.agg_param)?;
        self.part_batch_sel.encode_with_param(version, bytes)?;
        encode_u32_items(bytes, version, &self.prep_inits)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for AggregationJobInitReq {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            agg_param: decode_u32_bytes(bytes)?,
            part_batch_sel: PartialBatchSelector::decode_with_param(version, bytes)?,
            prep_inits: decode_u32_items(version, bytes)?,
        })
    }
}

/// Transition message. This conveyes a message sent from one Aggregator to another during the
/// preparation phase of VDAF evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct Transition {
    pub report_id: ReportId,
    pub var: TransitionVar,
}

impl ParameterizedEncode<DapVersion> for Transition {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.report_id.encode(bytes)?;
        self.var.encode_with_param(version, bytes)?;
        Ok(())
    }
}
impl ParameterizedDecode<DapVersion> for Transition {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            report_id: ReportId::decode(bytes)?,
            var: TransitionVar::decode_with_param(version, bytes)?,
        })
    }
}

/// Transition message variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum TransitionVar {
    Continued(Vec<u8>),
    Failed(TransitionFailure),
}

impl ParameterizedEncode<DapVersion> for TransitionVar {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match self {
            TransitionVar::Continued(vdaf_message) => {
                0_u8.encode(bytes)?;
                encode_u32_bytes(bytes, vdaf_message)?;
            }
            TransitionVar::Failed(err) => {
                2_u8.encode(bytes)?;
                err.encode_with_param(version, bytes)?;
            }
        };
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for TransitionVar {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            0 => Ok(Self::Continued(decode_u32_bytes(bytes)?)),
            2 => Ok(Self::Failed(TransitionFailure::decode_with_param(
                version, bytes,
            )?)),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// Transition error.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, thiserror::Error, Hash)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum TransitionFailure {
    Reserved,
    BatchCollected,
    ReportReplayed,
    ReportDropped,
    HpkeUnknownConfigId,
    HpkeDecryptError,
    VdafPrepError,
    BatchSaturated,
    TaskExpired,
    InvalidMessage,
    ReportTooEarly,
    TaskNotStarted,
}

#[derive(Clone, Copy)]
enum TransitionFailureDraft09 {
    BatchCollected = 0,
    ReportReplayed = 1,
    ReportDropped = 2,
    HpkeUnknownConfigId = 3,
    HpkeDecryptError = 4,
    VdafPrepError = 5,
    BatchSaturated = 6,
    TaskExpired = 7,
    InvalidMessage = 8,
    ReportTooEarly = 9,
}

#[derive(Clone, Copy)]
enum TransitionFailureLatest {
    Reserved = 0,
    BatchCollected = 1,
    ReportReplayed = 2,
    ReportDropped = 3,
    HpkeUnknownConfigId = 4,
    HpkeDecryptError = 5,
    VdafPrepError = 6,
    TaskExpired = 7,
    InvalidMessage = 8,
    ReportTooEarly = 9,
    TaskNotStarted = 10,
}

impl TryFrom<u8> for TransitionFailureDraft09 {
    type Error = CodecError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            b if b == Self::BatchCollected as u8 => Ok(Self::BatchCollected),
            b if b == Self::ReportReplayed as u8 => Ok(Self::ReportReplayed),
            b if b == Self::ReportDropped as u8 => Ok(Self::ReportDropped),
            b if b == Self::HpkeUnknownConfigId as u8 => Ok(Self::HpkeUnknownConfigId),
            b if b == Self::HpkeDecryptError as u8 => Ok(Self::HpkeDecryptError),
            b if b == Self::VdafPrepError as u8 => Ok(Self::VdafPrepError),
            b if b == Self::BatchSaturated as u8 => Ok(Self::BatchSaturated),
            b if b == Self::TaskExpired as u8 => Ok(Self::TaskExpired),
            b if b == Self::InvalidMessage as u8 => Ok(Self::InvalidMessage),
            b if b == Self::ReportTooEarly as u8 => Ok(Self::ReportTooEarly),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

impl TryFrom<u8> for TransitionFailureLatest {
    type Error = CodecError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            b if b == Self::Reserved as u8 => Ok(Self::Reserved),
            b if b == Self::BatchCollected as u8 => Ok(Self::BatchCollected),
            b if b == Self::ReportReplayed as u8 => Ok(Self::ReportReplayed),
            b if b == Self::ReportDropped as u8 => Ok(Self::ReportDropped),
            b if b == Self::HpkeUnknownConfigId as u8 => Ok(Self::HpkeUnknownConfigId),
            b if b == Self::HpkeDecryptError as u8 => Ok(Self::HpkeDecryptError),
            b if b == Self::VdafPrepError as u8 => Ok(Self::VdafPrepError),
            b if b == Self::TaskExpired as u8 => Ok(Self::TaskExpired),
            b if b == Self::InvalidMessage as u8 => Ok(Self::InvalidMessage),
            b if b == Self::ReportTooEarly as u8 => Ok(Self::ReportTooEarly),
            b if b == Self::TaskNotStarted as u8 => Ok(Self::TaskNotStarted),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

impl TryFrom<TransitionFailureDraft09> for TransitionFailure {
    type Error = CodecError;

    fn try_from(v: TransitionFailureDraft09) -> Result<Self, Self::Error> {
        match v {
            TransitionFailureDraft09::BatchCollected => Ok(TransitionFailure::BatchCollected),
            TransitionFailureDraft09::ReportReplayed => Ok(TransitionFailure::ReportReplayed),
            TransitionFailureDraft09::ReportDropped => Ok(TransitionFailure::ReportDropped),
            TransitionFailureDraft09::HpkeUnknownConfigId => {
                Ok(TransitionFailure::HpkeUnknownConfigId)
            }
            TransitionFailureDraft09::HpkeDecryptError => Ok(TransitionFailure::HpkeDecryptError),
            TransitionFailureDraft09::VdafPrepError => Ok(TransitionFailure::VdafPrepError),
            TransitionFailureDraft09::BatchSaturated => Ok(TransitionFailure::BatchSaturated),
            TransitionFailureDraft09::TaskExpired => Ok(TransitionFailure::TaskExpired),
            TransitionFailureDraft09::InvalidMessage => Ok(TransitionFailure::InvalidMessage),
            TransitionFailureDraft09::ReportTooEarly => Ok(TransitionFailure::ReportTooEarly),
        }
    }
}

impl TryFrom<&TransitionFailure> for TransitionFailureDraft09 {
    type Error = CodecError;

    fn try_from(v: &TransitionFailure) -> Result<Self, Self::Error> {
        match v {
            TransitionFailure::BatchCollected => Ok(TransitionFailureDraft09::BatchCollected),
            TransitionFailure::ReportReplayed => Ok(TransitionFailureDraft09::ReportReplayed),
            TransitionFailure::ReportDropped => Ok(TransitionFailureDraft09::ReportDropped),
            TransitionFailure::HpkeUnknownConfigId => {
                Ok(TransitionFailureDraft09::HpkeUnknownConfigId)
            }
            TransitionFailure::HpkeDecryptError => Ok(TransitionFailureDraft09::HpkeDecryptError),
            TransitionFailure::VdafPrepError => Ok(TransitionFailureDraft09::VdafPrepError),
            TransitionFailure::BatchSaturated => Ok(TransitionFailureDraft09::BatchSaturated),
            TransitionFailure::TaskExpired => Ok(TransitionFailureDraft09::TaskExpired),
            TransitionFailure::InvalidMessage => Ok(TransitionFailureDraft09::InvalidMessage),
            TransitionFailure::ReportTooEarly => Ok(TransitionFailureDraft09::ReportTooEarly),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

impl TryFrom<TransitionFailureLatest> for TransitionFailure {
    type Error = CodecError;

    fn try_from(v: TransitionFailureLatest) -> Result<Self, Self::Error> {
        match v {
            TransitionFailureLatest::Reserved => Ok(TransitionFailure::Reserved),
            TransitionFailureLatest::BatchCollected => Ok(TransitionFailure::BatchCollected),
            TransitionFailureLatest::ReportReplayed => Ok(TransitionFailure::ReportReplayed),
            TransitionFailureLatest::ReportDropped => Ok(TransitionFailure::ReportDropped),
            TransitionFailureLatest::HpkeUnknownConfigId => {
                Ok(TransitionFailure::HpkeUnknownConfigId)
            }
            TransitionFailureLatest::HpkeDecryptError => Ok(TransitionFailure::HpkeDecryptError),
            TransitionFailureLatest::VdafPrepError => Ok(TransitionFailure::VdafPrepError),
            TransitionFailureLatest::TaskExpired => Ok(TransitionFailure::TaskExpired),
            TransitionFailureLatest::InvalidMessage => Ok(TransitionFailure::InvalidMessage),
            TransitionFailureLatest::ReportTooEarly => Ok(TransitionFailure::ReportTooEarly),
            TransitionFailureLatest::TaskNotStarted => Ok(TransitionFailure::TaskNotStarted),
        }
    }
}

#[expect(clippy::match_wildcard_for_single_variants)]
impl TryFrom<&TransitionFailure> for TransitionFailureLatest {
    type Error = CodecError;

    fn try_from(v: &TransitionFailure) -> Result<Self, Self::Error> {
        match v {
            TransitionFailure::Reserved => Ok(TransitionFailureLatest::Reserved),
            TransitionFailure::BatchCollected => Ok(TransitionFailureLatest::BatchCollected),
            TransitionFailure::ReportReplayed => Ok(TransitionFailureLatest::ReportReplayed),
            TransitionFailure::ReportDropped => Ok(TransitionFailureLatest::ReportDropped),
            TransitionFailure::HpkeUnknownConfigId => {
                Ok(TransitionFailureLatest::HpkeUnknownConfigId)
            }
            TransitionFailure::HpkeDecryptError => Ok(TransitionFailureLatest::HpkeDecryptError),
            TransitionFailure::VdafPrepError => Ok(TransitionFailureLatest::VdafPrepError),
            TransitionFailure::TaskExpired => Ok(TransitionFailureLatest::TaskExpired),
            TransitionFailure::InvalidMessage => Ok(TransitionFailureLatest::InvalidMessage),
            TransitionFailure::ReportTooEarly => Ok(TransitionFailureLatest::ReportTooEarly),
            TransitionFailure::TaskNotStarted => Ok(TransitionFailureLatest::TaskNotStarted),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

impl Encode for TransitionFailureDraft09 {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(bytes)
    }
}

impl Encode for TransitionFailureLatest {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(bytes)
    }
}

impl ParameterizedEncode<DapVersion> for TransitionFailure {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match version {
            DapVersion::Draft09 => {
                TransitionFailureDraft09::try_from(self)?.encode(bytes)?;
                Ok(())
            }
            DapVersion::Latest => {
                TransitionFailureLatest::try_from(self)?.encode(bytes)?;
                Ok(())
            }
        }
    }
}

impl Decode for TransitionFailureDraft09 {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        u8::decode(bytes)?.try_into()
    }
}

impl Decode for TransitionFailureLatest {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        u8::decode(bytes)?.try_into()
    }
}

impl ParameterizedDecode<DapVersion> for TransitionFailure {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match version {
            DapVersion::Draft09 => TransitionFailureDraft09::decode(bytes)?.try_into(),
            DapVersion::Latest => TransitionFailureLatest::decode(bytes)?.try_into(),
        }
    }
}

impl std::fmt::Display for TransitionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Reserved => write!(f, "reserved"),
            Self::BatchCollected => write!(f, "batch_collected"),
            Self::ReportReplayed => write!(f, "report_replayed"),
            Self::ReportDropped => write!(f, "report_dropped"),
            Self::HpkeUnknownConfigId => write!(f, "hpke_unknown_config_id"),
            Self::HpkeDecryptError => write!(f, "hpke_decrypt_error"),
            Self::VdafPrepError => write!(f, "vdaf_prep_error"),
            Self::BatchSaturated => write!(f, "batch_saturated"),
            Self::TaskExpired => write!(f, "task_expired"),
            Self::InvalidMessage => write!(f, "invalid_message"),
            Self::ReportTooEarly => write!(f, "report_too_early"),
            Self::TaskNotStarted => write!(f, "task_not_started"),
        }
    }
}

/// An aggregate response sent from the Helper to the Leader.
#[derive(Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AggregationJobResp {
    pub transitions: Vec<Transition>,
}

impl ParameterizedEncode<DapVersion> for AggregationJobResp {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        encode_u32_items(bytes, version, &self.transitions)
    }
}

impl ParameterizedDecode<DapVersion> for AggregationJobResp {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            transitions: decode_u32_items(version, bytes)?,
        })
    }
}

/// A batch interval.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct Interval {
    pub start: Time,
    pub duration: Duration,
}

impl Interval {
    /// Return the end of the interval, i.e., `self.start + self.duration`.
    pub fn end(&self) -> Time {
        self.start + self.duration
    }
}

impl Encode for Interval {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.start.encode(bytes)?;
        self.duration.encode(bytes)?;
        Ok(())
    }
}

impl Decode for Interval {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            start: Time::decode(bytes)?,
            duration: Duration::decode(bytes)?,
        })
    }
}

/// A query issued by the Collector in a collect request.
#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum Query {
    TimeInterval { batch_interval: Interval },
    LeaderSelectedByBatchId { batch_id: BatchId },
    LeaderSelectedCurrentBatch,
}

impl Query {
    pub(crate) fn into_batch_sel(self) -> Option<BatchSelector> {
        match self {
            Self::TimeInterval { batch_interval } => {
                Some(BatchSelector::TimeInterval { batch_interval })
            }
            Self::LeaderSelectedByBatchId { batch_id } => {
                Some(BatchSelector::LeaderSelectedByBatchId { batch_id })
            }
            Self::LeaderSelectedCurrentBatch => None,
        }
    }
}

impl From<BatchSelector> for Query {
    fn from(batch_sel: BatchSelector) -> Self {
        match batch_sel {
            BatchSelector::TimeInterval { batch_interval } => Self::TimeInterval { batch_interval },
            BatchSelector::LeaderSelectedByBatchId { batch_id } => {
                Self::LeaderSelectedByBatchId { batch_id }
            }
        }
    }
}

impl std::fmt::Display for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeInterval { .. } => write!(f, "time_interval"),
            Self::LeaderSelectedByBatchId { batch_id } => {
                write!(
                    f,
                    "leader_selected_by_batch_id({})",
                    batch_id.to_base64url()
                )
            }
            Self::LeaderSelectedCurrentBatch => write!(f, "leader_selected_current_batch"),
        }
    }
}

impl ParameterizedEncode<DapVersion> for Query {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match version {
            DapVersion::Draft09 => {
                match self {
                    Self::TimeInterval { batch_interval } => {
                        BATCH_MODE_TIME_INTERVAL.encode(bytes)?;
                        batch_interval.encode(bytes)?;
                    }
                    Self::LeaderSelectedByBatchId { batch_id } => {
                        BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                        LEADER_SELECTED_BATCH_MODE_BY_BATCH_ID.encode(bytes)?;
                        batch_id.encode(bytes)?;
                    }
                    Self::LeaderSelectedCurrentBatch => {
                        BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                        LEADER_SELECTED_BATCH_MODE_CURRENT_BATCH.encode(bytes)?;
                    }
                };
            }
            DapVersion::Latest => match self {
                Self::TimeInterval { batch_interval } => {
                    BATCH_MODE_TIME_INTERVAL.encode(bytes)?;
                    let config = &mut Vec::new();
                    batch_interval.encode(config)?;
                    encode_u16_bytes(bytes, config)?;
                }
                Self::LeaderSelectedByBatchId { batch_id: _ } => {
                    return Err(CodecError::UnexpectedValue)
                }
                Self::LeaderSelectedCurrentBatch => {
                    BATCH_MODE_LEADER_SELECTED.encode(bytes)?;
                    let config = &mut Vec::new();
                    encode_u16_bytes(bytes, config)?;
                }
            },
        }
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for Query {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match version {
            DapVersion::Draft09 => match u8::decode(bytes)? {
                BATCH_MODE_TIME_INTERVAL => Ok(Self::TimeInterval {
                    batch_interval: Interval::decode(bytes)?,
                }),
                BATCH_MODE_LEADER_SELECTED => {
                    let subtype = u8::decode(bytes)?;
                    match subtype {
                        LEADER_SELECTED_BATCH_MODE_BY_BATCH_ID => {
                            Ok(Self::LeaderSelectedByBatchId {
                                batch_id: BatchId::decode(bytes)?,
                            })
                        }
                        LEADER_SELECTED_BATCH_MODE_CURRENT_BATCH => {
                            Ok(Self::LeaderSelectedCurrentBatch)
                        }
                        _ => Err(CodecError::UnexpectedValue),
                    }
                }
                _ => Err(CodecError::UnexpectedValue),
            },
            DapVersion::Latest => match u8::decode(bytes)? {
                BATCH_MODE_TIME_INTERVAL => {
                    let config = decode_u16_bytes(bytes)?;
                    Ok(Self::TimeInterval {
                        batch_interval: Interval::decode(&mut Cursor::new(config.as_slice()))?,
                    })
                }
                BATCH_MODE_LEADER_SELECTED => {
                    let config = decode_u16_bytes(bytes)?;
                    if !config.is_empty() {
                        Err(CodecError::UnexpectedValue)
                    } else {
                        Ok(Self::LeaderSelectedCurrentBatch)
                    }
                }
                _ => Err(CodecError::UnexpectedValue),
            },
        }
    }
}

impl Default for Query {
    fn default() -> Self {
        Self::TimeInterval {
            batch_interval: Interval::default(),
        }
    }
}

/// A collect request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct CollectionReq {
    pub query: Query,
    pub agg_param: Vec<u8>,
}

impl ParameterizedEncode<DapVersion> for CollectionReq {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.query.encode_with_param(version, bytes)?;
        encode_u32_bytes(bytes, &self.agg_param)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for CollectionReq {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            query: Query::decode_with_param(version, bytes)?,
            agg_param: decode_u32_bytes(bytes)?,
        })
    }
}

/// A collect response.
//
// TODO Add serialization tests.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct Collection {
    pub part_batch_sel: PartialBatchSelector,
    pub report_count: u64,
    pub interval: Interval,
    pub encrypted_agg_shares: [HpkeCiphertext; 2],
}

impl ParameterizedEncode<DapVersion> for Collection {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.part_batch_sel.encode_with_param(version, bytes)?;
        self.report_count.encode(bytes)?;
        self.interval.encode(bytes)?;
        self.encrypted_agg_shares[0].encode(bytes)?;
        self.encrypted_agg_shares[1].encode(bytes)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for Collection {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let part_batch_sel = PartialBatchSelector::decode_with_param(version, bytes)?;
        let report_count = u64::decode(bytes)?;
        let interval = Interval::decode(bytes)?;
        let encrypted_agg_shares = [
            HpkeCiphertext::decode(bytes)?,
            HpkeCiphertext::decode(bytes)?,
        ];

        Ok(Self {
            part_batch_sel,
            report_count,
            interval,
            encrypted_agg_shares,
        })
    }
}

/// An aggregate-share request.
//
// TODO Add serialization tests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateShareReq {
    pub batch_sel: BatchSelector,
    pub agg_param: Vec<u8>,
    pub report_count: u64,
    pub checksum: [u8; 32],
}

impl ParameterizedEncode<DapVersion> for AggregateShareReq {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.batch_sel.encode_with_param(version, bytes)?;
        encode_u32_bytes(bytes, &self.agg_param)?;
        self.report_count.encode(bytes)?;
        bytes.extend_from_slice(&self.checksum);
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for AggregateShareReq {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let batch_sel = BatchSelector::decode_with_param(version, bytes)?;
        let agg_param = decode_u32_bytes(bytes)?;
        Ok(Self {
            batch_sel,
            agg_param,
            report_count: u64::decode(bytes)?,
            checksum: {
                let mut checksum = [0u8; 32];
                bytes.read_exact(&mut checksum[..])?;
                checksum
            },
        })
    }
}

/// An aggregate-share response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AggregateShare {
    pub encrypted_agg_share: HpkeCiphertext,
}

impl Encode for AggregateShare {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.encrypted_agg_share.encode(bytes)
    }
}

impl Decode for AggregateShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            encrypted_agg_share: HpkeCiphertext::decode(bytes)?,
        })
    }
}

/// A list of HPKE public key configurations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HpkeConfigList {
    pub hpke_configs: Vec<HpkeConfig>,
}

impl Encode for HpkeKemId {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(*self).encode(bytes)
    }
}

impl Decode for HpkeKemId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(u16::decode(bytes)?.into())
    }
}

impl Encode for HpkeKdfId {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(*self).encode(bytes)
    }
}

impl Decode for HpkeKdfId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(u16::decode(bytes)?.into())
    }
}

impl Encode for HpkeAeadId {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(*self).encode(bytes)
    }
}

impl Decode for HpkeAeadId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(u16::decode(bytes)?.into())
    }
}

impl Encode for HpkeConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.id.encode(bytes)?;
        self.kem_id.encode(bytes)?;
        self.kdf_id.encode(bytes)?;
        self.aead_id.encode(bytes)?;
        encode_u16_bytes(bytes, self.public_key.as_slice())?;
        Ok(())
    }
}

impl Decode for HpkeConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            id: u8::decode(bytes)?,
            kem_id: HpkeKemId::decode(bytes)?,
            kdf_id: HpkeKdfId::decode(bytes)?,
            aead_id: HpkeAeadId::decode(bytes)?,
            public_key: HpkePublicKey::from(decode_u16_bytes(bytes)?),
        })
    }
}

impl Encode for HpkeConfigList {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_u16_items(bytes, &(), &self.hpke_configs)
    }
}

impl Decode for HpkeConfigList {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            hpke_configs: decode_u16_items(&(), bytes)?,
        })
    }
}

/// An HPKE ciphertext. In the DAP protocol, input shares and aggregate shares are encrypted to the
/// intended recipient.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct HpkeCiphertext {
    pub config_id: u8,
    #[serde(with = "hex")]
    pub enc: Vec<u8>,
    #[serde(with = "hex")]
    pub payload: Vec<u8>,
}

impl Encode for HpkeCiphertext {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.config_id.encode(bytes)?;
        encode_u16_bytes(bytes, &self.enc)?;
        encode_u32_bytes(bytes, &self.payload)?;
        Ok(())
    }
}

impl Decode for HpkeCiphertext {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            config_id: u8::decode(bytes)?,
            enc: decode_u16_bytes(bytes)?,
            payload: decode_u32_bytes(bytes)?,
        })
    }
}

/// A plaintext input share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaintextInputShare {
    pub extensions: Vec<Extension>,
    pub payload: Vec<u8>,
}

impl ParameterizedEncode<DapVersion> for PlaintextInputShare {
    fn encode_with_param(
        &self,
        version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        encode_u16_items(bytes, version, &self.extensions)?;
        encode_u32_bytes(bytes, &self.payload)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for PlaintextInputShare {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            extensions: decode_u16_items(version, bytes)?,
            payload: decode_u32_bytes(bytes)?,
        })
    }
}

// NOTE ring provides a similar function, but as of version 0.16.20, it doesn't compile to
// wasm32-unknown-unknown.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut r = 0;
    for (x, y) in left.iter().zip(right) {
        r |= x ^ y;
    }
    r == 0
}

pub(crate) fn encode_u16_bytes(bytes: &mut Vec<u8>, input: &[u8]) -> Result<(), CodecError> {
    u16::try_from(input.len())
        .map_err(|_| CodecError::LengthPrefixTooBig(input.len()))?
        .encode(bytes)?;
    bytes.extend_from_slice(input);
    Ok(())
}

pub(crate) fn decode_u16_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Vec<u8>, CodecError> {
    let len = u16::decode(bytes)? as usize;
    let mut out = vec![0; len];
    bytes.read_exact(&mut out)?;
    Ok(out)
}

pub(crate) fn encode_u32_bytes(bytes: &mut Vec<u8>, input: &[u8]) -> Result<(), CodecError> {
    u32::try_from(input.len())
        .map_err(|_| CodecError::LengthPrefixTooBig(input.len()))?
        .encode(bytes)?;
    bytes.extend_from_slice(input);
    Ok(())
}

pub(crate) fn decode_u32_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Vec<u8>, CodecError> {
    let len = u32::decode(bytes)? as usize;
    let mut out = vec![0; len];
    bytes.read_exact(&mut out)?;
    Ok(out)
}

/// Encode the input bytes as a URL-safe, base64 string.
pub fn encode_base64url<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Decode the input as a URL-safe, base64 encoding of an `OUT_LEN`-length byte string.
pub fn decode_base64url<T: AsRef<[u8]>, const OUT_LEN: usize>(input: T) -> Option<[u8; OUT_LEN]> {
    let mut bytes = [0; OUT_LEN];
    // NOTE(cjpatton) It would be better to use `decode_slice` here, but this function uses a
    // conservative estimate of the decoded length (`decoded_len_estimate`). See
    // https://github.com/marshallpierce/rust-base64/issues/210.
    let vec = URL_SAFE_NO_PAD.decode(input).ok()?;
    if vec.len() != OUT_LEN {
        return None;
    };
    bytes.copy_from_slice(vec.as_ref());
    Some(bytes)
}

/// Decode the input as a URL-safe, base64 encoding of a byte string of any length.
pub fn decode_base64url_vec<T: AsRef<[u8]>>(input: T) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(input).ok()
}

macro_rules! make_encode_len_prefixed {
    ($type:ident, $name:ident) => {
        pub(crate) fn $name(
            version: DapVersion,
            bytes: &mut Vec<u8>,
            e: impl Fn(DapVersion, &mut Vec<u8>) -> Result<(), CodecError>,
        ) -> Result<(), CodecError> {
            // Reserve space for the length prefix.
            let len_offset = bytes.len();
            (0 as $type).encode(bytes)?;

            e(version, bytes)?;
            let len_bytes = std::mem::size_of::<$type>();
            let len = bytes.len() - len_offset - len_bytes;
            bytes[len_offset..len_offset + len_bytes]
                .copy_from_slice(&$type::to_be_bytes(len.try_into().unwrap()));
            Ok(())
        }
    };
}

make_encode_len_prefixed!(u16, encode_u16_prefixed);
make_encode_len_prefixed!(u32, encode_u32_prefixed);

// Cribbed from `decode_u16_items()` from libprio.
fn decode_u16_prefixed<O>(
    version: DapVersion,
    bytes: &mut Cursor<&[u8]>,
    d: impl Fn(DapVersion, &mut Cursor<&[u8]>, Option<usize>) -> Result<O, CodecError>,
) -> Result<O, CodecError> {
    // Read the length prefix.
    let len = usize::from(u16::decode(bytes)?);

    let item_start = usize::try_from(bytes.position()).unwrap();

    // Make sure encoded length doesn't overflow usize or go past the end of provided byte buffer.
    let item_end = item_start
        .checked_add(len)
        .ok_or_else(|| CodecError::LengthPrefixTooBig(len))?;

    let mut inner = Cursor::new(&bytes.get_ref()[item_start..item_end]);
    let decoded = d(version, &mut inner, Some(len))?;

    let num_bytes_left_over = item_end - item_start - usize::try_from(inner.position()).unwrap();
    if num_bytes_left_over > 0 {
        return Err(CodecError::BytesLeftOver(num_bytes_left_over));
    }

    // Advance outer cursor by the amount read in the inner cursor.
    bytes.set_position(item_end.try_into().unwrap());

    Ok(decoded)
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::test_versions;
    use hpke_rs::HpkePublicKey;
    use prio::codec::{Decode, ParameterizedDecode, ParameterizedEncode};
    use rand::prelude::*;

    fn read_report(version: DapVersion) {
        let report = Report {
            report_metadata: ReportMetadata {
                id: ReportId([23; 16]),
                time: 1_637_364_244,
            },
            public_share: b"public share".to_vec(),
            encrypted_input_shares: [
                HpkeCiphertext {
                    config_id: 23,
                    enc: b"leader encapsulated key".to_vec(),
                    payload: b"leader ciphertext".to_vec(),
                },
                HpkeCiphertext {
                    config_id: 119,
                    enc: b"helper encapsulated key".to_vec(),
                    payload: b"helper ciphertext".to_vec(),
                },
            ],
        };
        assert_eq!(
            Report::get_decoded_with_param(
                &version,
                &report.get_encoded_with_param(&version).unwrap()
            )
            .unwrap(),
            report
        );
    }

    test_versions! {read_report}

    fn partial_batch_selector_encode_decode(version: DapVersion) {
        const TEST_DATA_DRAFT09: &[u8] = &[1];
        const TEST_DATA_LATEST: &[u8] = &[1, 0, 0];

        let test_data = match version {
            DapVersion::Draft09 => TEST_DATA_DRAFT09,
            DapVersion::Latest => TEST_DATA_LATEST,
        };

        let pbs = PartialBatchSelector::TimeInterval;
        let bytes = &mut Vec::new();

        pbs.encode_with_param(&version, bytes).unwrap();
        assert_eq!(bytes, test_data);

        let npbs =
            PartialBatchSelector::decode_with_param(&version, &mut Cursor::new(test_data)).unwrap();
        assert_eq!(npbs, pbs);
    }

    test_versions! {partial_batch_selector_encode_decode}

    fn batch_selector_encode_decode(version: DapVersion) {
        const TEST_DATA_DRAFT09: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 3, 232, 0, 0, 0, 0, 0, 0, 0, 5];
        const TEST_DATA_LATEST: &[u8] =
            &[1, 0, 16, 0, 0, 0, 0, 0, 0, 3, 232, 0, 0, 0, 0, 0, 0, 0, 5];

        let test_data = match version {
            DapVersion::Draft09 => TEST_DATA_DRAFT09,
            DapVersion::Latest => TEST_DATA_LATEST,
        };

        let bs = BatchSelector::TimeInterval {
            batch_interval: Interval {
                start: 1000,
                duration: 5,
            },
        };
        let bytes = &mut Vec::new();

        bs.encode_with_param(&version, bytes).unwrap();
        assert_eq!(bytes, test_data);

        let nbs = BatchSelector::decode_with_param(&version, &mut Cursor::new(test_data)).unwrap();
        assert_eq!(nbs, bs);
    }

    test_versions! {batch_selector_encode_decode}

    fn query_encode_decode(version: DapVersion) {
        const TEST_DATA_DRAFT09: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        const TEST_DATA_LATEST: &[u8] = &[1, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let test_data = match version {
            DapVersion::Draft09 => TEST_DATA_DRAFT09,
            DapVersion::Latest => TEST_DATA_LATEST,
        };
        let q = Query::TimeInterval {
            batch_interval: Interval::default(),
        };
        let bytes = &mut Vec::new();
        q.encode_with_param(&version, bytes).unwrap();
        assert_eq!(bytes, test_data);
        let nq = Query::decode_with_param(&version, &mut Cursor::new(bytes)).unwrap();
        assert_eq!(nq, q);
    }

    test_versions! {query_encode_decode}

    fn read_agg_job_init_req(version: DapVersion) {
        const TEST_DATA_DRAFT09: &[u8] = &[
            0, 0, 0, 32, 116, 104, 105, 115, 32, 105, 115, 32, 97, 110, 32, 97, 103, 103, 114, 101,
            103, 97, 116, 105, 111, 110, 32, 112, 97, 114, 97, 109, 101, 116, 101, 114, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 158, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 0, 0, 0,
            0, 97, 152, 38, 185, 0, 0, 0, 12, 112, 117, 98, 108, 105, 99, 32, 115, 104, 97, 114,
            101, 23, 0, 16, 101, 110, 99, 97, 112, 115, 117, 108, 97, 116, 101, 100, 32, 107, 101,
            121, 0, 0, 0, 10, 99, 105, 112, 104, 101, 114, 116, 101, 120, 116, 0, 0, 0, 10, 112,
            114, 101, 112, 32, 115, 104, 97, 114, 101, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
            17, 17, 17, 17, 17, 0, 0, 0, 0, 9, 194, 107, 103, 0, 0, 0, 12, 112, 117, 98, 108, 105,
            99, 32, 115, 104, 97, 114, 101, 0, 0, 0, 0, 0, 0, 10, 99, 105, 112, 104, 101, 114, 116,
            101, 120, 116, 0, 0, 0, 10, 112, 114, 101, 112, 32, 115, 104, 97, 114, 101,
        ];
        const TEST_DATA_LATEST: &[u8] = &[
            0, 0, 0, 32, 116, 104, 105, 115, 32, 105, 115, 32, 97, 110, 32, 97, 103, 103, 114, 101,
            103, 97, 116, 105, 111, 110, 32, 112, 97, 114, 97, 109, 101, 116, 101, 114, 2, 0, 32,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 158, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            0, 0, 0, 0, 97, 152, 38, 185, 0, 0, 0, 12, 112, 117, 98, 108, 105, 99, 32, 115, 104,
            97, 114, 101, 23, 0, 16, 101, 110, 99, 97, 112, 115, 117, 108, 97, 116, 101, 100, 32,
            107, 101, 121, 0, 0, 0, 10, 99, 105, 112, 104, 101, 114, 116, 101, 120, 116, 0, 0, 0,
            10, 112, 114, 101, 112, 32, 115, 104, 97, 114, 101, 17, 17, 17, 17, 17, 17, 17, 17, 17,
            17, 17, 17, 17, 17, 17, 17, 0, 0, 0, 0, 9, 194, 107, 103, 0, 0, 0, 12, 112, 117, 98,
            108, 105, 99, 32, 115, 104, 97, 114, 101, 0, 0, 0, 0, 0, 0, 10, 99, 105, 112, 104, 101,
            114, 116, 101, 120, 116, 0, 0, 0, 10, 112, 114, 101, 112, 32, 115, 104, 97, 114, 101,
        ];

        let want = AggregationJobInitReq {
            agg_param: b"this is an aggregation parameter".to_vec(),
            part_batch_sel: PartialBatchSelector::LeaderSelectedByBatchId {
                batch_id: BatchId([0; 32]),
            },
            prep_inits: vec![
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: ReportMetadata {
                            id: ReportId([99; 16]),
                            time: 1_637_361_337,
                        },
                        public_share: b"public share".to_vec(),
                        encrypted_input_share: HpkeCiphertext {
                            config_id: 23,
                            enc: b"encapsulated key".to_vec(),
                            payload: b"ciphertext".to_vec(),
                        },
                    },
                    payload: b"prep share".to_vec(),
                },
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: ReportMetadata {
                            id: ReportId([17; 16]),
                            time: 163_736_423,
                        },
                        public_share: b"public share".to_vec(),
                        encrypted_input_share: HpkeCiphertext {
                            config_id: 0,
                            enc: vec![],
                            payload: b"ciphertext".to_vec(),
                        },
                    },
                    payload: b"prep share".to_vec(),
                },
            ],
        };
        println!("want {:?}", want.get_encoded_with_param(&version).unwrap());

        let got = match version {
            DapVersion::Draft09 => {
                AggregationJobInitReq::get_decoded_with_param(&version, TEST_DATA_DRAFT09).unwrap()
            }
            DapVersion::Latest => {
                AggregationJobInitReq::get_decoded_with_param(&version, TEST_DATA_LATEST).unwrap()
            }
        };
        assert_eq!(got, want);
    }

    test_versions! { read_agg_job_init_req }

    fn roundtrip_agg_job_init_req(version: DapVersion) {
        let want = AggregationJobInitReq {
            agg_param: b"this is an aggregation parameter".to_vec(),
            part_batch_sel: PartialBatchSelector::LeaderSelectedByBatchId {
                batch_id: BatchId([0; 32]),
            },
            prep_inits: vec![
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: ReportMetadata {
                            id: ReportId([99; 16]),
                            time: 1_637_361_337,
                        },
                        public_share: b"public share".to_vec(),
                        encrypted_input_share: HpkeCiphertext {
                            config_id: 23,
                            enc: b"encapsulated key".to_vec(),
                            payload: b"ciphertext".to_vec(),
                        },
                    },
                    payload: b"prep share".to_vec(),
                },
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: ReportMetadata {
                            id: ReportId([17; 16]),
                            time: 163_736_423,
                        },
                        public_share: b"public share".to_vec(),
                        encrypted_input_share: HpkeCiphertext {
                            config_id: 0,
                            enc: vec![],
                            payload: b"ciphertext".to_vec(),
                        },
                    },
                    payload: b"prep share".to_vec(),
                },
            ],
        };

        let got = AggregationJobInitReq::get_decoded_with_param(
            &version,
            &want.get_encoded_with_param(&version).unwrap(),
        )
        .unwrap();
        assert_eq!(got, want);
    }

    test_versions! { roundtrip_agg_job_init_req }

    #[test]
    fn read_agg_job_resp() {
        const TEST_DATA: &[u8] = &[
            0, 0, 0, 147, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 0, 0, 0,
            0, 31, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 86, 68, 65, 70, 45, 115, 112, 101,
            99, 105, 102, 105, 99, 32, 109, 101, 115, 115, 97, 103, 101, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 56, 98, 101, 108,
            105, 101, 118, 101, 32, 105, 116, 32, 111, 114, 32, 110, 111, 116, 32, 116, 104, 105,
            115, 32, 105, 115, 32, 42, 97, 108, 115, 111, 42, 32, 97, 32, 86, 68, 65, 70, 45, 115,
            112, 101, 99, 105, 102, 105, 99, 32, 109, 101, 115, 115, 97, 103, 101, 17, 17, 17, 17,
            17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 2, 7,
        ];

        let want = AggregationJobResp {
            transitions: vec![
                Transition {
                    report_id: ReportId([22; 16]),
                    var: TransitionVar::Continued(b"this is a VDAF-specific message".to_vec()),
                },
                Transition {
                    report_id: ReportId([255; 16]),
                    var: TransitionVar::Continued(
                        b"believe it or not this is *also* a VDAF-specific message".to_vec(),
                    ),
                },
                Transition {
                    report_id: ReportId([17; 16]),
                    var: TransitionVar::Failed(TransitionFailure::TaskExpired),
                },
            ],
        };
        println!(
            "want {:?}",
            want.get_encoded_with_param(&DapVersion::Latest).unwrap()
        );

        let got =
            AggregationJobResp::get_decoded_with_param(&DapVersion::Latest, TEST_DATA).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn read_agg_share_req() {
        let want = AggregateShareReq {
            batch_sel: BatchSelector::LeaderSelectedByBatchId {
                batch_id: BatchId([23; 32]),
            },
            agg_param: b"this is an aggregation parameter".to_vec(),
            report_count: 100,
            checksum: [0; 32],
        };
        let got = AggregateShareReq::get_decoded_with_param(
            &DapVersion::Draft09,
            &want.get_encoded_with_param(&DapVersion::Draft09).unwrap(),
        )
        .unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn read_hpke_config() {
        let data = [
            23, 0, 32, 0, 1, 0, 1, 0, 20, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 112, 117,
            98, 108, 105, 99, 32, 107, 101, 121,
        ];

        let hpke_config = HpkeConfig::get_decoded(&data).unwrap();
        assert_eq!(
            hpke_config,
            HpkeConfig {
                id: 23,
                kem_id: HpkeKemId::X25519HkdfSha256,
                kdf_id: HpkeKdfId::HkdfSha256,
                aead_id: HpkeAeadId::Aes128Gcm,
                public_key: HpkePublicKey::from(b"this is a public key".to_vec()),
            }
        );
    }

    #[test]
    fn read_unsupported_hpke_config() {
        let data = [
            23, 0, 99, 0, 99, 0, 99, 0, 20, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 112, 117,
            98, 108, 105, 99, 32, 107, 101, 121,
        ];

        let hpke_config = HpkeConfig::get_decoded(&data).unwrap();
        assert_eq!(
            hpke_config,
            HpkeConfig {
                id: 23,
                kem_id: HpkeKemId::NotImplemented(99),
                kdf_id: HpkeKdfId::NotImplemented(99),
                aead_id: HpkeAeadId::NotImplemented(99),
                public_key: HpkePublicKey::from(b"this is a public key".to_vec()),
            }
        );
    }

    #[test]
    fn test_base64url() {
        let mut rng = thread_rng();
        let id = rng.gen::<[u8; 32]>();
        assert_eq!(decode_base64url(encode_base64url(id)).unwrap(), id);
        assert_eq!(decode_base64url_vec(encode_base64url(id)).unwrap(), id);
    }

    #[test]
    fn roundtrip_id_base64url() {
        let id = AggregationJobId([7; 16]);
        assert_eq!(
            AggregationJobId::try_from_base64url(id.to_base64url()).unwrap(),
            id
        );

        let id = BatchId([7; 32]);
        assert_eq!(BatchId::try_from_base64url(id.to_base64url()).unwrap(), id);

        let id = CollectionJobId([7; 16]);
        assert_eq!(
            CollectionJobId::try_from_base64url(id.to_base64url()).unwrap(),
            id
        );

        let id = ReportId([7; 16]);
        assert_eq!(ReportId::try_from_base64url(id.to_base64url()).unwrap(), id);

        let id = TaskId([7; 32]);
        assert_eq!(TaskId::try_from_base64url(id.to_base64url()).unwrap(), id);
    }
}
