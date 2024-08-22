// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Messages in the DAP protocol.

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

// Query types
const QUERY_TYPE_TIME_INTERVAL: u8 = 0x01;
const QUERY_TYPE_FIXED_SIZE: u8 = 0x02;

// FixedSize query subtypes
const FIXED_SIZE_QUERY_TYPE_BY_BATCH_ID: u8 = 0x00;
const FIXED_SIZE_QUERY_TYPE_CURRENT_BATCH: u8 = 0x01;

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
            Copy, Clone, Default, Deserialize, Hash, PartialEq, Eq, Serialize, PartialOrd, Ord,
        )]
        #[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
        pub struct $sname(#[serde(with = "hex")] pub [u8; $len]);

        impl $sname {
            /// Return the ID encoded as a hex string.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }

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
                write!(f, "{}", self.to_hex())
            }
        }

        impl fmt::Debug for $sname {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", ::std::stringify!($sname), self.to_hex())
            }
        }
    };
}

id_struct!(AggregationJobId, 16, "Aggregation Job ID");
id_struct!(BatchId, 32, "Batch ID");
id_struct!(CollectionJobId, 16, "Collection Job ID");
id_struct!(ReportId, 16, "Report ID");
id_struct!(TaskId, 32, "Task ID");

/// serde module for base64url-encoded serialization of ids
pub mod base64url {
    use serde::{de, ser};

    use super::Base64Encode;

    pub fn serialize<I, S>(id: &I, serializer: S) -> Result<S::Ok, S::Error>
    where
        I: Base64Encode,
        S: ser::Serializer,
    {
        serializer.serialize_str(&id.to_base64url())
    }

    pub fn deserialize<'de, I, D>(deserializer: D) -> Result<I, D::Error>
    where
        D: de::Deserializer<'de>,
        D::Error: de::Error,
        I: Base64Encode,
    {
        struct Visitor<I>(std::marker::PhantomData<I>);
        impl<'de, I> de::Visitor<'de> for Visitor<I>
        where
            I: Base64Encode,
        {
            type Value = I;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 encoded value")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                I::try_from_base64url(v).ok_or_else(|| E::custom("invalid base64"))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                I::try_from_base64url(v).ok_or_else(|| E::custom("invalid base64"))
            }
        }
        deserializer.deserialize_str(Visitor::<I>(std::marker::PhantomData))
    }
}

pub mod base64url_option {
    use serde::{de, ser, Deserialize, Deserializer};

    use super::Base64Encode;

    pub fn serialize<I, S>(id: &Option<I>, serializer: S) -> Result<S::Ok, S::Error>
    where
        I: Base64Encode,
        S: ser::Serializer,
    {
        match id {
            Some(id) => super::base64url::serialize(id, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: Base64Encode,
        D: Deserializer<'de>,
        D::Error: de::Error,
    {
        let opt: Option<&str> = Option::deserialize(deserializer)?;
        opt.map(|s| {
            T::try_from_base64url(s).ok_or_else(|| <D::Error as de::Error>::custom("invalid"))
        })
        .transpose()
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
#[allow(missing_docs)]
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
    FixedSizeByBatchId { batch_id: BatchId },
}

impl std::fmt::Display for PartialBatchSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeInterval => write!(f, "time_interval"),
            Self::FixedSizeByBatchId { .. } => write!(f, "fixed_size"),
        }
    }
}

impl From<BatchSelector> for PartialBatchSelector {
    fn from(batch_sel: BatchSelector) -> Self {
        match batch_sel {
            BatchSelector::TimeInterval { .. } => Self::TimeInterval,
            BatchSelector::FixedSizeByBatchId { batch_id } => Self::FixedSizeByBatchId { batch_id },
        }
    }
}

impl Encode for PartialBatchSelector {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::TimeInterval => QUERY_TYPE_TIME_INTERVAL.encode(bytes)?,
            Self::FixedSizeByBatchId { batch_id } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes)?;
                batch_id.encode(bytes)?;
            }
        };
        Ok(())
    }
}

impl Decode for PartialBatchSelector {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            QUERY_TYPE_TIME_INTERVAL => Ok(Self::TimeInterval),
            QUERY_TYPE_FIXED_SIZE => Ok(Self::FixedSizeByBatchId {
                batch_id: BatchId::decode(bytes)?,
            }),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// A batch selector issued by the Leader in an aggregate-share request.
#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum BatchSelector {
    TimeInterval { batch_interval: Interval },
    FixedSizeByBatchId { batch_id: BatchId },
}

impl std::fmt::Display for BatchSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeInterval { .. } => write!(f, "time_interval"),
            Self::FixedSizeByBatchId { batch_id } => {
                write!(f, "fixed_size_by_batch_id({})", batch_id.to_base64url())
            }
        }
    }
}

impl Encode for BatchSelector {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::TimeInterval { batch_interval } => {
                QUERY_TYPE_TIME_INTERVAL.encode(bytes)?;
                batch_interval.encode(bytes)?;
            }
            Self::FixedSizeByBatchId { batch_id } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes)?;
                batch_id.encode(bytes)?;
            }
        };
        Ok(())
    }
}

impl Decode for BatchSelector {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            QUERY_TYPE_TIME_INTERVAL => Ok(Self::TimeInterval {
                batch_interval: Interval::decode(bytes)?,
            }),
            QUERY_TYPE_FIXED_SIZE => Ok(Self::FixedSizeByBatchId {
                batch_id: BatchId::decode(bytes)?,
            }),
            _ => Err(CodecError::UnexpectedValue),
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
        self.part_batch_sel.encode(bytes)?;
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
            part_batch_sel: PartialBatchSelector::decode(bytes)?,
            prep_inits: decode_u32_items(version, bytes)?,
        })
    }
}

/// Transition message. This conveyes a message sent from one Aggregator to another during the
/// preparation phase of VDAF evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct Transition {
    pub report_id: ReportId,
    pub var: TransitionVar,
}

impl Encode for Transition {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.report_id.encode(bytes)?;
        self.var.encode(bytes)?;
        Ok(())
    }
}

impl Decode for Transition {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            report_id: ReportId::decode(bytes)?,
            var: TransitionVar::decode(bytes)?,
        })
    }
}

/// Transition message variant.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum TransitionVar {
    Continued(Vec<u8>),
    Failed(TransitionFailure),
}

impl Encode for TransitionVar {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            TransitionVar::Continued(vdaf_message) => {
                0_u8.encode(bytes)?;
                encode_u32_bytes(bytes, vdaf_message)?;
            }
            TransitionVar::Failed(err) => {
                2_u8.encode(bytes)?;
                err.encode(bytes)?;
            }
        };
        Ok(())
    }
}

impl Decode for TransitionVar {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            0 => Ok(Self::Continued(decode_u32_bytes(bytes)?)),
            2 => Ok(Self::Failed(TransitionFailure::decode(bytes)?)),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// Transition error.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, thiserror::Error, Hash)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub enum TransitionFailure {
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

impl TryFrom<u8> for TransitionFailure {
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

impl Encode for TransitionFailure {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(bytes)
    }
}

impl Decode for TransitionFailure {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        u8::decode(bytes)?.try_into()
    }
}

impl std::fmt::Display for TransitionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
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
        }
    }
}

/// An aggregate response sent from the Helper to the Leader.
#[derive(Debug, PartialEq, Eq, Default)]
#[allow(missing_docs)]
pub struct AggregationJobResp {
    pub transitions: Vec<Transition>,
}

impl Encode for AggregationJobResp {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_u32_items(bytes, &(), &self.transitions)
    }
}

impl Decode for AggregationJobResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            transitions: decode_u32_items(&(), bytes)?,
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
    FixedSizeByBatchId { batch_id: BatchId },
    FixedSizeCurrentBatch,
}

impl Query {
    pub(crate) fn into_batch_sel(self) -> Option<BatchSelector> {
        match self {
            Self::TimeInterval { batch_interval } => {
                Some(BatchSelector::TimeInterval { batch_interval })
            }
            Self::FixedSizeByBatchId { batch_id } => {
                Some(BatchSelector::FixedSizeByBatchId { batch_id })
            }
            Self::FixedSizeCurrentBatch => None,
        }
    }
}

impl From<BatchSelector> for Query {
    fn from(batch_sel: BatchSelector) -> Self {
        match batch_sel {
            BatchSelector::TimeInterval { batch_interval } => Self::TimeInterval { batch_interval },
            BatchSelector::FixedSizeByBatchId { batch_id } => Self::FixedSizeByBatchId { batch_id },
        }
    }
}

impl std::fmt::Display for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeInterval { .. } => write!(f, "time_interval"),
            Self::FixedSizeByBatchId { batch_id } => {
                write!(f, "fixed_size_by_batch_id({})", batch_id.to_base64url())
            }
            Self::FixedSizeCurrentBatch => write!(f, "fixed_size_current_batch"),
        }
    }
}

impl ParameterizedEncode<DapVersion> for Query {
    fn encode_with_param(
        &self,
        _version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        match self {
            Self::TimeInterval { batch_interval } => {
                QUERY_TYPE_TIME_INTERVAL.encode(bytes)?;
                batch_interval.encode(bytes)?;
            }
            Self::FixedSizeByBatchId { batch_id } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes)?;
                FIXED_SIZE_QUERY_TYPE_BY_BATCH_ID.encode(bytes)?;
                batch_id.encode(bytes)?;
            }
            Self::FixedSizeCurrentBatch => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes)?;
                FIXED_SIZE_QUERY_TYPE_CURRENT_BATCH.encode(bytes)?;
            }
        };
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for Query {
    fn decode_with_param(
        _version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            QUERY_TYPE_TIME_INTERVAL => Ok(Self::TimeInterval {
                batch_interval: Interval::decode(bytes)?,
            }),
            QUERY_TYPE_FIXED_SIZE => {
                let subtype = u8::decode(bytes)?;
                match subtype {
                    FIXED_SIZE_QUERY_TYPE_BY_BATCH_ID => Ok(Self::FixedSizeByBatchId {
                        batch_id: BatchId::decode(bytes)?,
                    }),
                    FIXED_SIZE_QUERY_TYPE_CURRENT_BATCH => Ok(Self::FixedSizeCurrentBatch),
                    _ => Err(CodecError::UnexpectedValue),
                }
            }
            _ => Err(CodecError::UnexpectedValue),
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
        _version: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.part_batch_sel.encode(bytes)?;
        self.report_count.encode(bytes)?;
        self.interval.encode(bytes)?;
        self.encrypted_agg_shares[0].encode(bytes)?;
        self.encrypted_agg_shares[1].encode(bytes)?;
        Ok(())
    }
}

impl ParameterizedDecode<DapVersion> for Collection {
    fn decode_with_param(
        _version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let part_batch_sel = PartialBatchSelector::decode(bytes)?;
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
#[derive(Debug)]
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
#[derive(Clone, Debug, PartialEq)]
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
#[allow(missing_docs)]
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
    use prio::codec::{Decode, Encode, ParameterizedDecode, ParameterizedEncode};
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

    fn read_agg_job_init_req(version: DapVersion) {
        const TEST_DATA: &[u8] = &[
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

        let want = AggregationJobInitReq {
            agg_param: b"this is an aggregation parameter".to_vec(),
            part_batch_sel: PartialBatchSelector::FixedSizeByBatchId {
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

        let got = AggregationJobInitReq::get_decoded_with_param(&version, TEST_DATA).unwrap();
        assert_eq!(got, want);
    }

    test_versions! { read_agg_job_init_req }

    fn roundtrip_agg_job_init_req(version: DapVersion) {
        let want = AggregationJobInitReq {
            agg_param: b"this is an aggregation parameter".to_vec(),
            part_batch_sel: PartialBatchSelector::FixedSizeByBatchId {
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
        println!("want {:?}", want.get_encoded().unwrap());

        let got = AggregationJobResp::get_decoded(TEST_DATA).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn read_agg_share_req() {
        let want = AggregateShareReq {
            batch_sel: BatchSelector::FixedSizeByBatchId {
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
