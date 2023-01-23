// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Messages in the DAP protocol.

use crate::{hpke::HpkePublicKeySerde, DapError, DapVersion};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use hpke_rs::HpkePublicKey;
use prio::codec::{
    decode_u16_items, decode_u32_items, encode_u16_items, encode_u32_items, CodecError, Decode,
    Encode, ParameterizedDecode, ParameterizedEncode,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    fmt,
    io::{Cursor, Read},
};

// Various algorithm constants
const KEM_ID_X25519_HKDF_SHA256: u16 = 0x0020;
const KEM_ID_P256_HKDF_SHA256: u16 = 0x0010;
const KDF_ID_HKDF_SHA256: u16 = 0x0001;
const AEAD_ID_AES128GCM: u16 = 0x0001;

// Query types
const QUERY_TYPE_TIME_INTERVAL: u8 = 0x01;
const QUERY_TYPE_FIXED_SIZE: u8 = 0x02;

// FixedSize query subtypes
const FIXED_SIZE_QUERY_TYPE_BY_BATCH_ID: u8 = 0x00;
const FIXED_SIZE_QUERY_TYPE_CURRENT_BATCH: u8 = 0x01;

// Known extension types.
const EXTENSION_TASKPROV: u16 = 0xff00;

/// The identifier for a DAP task.
#[derive(Clone, Debug, Default, Deserialize, Hash, PartialEq, Eq, Serialize)]
pub struct Id(#[serde(with = "hex")] pub [u8; 32]);

impl Id {
    /// Return the URL-safe, base64 encoding of the task ID.
    pub fn to_base64url(&self) -> String {
        encode_base64url(self.0)
    }

    /// Return the ID encoded as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Encode for Id {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }
}

impl Decode for Id {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut data = [0; 32];
        bytes.read_exact(&mut data[..])?;
        Ok(Id(data))
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A duration.
pub type Duration = u64;

/// The timestamp sent in a [`Report`].
pub type Time = u64;

/// A report ID.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, Serialize)]
#[allow(missing_docs)]
pub struct ReportId(pub [u8; 16]);

impl ReportId {
    /// Return the ID encoded as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Encode for ReportId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }
}

impl Decode for ReportId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut id = [0; 16];
        bytes.read_exact(&mut id)?;
        Ok(ReportId(id))
    }
}

impl AsRef<[u8]> for ReportId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ReportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Report extensions.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Extension {
    Taskprov { payload: Vec<u8> }, // Not a TaskConfig to make computing the expected task id more efficient
    Unhandled { typ: u16, payload: Vec<u8> },
}

impl Extension {
    /// Return the type code associated with the extension
    fn type_code(&self) -> u16 {
        match self {
            Self::Taskprov { .. } => EXTENSION_TASKPROV,
            Self::Unhandled { typ, .. } => *typ,
        }
    }
}

impl Encode for Extension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Taskprov { payload } => {
                EXTENSION_TASKPROV.encode(bytes);
                encode_u16_bytes(bytes, payload);
            }
            Self::Unhandled { typ, payload } => {
                typ.encode(bytes);
                encode_u16_bytes(bytes, payload);
            }
        }
    }
}

impl Decode for Extension {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let typ = u16::decode(bytes)?;
        let payload = decode_u16_bytes(bytes)?;
        match typ {
            EXTENSION_TASKPROV => Ok(Self::Taskprov { payload }),
            _ => Ok(Self::Unhandled { typ, payload }),
        }
    }
}

/// Report metadata.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[allow(missing_docs)]
pub struct ReportMetadata {
    pub id: ReportId,
    pub time: Time,

    /// Report extensions, only used in draft-02. In draft-03 and above, extensions are carried in encrypted input share.
    pub extensions: Vec<Extension>,
}

impl ParameterizedEncode<DapVersion> for ReportMetadata {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        self.id.encode(bytes);
        self.time.encode(bytes);
        if matches!(version, DapVersion::Draft02) {
            encode_u16_items(bytes, &(), &self.extensions);
        } else if !self.extensions.is_empty() {
            panic!("tried to encode extensions in the ReportMetadata for DAP > draft-02")
        }
    }
}

impl ParameterizedDecode<DapVersion> for ReportMetadata {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        let metadata = Self {
            id: ReportId::decode(bytes)?,
            time: Time::decode(bytes)?,
            extensions: match version {
                DapVersion::Draft02 => decode_u16_items(&(), bytes)?,
                _ => Vec::new(),
            },
        };
        // Check for duplicate extensions and unknown extensions.
        let mut seen: HashSet<u16> = HashSet::new();
        for extension in &metadata.extensions {
            if !seen.insert(extension.type_code()) {
                return Err(CodecError::UnexpectedValue);
            }
            if matches!(extension, Extension::Unhandled { .. }) {
                // Unrecognized extensions are an error.
                return Err(CodecError::UnexpectedValue);
            }
        }
        Ok(metadata)
    }
}

/// A report generated by a client.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[allow(missing_docs)]
pub struct Report {
    pub task_id: Id,
    pub metadata: ReportMetadata,
    pub public_share: Vec<u8>,
    pub encrypted_input_shares: Vec<HpkeCiphertext>,
}

impl ParameterizedEncode<DapVersion> for Report {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.metadata.encode_with_param(version, bytes);
        encode_u32_bytes(bytes, &self.public_share);
        encode_u32_items(bytes, &(), &self.encrypted_input_shares);
    }
}

impl ParameterizedDecode<DapVersion> for Report {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            task_id: Id::decode(bytes)?,
            metadata: ReportMetadata::decode_with_param(version, bytes)?,
            public_share: decode_u32_bytes(bytes)?,
            encrypted_input_shares: decode_u32_items(&(), bytes)?,
        })
    }
}

/// An initial aggregate sub-request sent in an [`AggregateInitializeReq`]. The contents of this
/// structure pertain to a single report.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[allow(missing_docs)]
pub struct ReportShare {
    pub metadata: ReportMetadata,
    pub public_share: Vec<u8>,
    pub encrypted_input_share: HpkeCiphertext,
}

impl ParameterizedEncode<DapVersion> for ReportShare {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        self.metadata.encode_with_param(version, bytes);
        encode_u32_bytes(bytes, &self.public_share);
        self.encrypted_input_share.encode(bytes);
    }
}

impl ParameterizedDecode<DapVersion> for ReportShare {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            metadata: ReportMetadata::decode_with_param(version, bytes)?,
            public_share: decode_u32_bytes(bytes)?,
            encrypted_input_share: HpkeCiphertext::decode(bytes)?,
        })
    }
}

/// Batch parameter conveyed to the Helper by the Leader in the aggregation sub-protocol. Used to
/// identify which batch the reports in the [`AggregateInitializeReq`] are intended for.
#[derive(Clone, Debug, Eq, Deserialize, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialBatchSelector {
    TimeInterval,
    FixedSizeByBatchId { batch_id: Id },
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
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::TimeInterval => QUERY_TYPE_TIME_INTERVAL.encode(bytes),
            Self::FixedSizeByBatchId { batch_id } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes);
                batch_id.encode(bytes);
            }
        }
    }
}

impl Decode for PartialBatchSelector {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            QUERY_TYPE_TIME_INTERVAL => Ok(Self::TimeInterval),
            QUERY_TYPE_FIXED_SIZE => Ok(Self::FixedSizeByBatchId {
                batch_id: Id::decode(bytes)?,
            }),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// A batch selector issued by the Leader in an aggregate-share request.
#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchSelector {
    TimeInterval { batch_interval: Interval },
    FixedSizeByBatchId { batch_id: Id },
}

impl Encode for BatchSelector {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::TimeInterval { batch_interval } => {
                QUERY_TYPE_TIME_INTERVAL.encode(bytes);
                batch_interval.encode(bytes);
            }
            Self::FixedSizeByBatchId { batch_id } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes);
                batch_id.encode(bytes);
            }
        }
    }
}

impl Decode for BatchSelector {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            QUERY_TYPE_TIME_INTERVAL => Ok(Self::TimeInterval {
                batch_interval: Interval::decode(bytes)?,
            }),
            QUERY_TYPE_FIXED_SIZE => Ok(Self::FixedSizeByBatchId {
                batch_id: Id::decode(bytes)?,
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

impl TryFrom<Query> for BatchSelector {
    type Error = DapError;

    fn try_from(query: Query) -> Result<Self, DapError> {
        match query {
            Query::TimeInterval { batch_interval } => Ok(Self::TimeInterval { batch_interval }),
            Query::FixedSizeByBatchId { batch_id } => Ok(Self::FixedSizeByBatchId { batch_id }),
            Query::FixedSizeCurrentBatch => Err(DapError::Fatal(
                "tried to make a BatchSelector from a FixedSizeCurrentBatch query".to_string(),
            )),
        }
    }
}

/// Aggregate initialization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateInitializeReq {
    pub task_id: Id,
    pub agg_job_id: Id,
    pub agg_param: Vec<u8>,
    pub part_batch_sel: PartialBatchSelector,
    pub report_shares: Vec<ReportShare>,
}

impl ParameterizedEncode<DapVersion> for AggregateInitializeReq {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.agg_job_id.encode(bytes);
        match version {
            DapVersion::Draft02 => encode_u16_bytes(bytes, &self.agg_param),
            DapVersion::Draft03 => encode_u32_bytes(bytes, &self.agg_param),
            _ => unreachable!("unimplemented version"),
        };
        self.part_batch_sel.encode(bytes);
        encode_u32_items(bytes, version, &self.report_shares);
    }
}

impl ParameterizedDecode<DapVersion> for AggregateInitializeReq {
    fn decode_with_param(
        version: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            task_id: Id::decode(bytes)?,
            agg_job_id: Id::decode(bytes)?,
            agg_param: match version {
                DapVersion::Draft02 => decode_u16_bytes(bytes)?,
                DapVersion::Draft03 => decode_u32_bytes(bytes)?,
                _ => unreachable!("unimplemented version"),
            },
            part_batch_sel: PartialBatchSelector::decode(bytes)?,
            report_shares: decode_u32_items(version, bytes)?,
        })
    }
}

/// Aggregate continuation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateContinueReq {
    pub task_id: Id,
    pub agg_job_id: Id,
    pub transitions: Vec<Transition>,
}

impl Encode for AggregateContinueReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.agg_job_id.encode(bytes);
        encode_u32_items(bytes, &(), &self.transitions);
    }
}

impl Decode for AggregateContinueReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            task_id: Id::decode(bytes)?,
            agg_job_id: Id::decode(bytes)?,
            transitions: decode_u32_items(&(), bytes)?,
        })
    }
}

/// Transition message. This conveyes a message sent from one Aggregator to another during the
/// preparation phase of VDAF evaluation.
//
// TODO spec: This is called `PrepareStep` in draft-ietf-ppm-dap-03. This is confusing because it
// overloads a term used in draft-irtf-cfrg-draft-02.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub report_id: ReportId,
    pub var: TransitionVar,
}

impl Encode for Transition {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.report_id.encode(bytes);
        self.var.encode(bytes);
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
pub enum TransitionVar {
    Continued(Vec<u8>),
    Finished,
    Failed(TransitionFailure),
}

impl Encode for TransitionVar {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            TransitionVar::Continued(vdaf_message) => {
                0_u8.encode(bytes);
                encode_u32_bytes(bytes, vdaf_message);
            }
            TransitionVar::Finished => {
                1_u8.encode(bytes);
            }
            TransitionVar::Failed(err) => {
                2_u8.encode(bytes);
                err.encode(bytes);
            }
        }
    }
}

impl Decode for TransitionVar {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            0 => Ok(Self::Continued(decode_u32_bytes(bytes)?)),
            1 => Ok(Self::Finished),
            2 => Ok(Self::Failed(TransitionFailure::decode(bytes)?)),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

/// Transition error.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionFailure {
    BatchCollected = 0,
    ReportReplayed = 1,
    ReportDropped = 2,
    HpkeUnknownConfigId = 3,
    HpkeDecryptError = 4,
    VdafPrepError = 5,
    BatchSaturated = 6,
    TaskExpired = 7,
    UnrecognizedMessage = 8,
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
            b if b == Self::UnrecognizedMessage as u8 => Ok(Self::UnrecognizedMessage),
            b if b == Self::ReportTooEarly as u8 => Ok(Self::ReportTooEarly),
            _ => Err(CodecError::UnexpectedValue),
        }
    }
}

impl Encode for TransitionFailure {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u8).encode(bytes);
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
            Self::UnrecognizedMessage => write!(f, "unrecognized_message"),
            Self::ReportTooEarly => write!(f, "report_too_early"),
        }
    }
}

/// An aggregate response sent from the Helper to the Leader.
#[derive(Debug, PartialEq, Eq, Default)]
#[allow(missing_docs)]
pub struct AggregateResp {
    pub transitions: Vec<Transition>,
}

impl Encode for AggregateResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u32_items(bytes, &(), &self.transitions);
    }
}

impl Decode for AggregateResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            transitions: decode_u32_items(&(), bytes)?,
        })
    }
}

/// A batch interval.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[allow(missing_docs)]
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
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.start.encode(bytes);
        self.duration.encode(bytes);
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
#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    TimeInterval { batch_interval: Interval },
    FixedSizeByBatchId { batch_id: Id },
    FixedSizeCurrentBatch,
}

impl ParameterizedEncode<DapVersion> for Query {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        match self {
            Self::TimeInterval { batch_interval } => {
                QUERY_TYPE_TIME_INTERVAL.encode(bytes);
                batch_interval.encode(bytes);
            }
            Self::FixedSizeByBatchId { batch_id } => {
                QUERY_TYPE_FIXED_SIZE.encode(bytes);
                if *version != DapVersion::Draft02 {
                    FIXED_SIZE_QUERY_TYPE_BY_BATCH_ID.encode(bytes);
                }
                batch_id.encode(bytes);
            }
            Self::FixedSizeCurrentBatch => {
                if *version == DapVersion::Draft02 {
                    panic!("tried to encode a Query or BatchSelector fixed size current batch in DAP 02");
                }
                QUERY_TYPE_FIXED_SIZE.encode(bytes);
                FIXED_SIZE_QUERY_TYPE_CURRENT_BATCH.encode(bytes);
            }
        }
    }
}

impl ParameterizedDecode<DapVersion> for Query {
    fn decode_with_param(
        decoding_parameter: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            QUERY_TYPE_TIME_INTERVAL => Ok(Self::TimeInterval {
                batch_interval: Interval::decode(bytes)?,
            }),
            QUERY_TYPE_FIXED_SIZE => {
                if *decoding_parameter == DapVersion::Draft02 {
                    Ok(Self::FixedSizeByBatchId {
                        batch_id: Id::decode(bytes)?,
                    })
                } else {
                    let subtype = u8::decode(bytes)?;
                    match subtype {
                        FIXED_SIZE_QUERY_TYPE_BY_BATCH_ID => Ok(Self::FixedSizeByBatchId {
                            batch_id: Id::decode(bytes)?,
                        }),
                        FIXED_SIZE_QUERY_TYPE_CURRENT_BATCH => Ok(Self::FixedSizeCurrentBatch),
                        _ => Err(CodecError::UnexpectedValue),
                    }
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
//
// TODO Add serialization tests.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CollectReq {
    pub task_id: Id,
    pub query: Query,
    pub agg_param: Vec<u8>,
}

impl ParameterizedEncode<DapVersion> for CollectReq {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.query.encode_with_param(version, bytes);
        match version {
            DapVersion::Draft02 => encode_u16_bytes(bytes, &self.agg_param),
            DapVersion::Draft03 => encode_u32_bytes(bytes, &self.agg_param),
            _ => panic!("unimplemented DapVersion"),
        };
    }
}

impl ParameterizedDecode<DapVersion> for CollectReq {
    fn decode_with_param(
        decoding_parameter: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            task_id: Id::decode(bytes)?,
            query: Query::decode_with_param(decoding_parameter, bytes)?,
            agg_param: match decoding_parameter {
                DapVersion::Draft02 => decode_u16_bytes(bytes)?,
                DapVersion::Draft03 => decode_u32_bytes(bytes)?,
                _ => panic!("unimplemented DapVersion"),
            },
        })
    }
}

/// A collect response.
//
// TODO Add serialization tests.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CollectResp {
    pub part_batch_sel: PartialBatchSelector,
    pub report_count: u64,
    pub encrypted_agg_shares: Vec<HpkeCiphertext>,
}

impl Encode for CollectResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.part_batch_sel.encode(bytes);
        self.report_count.encode(bytes);
        encode_u32_items(bytes, &(), &self.encrypted_agg_shares);
    }
}

impl Decode for CollectResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            part_batch_sel: PartialBatchSelector::decode(bytes)?,
            report_count: u64::decode(bytes)?,
            encrypted_agg_shares: decode_u32_items(&(), bytes)?,
        })
    }
}

/// An aggregate-share request.
//
// TODO Add serialization tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AggregateShareReq {
    pub task_id: Id,
    pub batch_sel: BatchSelector,
    pub agg_param: Vec<u8>,
    pub report_count: u64,
    pub checksum: [u8; 32],
}

impl ParameterizedEncode<DapVersion> for AggregateShareReq {
    fn encode_with_param(&self, version: &DapVersion, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_sel.encode_with_param(version, bytes);
        match version {
            DapVersion::Draft02 => encode_u16_bytes(bytes, &self.agg_param),
            DapVersion::Draft03 => encode_u32_bytes(bytes, &self.agg_param),
            _ => panic!("unimplemented DapVersion"),
        };
        self.report_count.encode(bytes);
        bytes.extend_from_slice(&self.checksum);
    }
}

impl ParameterizedDecode<DapVersion> for AggregateShareReq {
    fn decode_with_param(
        decoding_parameter: &DapVersion,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            task_id: Id::decode(bytes)?,
            batch_sel: BatchSelector::decode_with_param(decoding_parameter, bytes)?,
            agg_param: match decoding_parameter {
                DapVersion::Draft02 => decode_u16_bytes(bytes)?,
                DapVersion::Draft03 => decode_u32_bytes(bytes)?,
                _ => panic!("unimplemented DapVersion"),
            },
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
//
// TODO Add serialization tests.
#[derive(Debug)]
pub struct AggregateShareResp {
    pub encrypted_agg_share: HpkeCiphertext,
}

impl Encode for AggregateShareResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.encrypted_agg_share.encode(bytes);
    }
}

impl Decode for AggregateShareResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            encrypted_agg_share: HpkeCiphertext::decode(bytes)?,
        })
    }
}

/// Codepoint for KEM schemes compatible with HPKE.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HpkeKemId {
    P256HkdfSha256,
    X25519HkdfSha256,
    NotImplemented(u16),
}

impl From<HpkeKemId> for u16 {
    fn from(kem_id: HpkeKemId) -> Self {
        match kem_id {
            HpkeKemId::P256HkdfSha256 => KEM_ID_P256_HKDF_SHA256,
            HpkeKemId::X25519HkdfSha256 => KEM_ID_X25519_HKDF_SHA256,
            HpkeKemId::NotImplemented(x) => x,
        }
    }
}

impl Encode for HpkeKemId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        u16::from(*self).encode(bytes);
    }
}

impl Decode for HpkeKemId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u16::decode(bytes)? {
            x if x == KEM_ID_P256_HKDF_SHA256 => Ok(Self::P256HkdfSha256),
            x if x == KEM_ID_X25519_HKDF_SHA256 => Ok(Self::X25519HkdfSha256),
            x => Ok(Self::NotImplemented(x)),
        }
    }
}

/// Codepoint for KDF schemes compatible with HPKE.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HpkeKdfId {
    HkdfSha256,
    NotImplemented(u16),
}

impl From<HpkeKdfId> for u16 {
    fn from(kdf_id: HpkeKdfId) -> Self {
        match kdf_id {
            HpkeKdfId::HkdfSha256 => KDF_ID_HKDF_SHA256,
            HpkeKdfId::NotImplemented(x) => x,
        }
    }
}

impl Encode for HpkeKdfId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        u16::from(*self).encode(bytes);
    }
}

impl Decode for HpkeKdfId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u16::decode(bytes)? {
            x if x == KDF_ID_HKDF_SHA256 => Ok(Self::HkdfSha256),
            x => Ok(Self::NotImplemented(x)),
        }
    }
}

/// Codepoint for AEAD schemes compatible with HPKE.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HpkeAeadId {
    Aes128Gcm,
    NotImplemented(u16),
}

impl From<HpkeAeadId> for u16 {
    fn from(aead_id: HpkeAeadId) -> Self {
        match aead_id {
            HpkeAeadId::Aes128Gcm => AEAD_ID_AES128GCM,
            HpkeAeadId::NotImplemented(x) => x,
        }
    }
}

impl Encode for HpkeAeadId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        u16::from(*self).encode(bytes);
    }
}

impl Decode for HpkeAeadId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u16::decode(bytes)? {
            x if x == AEAD_ID_AES128GCM => Ok(Self::Aes128Gcm),
            x => Ok(Self::NotImplemented(x)),
        }
    }
}

/// The HPKE public key configuration of a Server.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct HpkeConfig {
    pub id: u8,
    pub kem_id: HpkeKemId,
    pub kdf_id: HpkeKdfId,
    pub aead_id: HpkeAeadId,
    #[serde(with = "HpkePublicKeySerde")]
    pub public_key: HpkePublicKey,
}

impl AsRef<HpkeConfig> for HpkeConfig {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Encode for HpkeConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.id.encode(bytes);
        self.kem_id.encode(bytes);
        self.kdf_id.encode(bytes);
        self.aead_id.encode(bytes);
        encode_u16_bytes(bytes, self.public_key.as_slice());
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

/// A list of HPKE public key configurations.
#[derive(Clone, Debug, PartialEq)]
pub struct HpkeConfigList {
    pub hpke_configs: Vec<HpkeConfig>,
}

impl Encode for HpkeConfigList {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.hpke_configs);
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
#[allow(missing_docs)]
pub struct HpkeCiphertext {
    pub config_id: u8,
    #[serde(with = "hex")]
    pub enc: Vec<u8>,
    #[serde(with = "hex")]
    pub payload: Vec<u8>,
}

impl Encode for HpkeCiphertext {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.config_id.encode(bytes);
        encode_u16_bytes(bytes, &self.enc);
        encode_u32_bytes(bytes, &self.payload);
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

impl Encode for PlaintextInputShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.extensions);
        encode_u32_bytes(bytes, &self.payload);
    }
}

impl Decode for PlaintextInputShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let share = Self {
            extensions: decode_u16_items(&(), bytes)?,
            payload: decode_u32_bytes(bytes)?,
        };
        // Check for duplicate extensions and unknown extensions.
        let mut seen: HashSet<u16> = HashSet::new();
        for extension in &share.extensions {
            if !seen.insert(extension.type_code()) {
                return Err(CodecError::UnexpectedValue);
            }
            if matches!(extension, Extension::Unhandled { .. }) {
                return Err(CodecError::UnexpectedValue);
            }
        }
        Ok(share)
    }
}

// NOTE ring provides a similar function, but as of version 0.16.20, it doesn't compile to
// wasm32-unknown-unknown.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut r = 0;
    for (x, y) in left.iter().zip(right) {
        r |= x ^ y;
    }
    r == 0
}

pub(crate) fn encode_u16_bytes(bytes: &mut Vec<u8>, input: &[u8]) {
    u16::try_from(input.len())
        .expect("length too large for u16")
        .encode(bytes);
    bytes.extend_from_slice(input);
}

pub(crate) fn decode_u16_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Vec<u8>, CodecError> {
    let len = u16::decode(bytes)? as usize;
    let mut out = vec![0; len];
    bytes.read_exact(&mut out)?;
    Ok(out)
}

pub(crate) fn encode_u32_bytes(bytes: &mut Vec<u8>, input: &[u8]) {
    u32::try_from(input.len())
        .expect("length too large for u32")
        .encode(bytes);
    bytes.extend_from_slice(input);
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

#[cfg(test)]
mod mod_test;
pub mod taskprov;
