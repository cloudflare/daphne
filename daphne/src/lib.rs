// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Daphne is an implementation of the [DAP](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)
//! protocol. Daphne includes supports for the following [VDAFs](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/):
//!  - Prio3Aes128Count
//!  - Prio3Aes128Histogram
//!  - Prio3Aes128Sum
//!
//! Additional Prio3 variants can be added easily as need.
//!
//! Daphne is not compatible with DAP tasks whose batch lifetime is longer than one aggregation.

use crate::{
    messages::{CollectResp, HpkeConfig, Interval, Nonce, TransitionFailure},
    vdaf::{
        prio3::{prio3_append_prepare_state, prio3_decode_prepare_state, Prio3Error},
        VdafAggregateShare, VdafMessage, VdafState, VdafVerifyKey,
    },
};
use prio::{
    codec::{CodecError, Decode, Encode},
    vdaf::Aggregatable as AggregatableTrait,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, fmt::Debug};
use url::Url;

/// DAP errors.
#[derive(Debug, thiserror::Error)]
pub enum DapError {
    /// Fatal error. If this triggers an abort, then treat this as an internal error.
    #[error("fatal error: {0}")]
    Fatal(String),

    /// Transition failure. This error blocks processing of a paritcular report and may, under
    /// certain conditions, trigger an abort.
    #[error("transition error: {0}")]
    Transition(TransitionFailure),
}

impl DapError {
    /// Create a fatal error.
    pub fn fatal(s: &'static str) -> Self {
        Self::Fatal(s.into())
    }
}

impl From<serde_json::Error> for DapError {
    fn from(e: serde_json::Error) -> Self {
        Self::Fatal(format!("serde_json: {}", e))
    }
}

impl From<worker::Error> for DapError {
    fn from(e: worker::Error) -> Self {
        Self::Fatal(format!("worker: {}", e))
    }
}

impl From<CodecError> for DapError {
    fn from(e: CodecError) -> Self {
        Self::Fatal(format!("codec: {}", e))
    }
}

impl From<Prio3Error> for DapError {
    fn from(e: Prio3Error) -> Self {
        match e {
            Prio3Error::Codec(..) | Prio3Error::Vdaf(..) => {
                Self::Transition(TransitionFailure::VdafPrepError)
            }
        }
    }
}

impl From<::hpke::HpkeError> for DapError {
    fn from(_e: ::hpke::HpkeError) -> Self {
        Self::Transition(TransitionFailure::HpkeDecryptError)
    }
}

/// DAP aborts.
#[derive(Debug, thiserror::Error)]
pub enum DapAbort {
    /// Bad request. Sent in response to an HTTP request that couldn't be handled preoprly.
    //
    // TODO spec: Decide whether to specify this.
    #[error("badRequest")]
    BadRequest(String),

    /// Batch mismatch. Sent in response to an AggregateShareReq.
    #[error("batchMismatch")]
    BatchMismatch,

    /// Internal error.
    #[error("internalError: {0}")]
    Internal(#[source] Box<dyn std::error::Error + 'static + Send + Sync>),

    /// Invalid batch interval. Sent in response to a CollectReq or AggregateShareReq.
    #[error("invalidBatchInterval")]
    InvalidBatchInterval,

    /// Insufficient batch size. Sent in response to a CollectReq or AggregateShareReq.
    #[error("insufficientBatchSize")]
    InsufficientBatchSize,

    /// Replayed report. Sent in response to an upload request containing a Report that has been replayed.
    //
    // TODO spec: Define this error type.
    #[error("replayedReport")]
    ReplayedReport,

    /// Stale report. Sent in response to an upload request containing a report pertaining to a
    /// batch that has already been collected.
    #[error("staleReport")]
    StaleReport,

    /// Unauthorized HTTP request.
    #[error("unauthorizedRequest")]
    UnauthorizedRequest,

    /// Unrecognized HPKE config. Sent in response to an upload request for which the leader share
    /// is encrypted using an unrecognized HPKE configuration.
    //
    // TODO spec: Rename this error type.
    #[error("unrecognizedHpkeConfig")]
    UnrecognizedHpkeConfig,

    /// Unrecognized message. Sent in response to a malformed or unexpected message.
    #[error("unrecognizedMessage")]
    UnrecognizedMessage,

    /// Unrecognized DAP task. Sent in response to a request indicating an unrecognized task ID.
    #[error("unrecognizedTask")]
    UnrecognizedTask,
}

impl DapAbort {
    /// Construct a problem details JSON object for this abort. `url` is the URL to which the
    /// request was targeted and `task_id` is the associated TaskID.
    pub fn to_problem_details(&self) -> ProblemDetails {
        let (typ, detail) = match self {
            Self::BatchMismatch
            | Self::InvalidBatchInterval
            | Self::InsufficientBatchSize
            | Self::ReplayedReport
            | Self::StaleReport
            | Self::UnauthorizedRequest
            | Self::UnrecognizedHpkeConfig
            | Self::UnrecognizedMessage
            | Self::UnrecognizedTask => (self.to_string(), None),
            Self::BadRequest(s) => ("badRequest".to_string(), Some(s.clone())),
            Self::Internal(e) => ("internalError".to_string(), Some(e.to_string())),
        };

        ProblemDetails {
            typ,
            taskid: None,   // TODO interop: Implement as specified.
            instance: None, // TODO interop: Implement as specified.
            detail,
        }
    }
}

impl From<DapError> for DapAbort {
    fn from(e: DapError) -> Self {
        match e {
            e @ DapError::Fatal(..) => Self::Internal(Box::new(e)),
            DapError::Transition(t) => Self::from(t),
        }
    }
}

impl From<CodecError> for DapAbort {
    fn from(_e: CodecError) -> Self {
        Self::UnrecognizedMessage
    }
}

impl From<TransitionFailure> for DapAbort {
    fn from(failure_reason: TransitionFailure) -> Self {
        match failure_reason {
            TransitionFailure::BatchCollected => Self::StaleReport,
            TransitionFailure::ReportReplayed => Self::ReplayedReport,
            _ => DapError::fatal("unhandled transition failure").into(),
        }
    }
}

/// A problem details document compatible with RFC 7807.
#[derive(Deserialize, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub typ: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) taskid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) instance: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Per-task DAP parameters.
#[derive(Deserialize, Serialize)]
#[serde(try_from = "ShadowDapTaskConfig")]
pub struct DapTaskConfig {
    pub leader_url: Url,
    pub helper_url: Url,
    pub min_batch_duration: u64, // seconds
    pub min_batch_size: u64,     // number of reports
    pub vdaf: VdafConfig,
    #[serde(skip_serializing)]
    pub(crate) vdaf_verify_key: VdafVerifyKey,
    #[serde(skip_serializing)]
    pub(crate) collector_hpke_config: HpkeConfig,
}

impl DapTaskConfig {
    /// Convert at timestamp `now` into an [`Interval`] that contains it. The timestamp is the
    /// numbre of seconds since the beginning of UNIX time.
    pub fn current_batch_window(&self, now: u64) -> Interval {
        let start = now - (now % self.min_batch_duration);
        Interval {
            start,
            duration: self.min_batch_duration,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct ShadowDapTaskConfig {
    leader_url: Url,
    helper_url: Url,
    min_batch_duration: u64,
    min_batch_size: u64,
    vdaf: VdafConfig,
    #[serde(with = "hex")]
    vdaf_verify_key: Vec<u8>,
    #[serde(with = "hex")]
    collector_hpke_config: Vec<u8>,
}

impl TryFrom<ShadowDapTaskConfig> for DapTaskConfig {
    type Error = DapAbort;

    fn try_from(shadow: ShadowDapTaskConfig) -> std::result::Result<Self, Self::Error> {
        let vdaf_verify_key = shadow
            .vdaf
            .get_decoded_verify_key(&shadow.vdaf_verify_key)?;

        let collector_hpke_config = HpkeConfig::get_decoded(&shadow.collector_hpke_config)?;

        Ok(Self {
            leader_url: shadow.leader_url,
            helper_url: shadow.helper_url,
            min_batch_duration: shadow.min_batch_duration,
            min_batch_size: shadow.min_batch_size,
            vdaf: shadow.vdaf,
            vdaf_verify_key,
            collector_hpke_config,
        })
    }
}

/// A measurement from which a Client generates a report.
pub enum DapMeasurement {
    U64(u64),
}

/// The aggregate result computed by the Collector.
#[derive(Debug, PartialEq)]
pub enum DapAggregateResult {
    U64(u64),
    U128(u128),
    U128Vec(Vec<u128>),
}

/// The Leader's state after sending an AggregateInitReq.
#[derive(Debug)]
pub struct DapLeaderState {
    pub(crate) seq: Vec<(VdafState, VdafMessage, Nonce)>,
}

/// The Leader's state after sending an AggregateContReq.
#[derive(Debug)]
pub struct DapLeaderUncommitted {
    pub(crate) seq: Vec<(DapOutputShare, Nonce)>,
}

/// The Helper's state during the aggregation flow.
#[derive(Debug, PartialEq)]
pub struct DapHelperState {
    pub(crate) seq: Vec<(VdafState, Nonce)>,
}

impl DapHelperState {
    /// Encode the Helper state as a byte string.
    ///
    /// This method is used by the Helper in order to offload its state to the Leader. For
    /// example, it might encrypt the output and add the ciphertext to an outgoing aggregate
    /// response.
    ///
    /// Note that the encoding format is not specified by the DAP standard.
    pub fn get_encoded(&self, vdaf_config: &VdafConfig) -> Result<Vec<u8>, DapError> {
        let mut bytes = vec![];
        for (state, nonce) in self.seq.iter() {
            match vdaf_config {
                VdafConfig::Prio3(prio3_config) => {
                    prio3_append_prepare_state(&mut bytes, prio3_config, state)?;
                }
            };
            nonce.encode(&mut bytes);
        }
        Ok(bytes)
    }

    /// Decode the Helper state from a byte string.
    pub fn get_decoded(vdaf_config: &VdafConfig, data: &[u8]) -> Result<Self, DapError> {
        let mut seq = vec![];
        let mut r = std::io::Cursor::new(data);
        while (r.position() as usize) < data.len() {
            let state = match vdaf_config {
                VdafConfig::Prio3(ref prio3_config) => {
                    prio3_decode_prepare_state(prio3_config, 1, &mut r)?
                }
            };
            let nonce = Nonce::decode(&mut r)?;
            seq.push((state, nonce))
        }

        Ok(DapHelperState { seq })
    }
}

#[derive(Debug)]
/// An ouptut share produced by an Aggregator for a single report.
pub struct DapOutputShare {
    pub(crate) time: u64, // Value from the report nonce
    pub(crate) checksum: [u8; 32],
    pub(crate) data: VdafAggregateShare,
}

/// An aggregate share computed by combining a set of output shares.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct DapAggregateShare {
    pub(crate) report_count: u64,
    pub(crate) checksum: [u8; 32],
    pub(crate) data: Option<VdafAggregateShare>,
}

impl DapAggregateShare {
    /// Merge two aggregate shares. This method is run by an Aggregator.
    //
    // TODO Add unit tests.
    pub fn merge(&mut self, other: DapAggregateShare) -> Result<(), DapError> {
        // Update the aggregate share data.
        match (self.data.as_mut(), other.data) {
            (_, None) => (),
            (None, Some(data)) => {
                self.data = Some(data);
            }
            (Some(VdafAggregateShare::Field64(left)), Some(VdafAggregateShare::Field64(right))) => {
                left.merge(&right)
                    .map_err(|e| DapError::Fatal(e.to_string()))?;
            }
            (
                Some(VdafAggregateShare::Field128(left)),
                Some(VdafAggregateShare::Field128(right)),
            ) => {
                left.merge(&right)
                    .map_err(|e| DapError::Fatal(e.to_string()))?;
            }
            _ => return Err(DapError::fatal("invalid aggregate share merge")),
        };

        self.report_count += other.report_count;
        for (x, y) in self.checksum.iter_mut().zip(other.checksum) {
            *x ^= y;
        }
        Ok(())
    }

    /// Transform a sequence of output shares into a map from batch intervals to aggregate shares.
    //
    // TODO Add unit tests
    pub fn batches_from_out_shares(
        out_shares: Vec<DapOutputShare>,
        min_batch_interval: u64,
    ) -> Result<HashMap<u64, Self>, DapError> {
        let mut agg_shares: HashMap<u64, Self> = HashMap::new();
        for out_share in out_shares.into_iter() {
            let interval = out_share.time - (out_share.time % min_batch_interval);
            let agg_share_delta = DapAggregateShare {
                report_count: 1,
                checksum: out_share.checksum,
                data: Some(out_share.data),
            };
            if let Some(agg_share) = agg_shares.get_mut(&interval) {
                agg_share.merge(agg_share_delta)?;
            } else {
                agg_shares.insert(interval, agg_share_delta);
            }
        }
        Ok(agg_shares)
    }

    /// Set the aggregate share to zero.
    pub fn reset(&mut self) {
        self.report_count = 0;
        self.checksum = [0; 32];
        self.data = None;
    }
}

/// Leader state transition during the aggregation flow.
#[derive(Debug)]
pub enum DapLeaderTransition<M: Debug> {
    /// The Leader has produced the next outbound message and its state has been updated.
    Continue(DapLeaderState, M),

    /// The leader has computed output shares, but is waiting on an AggregateResp from the hepler
    /// before committing them.
    Uncommitted(DapLeaderUncommitted, M),

    /// The Leader has completed the aggregation flow without computing an aggregate share.
    Skip,
}

/// Helper state transition during the aggregation flow.
#[derive(Debug)]
pub enum DapHelperTransition<M: Debug> {
    /// The Helper has produced the next outbound message and its state has been updated.
    Continue(DapHelperState, M),

    /// The Helper has produced the last outbound message and has computed a sequence of output
    /// shares.
    //
    // TODO Instead of merging all output shares into a single aggregate share, return a collection
    // of aggregat shares, each corresponding to a different batch interval.
    Finish(Vec<DapOutputShare>, M),
}

/// Specificaiton of a concrete VDAF.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VdafConfig {
    Prio3(Prio3Config),
}

/// Supported data types for prio3.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Prio3Config {
    /// A 64-bit counter. The aggregate is the sum of the measurements, where each measurement is
    /// equal to `0` or `1`.
    Count,

    /// A histogram for estimating the distribution of 64-bit, unsigned integers using pre-defined
    /// bucket boundaries.
    Histogram { buckets: Vec<u64> },

    /// The sum of 64-bit, unsigned integers. Each measurement is an integer in range `[0,
    /// 2^bits)`.
    Sum { bits: u32 },
}

/// DAP request.
#[derive(Debug)]
pub struct DapRequest<S> {
    pub media_type: Option<&'static str>,
    pub payload: Vec<u8>,
    pub url: Url,
    pub sender_auth: Option<S>,
}

/// DAP response.
#[derive(Debug)]
pub struct DapResponse {
    pub media_type: Option<&'static str>,
    pub payload: Vec<u8>,
}

/// Status of a collect job.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DapCollectJob {
    Done(CollectResp),
    Pending,
    Unknown,
}

/// Telemetry information for the leader's processing loop.
//
// TODO This is used for tests. Perhaps Prometheus metrics would be sufficient?
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct DapLeaderProcessTelemetry {
    /// Number of collect requests completed.
    pub reports_collected: u64,

    /// The number of reports aggregated.
    pub reports_aggregated: u64,

    /// The number of reports processed.
    pub reports_processed: u64,
}

pub mod auth;
pub mod constants;
pub mod hpke;
#[cfg(test)]
mod hpke_test;
pub mod messages;
#[cfg(test)]
mod messages_test;
pub mod roles;
#[cfg(test)]
mod roles_test;
mod vdaf;
