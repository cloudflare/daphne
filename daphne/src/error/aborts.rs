// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Definitions and tooling for DAP protocol aborts.

use crate::{
    fatal_error,
    messages::{BatchSelector, TaskId, TransitionFailure},
    DapError, DapMediaType, DapRequest, DapVersion,
};
use hex::FromHexError;
use prio::codec::CodecError;
use serde::{Deserialize, Serialize};

// NOTE:
// The display implementation of this error is used for metrics, as such, it can't be changed to
// include field values
/// DAP aborts.
#[derive(Debug, thiserror::Error)]
pub enum DapAbort {
    /// Bad request. Sent in response to an HTTP request that couldn't be handled preoprly.
    #[error("bad request")]
    BadRequest(String),

    /// Invalid batch. Sent in response to a CollectReq or AggregateShareReq.
    #[error("batchInvalid")]
    BatchInvalid { detail: String, task_id: TaskId },

    /// Batch mismatch. Sent in response to an AggregateShareReq.
    #[error("batchMismatch")]
    BatchMismatch { detail: String, task_id: TaskId },

    /// Batch overlap. Sent in response to an CollectReq for which the Leader detects the same
    /// Collector requesting an aggregate share which it has collected in the past.
    #[error("batchOverlap")]
    BatchOverlap { detail: String, task_id: TaskId },

    /// Invalid batch size (either too small or too large). Sent in response to a CollectReq or
    /// AggregateShareReq.
    #[error("invalidBatchSize")]
    InvalidBatchSize { detail: String, task_id: TaskId },

    /// taskprov: Invalid DAP task. Sent when a server opts out of a taskprov task configuration.
    #[error("invalidTask")]
    InvalidTask { detail: String, task_id: TaskId },

    /// Request with missing task ID.
    #[error("missingTaskID")]
    MissingTaskId,

    /// Query mismatch. Sent in response to a CollectReq or AggregateShareReq.
    #[error("queryMismatch")]
    QueryMismatch { detail: String, task_id: TaskId },

    /// Report rejected. Sent in response to an upload request containing a Report that the Leader
    /// would reject during the aggregation sub-protocol.
    #[error("reportRejected")]
    ReportRejected { detail: String },

    /// Report too late. Sent in response to an upload request for a task that is known to have
    /// expired.
    #[error("reportTooLate")]
    ReportTooLate,

    /// Round mismatch. The aggregators disagree on the current round of the VDAF preparation protocol.
    /// This abort occurs during the aggregation sub-protocol.
    #[error("roundMismatch")]
    RoundMismatch {
        detail: String,
        task_id: TaskId,
        // draft02 compatibility: The ID's definition (i.e., length in bytes) depends on which
        // protocol is in use, hence the need for the `MetaAggregationJobId` type for representing
        // the union of both To avoid having to propgate the lifetime parameter to `DapAbort`, we
        // encode it right away.
        agg_job_id_base64url: String,
    },

    /// Unauthorized HTTP request.
    #[error("unauthorizedRequest")]
    UnauthorizedRequest { detail: String, task_id: TaskId },

    /// Unrecognized aggregation job. Sent in response to an AggregateContinueReq for which the
    /// Helper does not recognize the indicated aggregation job.
    #[error("unrecognizedAggregationJob")]
    UnrecognizedAggregationJob {
        task_id: TaskId,
        // draft02 compatibility: The ID's definition (i.e., length in bytes) depends on which
        // protocol is in use, hence the need for the `MetaAggregationJobId` type for representing
        // the union of both To avoid having to propgate the lifetime parameter to `DapAbort`, we
        // encode it right away.
        agg_job_id_base64url: String,
    },

    /// Invalid message. Sent in response to a malformed or unexpected message.
    #[error("invalidMessage")]
    InvalidMessage {
        detail: String,
        task_id: Option<TaskId>,
    },

    /// Unrecognized DAP task. Sent in response to a request indicating an unrecognized task ID.
    #[error("unrecognizedTask")]
    UnrecognizedTask,
}

impl DapAbort {
    /// Construct a problem details JSON object for this abort. `url` is the URL to which the
    /// request was targeted and `task_id` is the associated `TaskID`.
    pub fn into_problem_details(self) -> ProblemDetails {
        let (title, typ) = self.title_and_type();
        let (task_id, detail, agg_job_id_base64url) = match self {
            Self::BatchInvalid { detail, task_id }
            | Self::InvalidTask { detail, task_id }
            | Self::BatchMismatch { detail, task_id }
            | Self::BatchOverlap { detail, task_id }
            | Self::InvalidBatchSize { detail, task_id }
            | Self::QueryMismatch { detail, task_id }
            | Self::UnauthorizedRequest { detail, task_id } => (Some(task_id), Some(detail), None),
            Self::MissingTaskId => (
                None,
                Some("A task ID must be specified in the query parameter of the request.".into()),
                None,
            ),
            Self::BadRequest(detail) | Self::ReportRejected { detail } => {
                (None, Some(detail), None)
            }
            Self::RoundMismatch {
                detail,
                task_id,
                agg_job_id_base64url,
            } => (Some(task_id), Some(detail), Some(agg_job_id_base64url)),
            Self::UnrecognizedAggregationJob {
                task_id,
                agg_job_id_base64url,
            } => (
                Some(task_id),
                Some("The request indicates an aggregation job that does not exist.".into()),
                Some(agg_job_id_base64url),
            ),
            Self::InvalidMessage { detail, task_id } => (task_id, Some(detail), None),
            Self::ReportTooLate | Self::UnrecognizedTask => (None, None, None),
        };

        ProblemDetails {
            typ,
            title,
            task_id: task_id.map(|id| id.to_base64url()),
            agg_job_id: agg_job_id_base64url,
            instance: None, // TODO interop: Implement as specified.
            detail,
        }
    }

    /// Abort due to unexpected value for HTTP content-type header.
    pub fn content_type<S>(req: &DapRequest<S>, expected: DapMediaType) -> Self {
        let want_str = expected
            .as_str_for_version(req.version)
            .expect("could not resolve content-type for expected media type");

        if let Some(got_str) = req.media_type.as_str_for_version(req.version) {
            Self::BadRequest(format!(
                "unexpected content-type: got {got_str}; want {want_str}"
            ))
        } else {
            Self::BadRequest(format!("missing content-type: expected {want_str}"))
        }
    }

    #[inline]
    pub(crate) fn version_mismatch(indicated: DapVersion, expected: DapVersion) -> Self {
        DapAbort::BadRequest(format!(
            "DAP version of request does not match task: got {indicated:?}; want {expected:?}"
        ))
    }

    #[inline]
    pub(crate) fn version_unknown() -> Self {
        DapAbort::BadRequest("DAP version of request is not recognized".into())
    }

    #[inline]
    pub(crate) fn batch_overlap(task_id: &TaskId, batch_sel: &BatchSelector) -> Self {
        Self::BatchOverlap {
            detail: format!(
                "The batch indicated by the request: {}",
                serde_json::to_string(batch_sel).expect("failed to JSON-encode the batch selector while constructing a \"batchOverlap\" abort"),
            ),
            task_id: *task_id,
        }
    }

    #[inline]
    pub(crate) fn query_mismatch(
        task_id: &TaskId,
        query_type_for_task: impl std::fmt::Display,
        query_type_for_request: impl std::fmt::Display,
    ) -> Self {
        Self::QueryMismatch {
            detail: format!("The task's query type is \"{query_type_for_task}\", but the request indicates \"{query_type_for_request}\"."),
            task_id: *task_id,
        }
    }

    #[inline]
    pub fn report_rejected(failure_reason: TransitionFailure) -> Result<Self, DapError> {
        let detail = match failure_reason {
            TransitionFailure::BatchCollected => {
                "The report pertains to a batch that has already been collected."
            }
            TransitionFailure::ReportReplayed => {
                "A report with the same ID was uploaded previously."
            }
            _ => {
                return Err(fatal_error!(
                    err = "Attempted to construct a \"reportRejected\" abort with unexpected transition failure",
                    unexpected_transition_failure = ?failure_reason,
                ))
            }
        };

        Ok(Self::ReportRejected {
            detail: detail.into(),
        })
    }

    fn title_and_type(&self) -> (String, Option<String>) {
        let (title, dap_abort_type) = match self {
            Self::BatchInvalid { .. } => ("Batch boundary check failed", Some(self.to_string())),
            Self::BatchMismatch { .. } => (
                "Aggregators disagree on the set of reports in the batch",
                Some(self.to_string()),
            ),
            Self::BatchOverlap { .. } => (
                "The selected batch overlaps with a previous batch",
                Some(self.to_string()),
            ),
            Self::InvalidBatchSize { .. } => ("Batch size is invalid", Some(self.to_string())),
            Self::InvalidTask { .. } => ("Opted out of Taskprov task", Some(self.to_string())),
            Self::QueryMismatch { .. } => {
                ("Query type does not match the task", Some(self.to_string()))
            }
            Self::RoundMismatch { .. } => (
                "Aggregation round indicated by peer does not match host",
                Some(self.to_string()),
            ),
            Self::MissingTaskId => (
                "Request for HPKE configuration with unspecified task",
                Some(self.to_string()),
            ),
            Self::ReportRejected { .. } => ("Report rejected", Some(self.to_string())),
            Self::ReportTooLate => (
                "The requested task expires after report timestamp",
                Some(self.to_string()),
            ),
            Self::UnauthorizedRequest { .. } => {
                ("Request authorization failed", Some(self.to_string()))
            }
            Self::UnrecognizedAggregationJob { .. } => {
                ("Unrecognized aggregation job", Some(self.to_string()))
            }
            Self::InvalidMessage { .. } => ("Malformed or invalid message", Some(self.to_string())),
            Self::UnrecognizedTask => (
                "Task indicated by request is not recognized",
                Some(self.to_string()),
            ),
            Self::BadRequest(..) => ("Bad request", None),
        };

        (
            title.to_string(),
            dap_abort_type.map(|t| format!("urn:ietf:params:ppm:dap:error:{t}")),
        )
    }
}

impl DapAbort {
    pub fn from_codec_error<Id: Into<Option<TaskId>>>(e: CodecError, task_id: Id) -> Self {
        Self::InvalidMessage {
            detail: format!("codec error: {e}"),
            task_id: task_id.into(),
        }
    }

    pub fn from_hex_error(e: FromHexError, task_id: TaskId) -> Self {
        Self::InvalidMessage {
            detail: format!("invalid hexadecimal string {e:?}"),
            task_id: Some(task_id),
        }
    }
}

/// A problem details document compatible with RFC 7807.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProblemDetails {
    pub title: String,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    #[serde(rename = "taskid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) task_id: Option<String>,

    #[serde(rename = "aggregationjobid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) agg_job_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) instance: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
