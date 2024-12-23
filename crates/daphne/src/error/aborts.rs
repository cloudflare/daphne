// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Definitions and tooling for DAP protocol aborts.

use crate::{
    constants::DapMediaType,
    fatal_error,
    messages::{AggregationJobId, ReportError, ReportId, TaskId},
    DapError, DapRequestMeta, DapVersion,
};
use prio::codec::CodecError;
use serde::{Deserialize, Serialize};

use super::FatalDapError;

// NOTE:
// The display implementation of this error is used for metrics, as such, it can't be changed to
// include field values
/// DAP aborts.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum DapAbort {
    /// Bad request. Sent in response to an HTTP request that couldn't be handled preoprly.
    #[error("bad request")]
    BadRequest(String),

    /// Invalid batch. Sent in response to a [`CollectionReq`](crate::messages::CollectionReq) or
    /// [`AggregateShareReq`](crate::messages::AggregateShareReq).
    #[error("batchInvalid")]
    BatchInvalid { detail: String, task_id: TaskId },

    /// Batch mismatch. Sent in response to an
    /// [`AggregateShareReq`](crate::messages::AggregateShareReq).
    #[error("batchMismatch")]
    BatchMismatch { detail: String, task_id: TaskId },

    /// Batch overlap. Sent in response to an [`CollectionReq`](crate::messages::CollectionReq) for which the Leader detects the same
    /// Collector requesting an aggregate share which it has collected in the past.
    #[error("batchOverlap")]
    BatchOverlap { detail: String, task_id: TaskId },

    /// Invalid batch size (either too small or too large). Sent in response to a `CollectReq` or
    /// `AggregateShareReq`.
    #[error("invalidBatchSize")]
    InvalidBatchSize { detail: String, task_id: TaskId },

    /// taskprov: Invalid DAP task. Sent when a server opts out of a taskprov task configuration.
    #[error("invalidTask")]
    InvalidTask { detail: String, task_id: TaskId },

    /// Request with missing task ID.
    #[error("missingTaskID")]
    MissingTaskId,

    /// Query mismatch. Sent in response to a [`CollectionReq`](crate::messages::CollectionReq) or
    /// [`AggregateShareReq`](crate::messages::AggregateShareReq).
    #[error("queryMismatch")]
    BatchModeMismatch { detail: String, task_id: TaskId },

    /// Report rejected. Sent in response to an upload request containing a Report that the Leader
    /// would reject during the aggregation sub-protocol.
    #[error("reportRejected")]
    ReportRejected { detail: String },

    /// Report too late. Sent in response to an upload request for a task that is known to have
    /// expired.
    #[error("reportTooLate")]
    ReportTooLate { report_id: ReportId },

    /// Round mismatch. The aggregators disagree on the current round of the VDAF preparation protocol.
    /// This abort occurs during the aggregation sub-protocol.
    #[error("roundMismatch")]
    RoundMismatch {
        detail: String,
        task_id: TaskId,
        agg_job_id: AggregationJobId,
    },

    /// Unauthorized HTTP request.
    #[error("unauthorizedRequest")]
    UnauthorizedRequest { detail: String, task_id: TaskId },

    /// Unrecognized aggregation job. Sent in response to an `AggregateContinueReq` for which the
    /// Helper does not recognize the indicated aggregation job.
    #[error("unrecognizedAggregationJob")]
    UnrecognizedAggregationJob {
        task_id: TaskId,
        agg_job_id: AggregationJobId,
    },

    /// Invalid message. Sent in response to a malformed or unexpected message.
    #[error("invalidMessage")]
    InvalidMessage { detail: String, task_id: TaskId },

    /// Unrecognized DAP task. Sent in response to a request indicating an unrecognized task ID.
    #[error("unrecognizedTask")]
    UnrecognizedTask { task_id: TaskId },

    /// Unsupported Extension. Sent in response to a report upload with an unsupported extension.
    #[error("unsupportedExtension")]
    UnsupportedExtension { detail: String, task_id: TaskId },
}

impl DapAbort {
    /// Construct a problem details JSON object for this abort. `url` is the URL to which the
    /// request was targeted and `task_id` is the associated `TaskID`.
    pub fn into_problem_details(self) -> ProblemDetails {
        let (title, typ) = self.title_and_type();
        let to_instance = |params| {
            format!(
                "/problem-details/{}?{params}",
                typ.as_deref().unwrap_or("badrequest"),
            )
        };
        let (task_id, detail, agg_job_id, instance) = match self {
            Self::BatchInvalid { detail, task_id }
            | Self::InvalidTask { detail, task_id }
            | Self::BatchMismatch { detail, task_id }
            | Self::BatchOverlap { detail, task_id }
            | Self::InvalidBatchSize { detail, task_id }
            | Self::BatchModeMismatch { detail, task_id }
            | Self::UnauthorizedRequest { detail, task_id }
            | Self::InvalidMessage { detail, task_id }
            | Self::UnsupportedExtension { detail, task_id } => (
                Some(task_id),
                Some(detail),
                None,
                to_instance(format_args!("task_id={task_id}")),
            ),
            Self::MissingTaskId => (
                None,
                Some("A task ID must be specified in the query parameter of the request.".into()),
                None,
                to_instance(format_args!("task_id=none")),
            ),
            Self::BadRequest(detail) | Self::ReportRejected { detail } => {
                (
                    None,
                    Some(detail),
                    None,
                    // TODO: make it possible to pass the rejected report id here.
                    to_instance(format_args!("report_id=not-implemented")),
                )
            }
            Self::RoundMismatch {
                detail,
                task_id,
                agg_job_id,
            } => (
                Some(task_id),
                Some(detail),
                Some(agg_job_id),
                to_instance(format_args!("task_id={task_id}&agg_job_id={agg_job_id}")),
            ),
            Self::UnrecognizedAggregationJob {
                task_id,
                agg_job_id,
            } => (
                Some(task_id),
                Some("The request indicates an aggregation job that does not exist.".into()),
                Some(agg_job_id),
                to_instance(format_args!("agg_job_id={agg_job_id}")),
            ),
            Self::ReportTooLate { report_id } => (
                None,
                Some("one of the reports' timestamp was too late".into()),
                None,
                to_instance(format_args!("report_id={report_id}")),
            ),
            Self::UnrecognizedTask { task_id } => (
                Some(task_id),
                None,
                None,
                to_instance(format_args!("task_id={task_id}")),
            ),
        };

        ProblemDetails {
            typ,
            title: title.to_string(),
            task_id,
            agg_job_id,
            instance,
            detail,
        }
    }

    /// Abort due to unexpected value for HTTP content-type header.
    pub fn content_type(req: &DapRequestMeta, expected: DapMediaType) -> Self {
        let want_content_type = expected.as_str_for_version(req.version).unwrap_or_else(|| {
            unreachable!("unexpected content-type for DAP version {:?}", req.version)
        });

        let Some(media_type) = req.media_type else {
            return Self::BadRequest("missing content-type".into());
        };

        let got_content_type = media_type
            .as_str_for_version(req.version)
            .unwrap_or_else(|| {
                unreachable!(
                    "missing or unexpected content type for DAP version {:?}",
                    req.version
                )
            });

        Self::BadRequest(format!(
            "unexpected content-type: got {got_content_type}; want {want_content_type}"
        ))
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
    pub(crate) fn batch_overlap(task_id: &TaskId, batch_sel: impl std::fmt::Display) -> Self {
        Self::BatchOverlap {
            detail: format!("The batch indicated by the request: {batch_sel}"),
            task_id: *task_id,
        }
    }

    #[inline]
    pub(crate) fn batch_mode_mismatch(
        task_id: &TaskId,
        batch_mode_for_task: impl std::fmt::Display,
        batch_mode_for_request: impl std::fmt::Display,
    ) -> Self {
        Self::BatchModeMismatch {
            detail: format!("The task's batch mode is \"{batch_mode_for_task}\", but the request indicates \"{batch_mode_for_request}\"."),
            task_id: *task_id,
        }
    }

    #[inline]
    pub fn report_rejected(failure_reason: ReportError) -> Result<Self, FatalDapError> {
        let detail = match failure_reason {
            ReportError::BatchCollected => {
                "The report pertains to a batch that has already been collected."
            }
            ReportError::ReportReplayed => "A report with the same ID was uploaded previously.",
            _ => {
                let DapError::Fatal(fatal) = fatal_error!(
                    err = "Attempted to construct a \"reportRejected\" abort with unexpected report error",
                    unexpected_report_error = ?failure_reason,
                ) else {
                    unreachable!("fatal_error! should always create a DapError::Fatal");
                };
                return Err(fatal);
            }
        };

        Ok(Self::ReportRejected {
            detail: detail.into(),
        })
    }

    pub fn unsupported_extension(
        task_id: &TaskId,
        unknown_extensions: &[u16],
    ) -> Result<Self, DapError> {
        Ok(Self::UnsupportedExtension {
            detail: format!("{unknown_extensions:?}"),
            task_id: *task_id,
        })
    }

    fn title_and_type(&self) -> (&'static str, Option<String>) {
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
            Self::BatchModeMismatch { .. } => {
                ("Batch Mode does not match the task", Some(self.to_string()))
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
            Self::ReportTooLate { .. } => (
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
            Self::UnrecognizedTask { .. } => (
                "Task indicated by request is not recognized",
                Some(self.to_string()),
            ),
            Self::BadRequest(..) => ("Bad request", None),
            Self::UnsupportedExtension { .. } => {
                ("Unsupported extensions in report", Some(self.to_string()))
            }
        };

        (
            title,
            dap_abort_type.map(|t| format!("urn:ietf:params:ppm:dap:error:{t}")),
        )
    }
}

impl DapAbort {
    pub fn from_codec_error(e: CodecError, task_id: TaskId) -> Self {
        Self::InvalidMessage {
            detail: format!("codec error: {e}"),
            task_id,
        }
    }
}

/// A problem details document compatible with RFC 7807.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProblemDetails {
    pub title: String,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub typ: Option<String>,

    #[serde(rename = "taskid")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) task_id: Option<TaskId>,

    #[serde(rename = "aggregationjobid")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) agg_job_id: Option<AggregationJobId>,

    pub(crate) instance: String,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

#[cfg(test)]
mod test {
    use crate::messages::{AggregationJobId, ReportId, TaskId};

    use super::{DapAbort, ProblemDetails};

    #[test]
    fn assert_that_instance_fields_are_url_safe() {
        let detail = String::from("detail");
        let task_id = TaskId(std::array::from_fn(|i| i.try_into().unwrap()));
        let report_id = ReportId(std::array::from_fn(|i| i.try_into().unwrap()));
        let agg_job_id = AggregationJobId(std::array::from_fn(|i| i.try_into().unwrap()));
        let errors = [
            DapAbort::BatchInvalid {
                detail: detail.clone(),
                task_id,
            },
            DapAbort::BatchMismatch {
                detail: detail.clone(),
                task_id,
            },
            DapAbort::BatchOverlap {
                detail: detail.clone(),
                task_id,
            },
            DapAbort::InvalidBatchSize {
                detail: detail.clone(),
                task_id,
            },
            DapAbort::InvalidTask {
                detail: detail.clone(),
                task_id,
            },
            DapAbort::MissingTaskId,
            DapAbort::BatchModeMismatch {
                detail: detail.clone(),
                task_id,
            },
            DapAbort::ReportRejected {
                detail: detail.clone(),
            },
            DapAbort::ReportTooLate { report_id },
            DapAbort::RoundMismatch {
                detail: detail.clone(),
                task_id,
                agg_job_id,
            },
            DapAbort::UnauthorizedRequest {
                detail: detail.clone(),
                task_id,
            },
            DapAbort::UnrecognizedAggregationJob {
                task_id,
                agg_job_id,
            },
            DapAbort::InvalidMessage {
                detail: detail.clone(),
                task_id,
            },
            DapAbort::UnrecognizedTask { task_id },
            DapAbort::BadRequest("bad-request".into()),
        ];

        for e in errors {
            let ProblemDetails { instance, .. } = e.into_problem_details();
            let instance_url = url::Url::parse(&format!("https://some-host.com{instance}"));
            assert!(instance_url.is_ok(), "{instance:?} is not url safe");
        }
    }
}
