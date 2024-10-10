// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::Deref;

use crate::{
    constants::DapMediaType,
    error::DapAbort,
    messages::{AggregationJobId, CollectionJobId, TaskId},
    DapVersion,
};

/// Types of resources associated with DAP tasks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DapResource {
    /// Aggregation job resource.
    AggregationJob(AggregationJobId),

    /// Collection job resource.
    CollectionJob(CollectionJobId),

    /// Undefined (or undetermined) resource.
    ///
    /// The resource of a DAP request is undefined if there is not a unique object (in the context
    /// of a DAP task) that the request pertains to. For example:
    ///
    ///   * The Client->Aggregator request for the HPKE config or to upload a report
    ///   * The Leader->Helper request for an aggregate share
    ///
    /// The resource of a DAP request is undetermined if its identifier could not be parsed from
    /// request path.
    #[default]
    Undefined,
}

/// Fields common to all DAP requests.
#[derive(Debug)]
#[cfg_attr(test, derive(Default))]
pub struct DapRequestMeta {
    /// Protocol version indicated by the request.
    pub version: DapVersion,

    /// Request media type, sent in the "content-type" header of the HTTP request.
    pub media_type: Option<DapMediaType>,

    /// ID of the task with which the request is associated.
    pub task_id: TaskId,

    /// taskprov: The task advertisement, sent in the `dap-taskprov` header.
    pub taskprov: Option<String>,

    /// The resource with which this request is associated.
    pub resource: DapResource,
}

impl DapRequestMeta {
    /// Checks the request content type against the expected content type.
    pub fn get_checked_media_type(&self, expected: DapMediaType) -> Result<DapMediaType, DapAbort> {
        self.media_type
            .filter(|m| *m == expected)
            .ok_or_else(|| DapAbort::content_type(self, expected))
    }
}

/// DAP request.
#[derive(Debug)]
#[cfg_attr(test, derive(Default))]
pub struct DapRequest<P> {
    pub meta: DapRequestMeta,

    /// Request payload.
    pub payload: P,
}

impl<P> AsRef<DapRequestMeta> for DapRequest<P> {
    fn as_ref(&self) -> &DapRequestMeta {
        &self.meta
    }
}

impl<P> Deref for DapRequest<P> {
    type Target = DapRequestMeta;
    fn deref(&self) -> &Self::Target {
        &self.meta
    }
}

impl<P> DapRequest<P> {
    /// Return the collection job ID, handling a missing ID as a user error.
    pub fn collection_job_id(&self) -> Result<&CollectionJobId, DapAbort> {
        if let DapResource::CollectionJob(collection_job_id) = &self.resource {
            Ok(collection_job_id)
        } else {
            Err(DapAbort::BadRequest(
                "missing or malformed collection job ID".into(),
            ))
        }
    }
}

/// DAP response.
#[derive(Debug)]
pub struct DapResponse {
    pub version: DapVersion,
    pub media_type: DapMediaType,
    pub payload: Vec<u8>,
}
