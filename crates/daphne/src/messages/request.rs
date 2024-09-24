// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    constants::DapMediaType,
    error::DapAbort,
    messages::{AggregationJobId, CollectionJobId, TaskId},
    DapSender, DapVersion,
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

/// DAP request.
#[derive(Debug)]
pub struct DapRequest {
    /// Protocol version indicated by the request.
    pub version: DapVersion,

    /// Request media type, sent in the "content-type" header of the HTTP request.
    pub media_type: Option<DapMediaType>,

    /// ID of the task with which the request is associated.
    pub task_id: TaskId,

    /// The resource with which this request is associated.
    pub resource: DapResource,

    /// Request payload.
    pub payload: Vec<u8>,

    /// taskprov: The task advertisement, sent in the `dap-taskprov` header.
    pub taskprov: Option<String>,
}

#[cfg(test)]
impl Default for DapRequest {
    fn default() -> Self {
        Self {
            version: DapVersion::Draft09,
            media_type: None,
            task_id: Default::default(),
            resource: Default::default(),
            payload: Default::default(),
            taskprov: Default::default(),
        }
    }
}

impl DapRequest {
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

    pub fn sender(&self) -> Option<DapSender> {
        self.media_type.map(|m| m.sender())
    }
}

/// DAP response.
#[derive(Debug)]
pub struct DapResponse {
    pub version: DapVersion,
    pub media_type: DapMediaType,
    pub payload: Vec<u8>,
}
