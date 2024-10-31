// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::Deref;

use crate::{constants::DapMediaType, error::DapAbort, messages::TaskId, DapVersion};

pub mod resource {
    /// Aggregation job resource.
    pub use crate::messages::AggregationJobId;
    /// Collection job resource.
    pub use crate::messages::CollectionJobId;

    /// Undefined (or undetermined) resource.
    ///
    /// The resource of a DAP request is undefined if there is not a unique object (in the context
    /// of a DAP task) that the request pertains to. For example:
    ///
    ///   * The Client->Aggregator request for the HPKE config or to upload a report
    ///   * The Leader->Helper request for an aggregate share
    #[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Copy)]
    pub struct None;
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
    pub taskprov_advertisement: Option<String>,
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
///
/// # Type parameters
/// - `P`: is the payload of the request.
/// - `R`: is the resource id this request points to. Possible values of this are:
///     - [`AggregationJobId`](resource::AggregationJobId)
///     - [`CollectionJobId`](resource::CollectionJobId)
///     - [`None`](resource::None)
#[derive(Debug)]
#[cfg_attr(test, derive(Default))]
pub struct DapRequest<P, R = resource::None> {
    pub meta: DapRequestMeta,

    /// The resource with which this request is associated.
    pub resource_id: R,

    /// Request payload.
    pub payload: P,
}

impl<P, R> AsRef<DapRequestMeta> for DapRequest<P, R> {
    fn as_ref(&self) -> &DapRequestMeta {
        &self.meta
    }
}

impl<P, R> Deref for DapRequest<P, R> {
    type Target = DapRequestMeta;
    fn deref(&self) -> &Self::Target {
        &self.meta
    }
}

/// DAP response.
#[derive(Debug)]
pub struct DapResponse {
    pub version: DapVersion,
    pub media_type: DapMediaType,
    pub payload: Vec<u8>,
}
