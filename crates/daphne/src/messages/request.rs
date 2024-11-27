// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::Deref;

use super::{
    taskprov::TaskprovAdvertisement, AggregateShareReq, AggregationJobId, AggregationJobInitReq,
    CollectionJobId, CollectionReq, Report,
};
use crate::{constants::DapMediaType, error::DapAbort, messages::TaskId, DapVersion};

pub trait RequestBody {
    type ResourceId;
}

/// A poll request has no body, but requires a `CollectionJobId`.
pub struct CollectionPollReq;

macro_rules! impl_req_body {
    ($($body:tt | $id:tt)*) => {
        $(impl RequestBody for $body {
                type ResourceId = $id;
        })*
    };
}

impl_req_body! {
//  body type             | id type
//  --------------------- | ----------------
    Report                | ()
    AggregationJobInitReq | AggregationJobId
    AggregateShareReq     | ()
    CollectionReq         | CollectionJobId
    CollectionPollReq     | CollectionJobId
    ()                    | ()
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
    pub taskprov_advertisement: Option<TaskprovAdvertisement>,
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
pub struct DapRequest<B: RequestBody> {
    pub meta: DapRequestMeta,

    /// The resource with which this request is associated.
    pub resource_id: B::ResourceId,

    /// Request payload.
    pub payload: B,
}

impl<B: RequestBody> AsRef<DapRequestMeta> for DapRequest<B> {
    fn as_ref(&self) -> &DapRequestMeta {
        &self.meta
    }
}

impl<B: RequestBody> Deref for DapRequest<B> {
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
