// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::Deref;

use super::{
    taskprov::TaskprovAdvertisement, AggregateShareReq, AggregationJobId, AggregationJobInitReq,
    CollectionJobId, CollectionReq, Report,
};
use crate::{constants::DapMediaType, error::DapAbort, messages::TaskId, DapVersion};
use prio::codec::{ParameterizedDecode, ParameterizedEncode};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "test-utils"), derive(deepsize::DeepSizeOf))]
pub struct AggregationJobRequestHash(Vec<u8>);

impl AggregationJobRequestHash {
    pub fn get(&self) -> &[u8] {
        &self.0
    }

    fn hash(bytes: &[u8]) -> Self {
        Self(
            ring::digest::digest(&ring::digest::SHA256, bytes)
                .as_ref()
                .to_vec(),
        )
    }
}

pub struct HashedAggregationJobReq {
    pub request: AggregationJobInitReq,
    pub hash: AggregationJobRequestHash,
}

impl HashedAggregationJobReq {
    #[cfg(any(test, feature = "test-utils"))]
    pub fn from_aggregation_req(version: DapVersion, request: AggregationJobInitReq) -> Self {
        let mut buf = Vec::new();
        request.encode_with_param(&version, &mut buf).unwrap();
        Self {
            request,
            hash: AggregationJobRequestHash::hash(&buf),
        }
    }
}

impl ParameterizedEncode<DapVersion> for HashedAggregationJobReq {
    fn encode_with_param(
        &self,
        encoding_parameter: &DapVersion,
        bytes: &mut Vec<u8>,
    ) -> Result<(), prio::codec::CodecError> {
        self.request.encode_with_param(encoding_parameter, bytes)
    }
}

impl ParameterizedDecode<DapVersion> for HashedAggregationJobReq {
    fn decode_with_param(
        decoding_parameter: &DapVersion,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, prio::codec::CodecError> {
        let start = usize::try_from(bytes.position())
            .map_err(|e| prio::codec::CodecError::Other(Box::new(e)))?;
        let request = AggregationJobInitReq::decode_with_param(decoding_parameter, bytes)?;
        let end = usize::try_from(bytes.position())
            .map_err(|e| prio::codec::CodecError::Other(Box::new(e)))?;

        Ok(Self {
            request,
            hash: AggregationJobRequestHash::hash(&bytes.get_ref()[start..end]),
        })
    }
}

impl_req_body! {
    //  body type           | id type
    //  --------------------| ----------------
    Report                  | ()
    AggregationJobInitReq   | AggregationJobId
    HashedAggregationJobReq | AggregationJobId
    AggregateShareReq       | ()
    CollectionReq           | CollectionJobId
    CollectionPollReq       | CollectionJobId
    ()                      | ()
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

impl<B: RequestBody> DapRequest<B> {
    pub fn map<F, O>(self, mapper: F) -> DapRequest<O>
    where
        F: FnOnce(B) -> O,
        O: RequestBody<ResourceId = B::ResourceId>,
    {
        DapRequest {
            meta: self.meta,
            resource_id: self.resource_id,
            payload: mapper(self.payload),
        }
    }
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
