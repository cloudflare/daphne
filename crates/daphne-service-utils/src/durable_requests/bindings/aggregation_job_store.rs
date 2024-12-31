// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    aggregation_job_store_capnp::new_job_request,
    capnproto::{CapnprotoPayloadDecode, CapnprotoPayloadEncode},
    durable_requests::ObjectIdFrom,
};
use daphne::{
    messages::{AggregationJobId, TaskId},
    DapVersion,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

super::define_do_binding! {
    const BINDING = "AGGREGATION_JOB_STORE";

    enum Command {
        NewJob = "/new-job",
        ContainsJob = "/contains",
    }

    fn name((version, task_id): (DapVersion, &'n TaskId)) -> ObjectIdFrom {
        ObjectIdFrom::Name(format!("{version}/task/{task_id}"))
    }
}

#[derive(Debug)]
pub struct NewJobRequest<'h> {
    pub id: AggregationJobId,
    pub agg_job_hash: Cow<'h, [u8]>,
}

impl CapnprotoPayloadEncode for NewJobRequest<'_> {
    type Builder<'a> = new_job_request::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        self.id.encode_to_builder(builder.reborrow().init_id());
        builder.set_agg_job_hash(&self.agg_job_hash);
    }
}

impl CapnprotoPayloadDecode for NewJobRequest<'static> {
    type Reader<'a> = new_job_request::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            id: <_>::decode_from_reader(reader.get_id()?)?,
            agg_job_hash: reader.get_agg_job_hash()?.to_vec().into(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum NewJobResponse {
    Ok,
    /// Request would change an existing aggregation job's parameters.
    IllegalJobParameters,
}
