// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    aggregation_job_store_capnp::new_job_request,
    capnproto::{CapnprotoPayloadDecode, CapnprotoPayloadEncode},
    durable_requests::ObjectIdFrom,
};
use daphne::{
    messages::{AggregationJobId, AggregationJobInitReq, PartialBatchSelector, TaskId},
    DapVersion,
};
use serde::{Deserialize, Serialize};
use std::{ops::Deref, slice};

super::define_do_binding! {
    const BINDING = "AGGREGATION_JOB_STORE";

    enum Command {
        NewJob = "/new-job",
        ListJobIds = "/job-ids",
    }

    fn name((version, task_id): (DapVersion, &'n TaskId)) -> ObjectIdFrom {
        ObjectIdFrom::Name(format!("{version}/task/{task_id}"))
    }
}

#[derive(Debug)]
pub struct AggregationJobReqHash(Vec<u8>);

impl Deref for AggregationJobReqHash {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&AggregationJobInitReq> for AggregationJobReqHash {
    fn from(req: &AggregationJobInitReq) -> Self {
        let AggregationJobInitReq {
            agg_param,
            part_batch_sel,
            prep_inits,
        } = req;

        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        context.update(agg_param);
        context.update(match part_batch_sel {
            PartialBatchSelector::TimeInterval => &[0],
            PartialBatchSelector::LeaderSelectedByBatchId { batch_id } => batch_id.as_ref(),
        });
        for p in prep_inits {
            let daphne::messages::PrepareInit {
                report_share:
                    daphne::messages::ReportShare {
                        report_metadata: daphne::messages::ReportMetadata { id, time },
                        public_share,
                        encrypted_input_share:
                            daphne::messages::HpkeCiphertext {
                                config_id,
                                enc,
                                payload: cypher_text_payload,
                            },
                    },
                payload,
            } = p;

            context.update(payload);
            context.update(public_share);
            context.update(id.as_ref());
            context.update(&time.to_be_bytes());
            context.update(cypher_text_payload);
            context.update(slice::from_ref(config_id));
            context.update(enc);
        }
        Self(context.finish().as_ref().to_vec())
    }
}

#[derive(Debug)]
pub struct NewJobRequest {
    pub id: AggregationJobId,
    pub agg_job_hash: AggregationJobReqHash,
}

impl CapnprotoPayloadEncode for NewJobRequest {
    type Builder<'a> = new_job_request::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        self.id.encode_to_builder(builder.reborrow().init_id());
        builder.set_agg_job_hash(&self.agg_job_hash.0);
    }
}

impl CapnprotoPayloadDecode for NewJobRequest {
    type Reader<'a> = new_job_request::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            id: <_>::decode_from_reader(reader.get_id()?)?,
            agg_job_hash: AggregationJobReqHash(reader.get_agg_job_hash()?.to_vec()),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum NewJobResponse {
    Ok,
    /// Request would change an existing aggregation job's parameters.
    IllegalJobParameters,
}
