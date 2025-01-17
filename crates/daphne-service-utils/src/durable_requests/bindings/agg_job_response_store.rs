// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::{
    messages::{AggregationJobId, ReadyAggregationJobResp, TaskId, Transition, TransitionVar},
    DapVersion,
};

use crate::{
    agg_job_response_store_capnp::aggregation_job_response,
    capnproto::{
        decode_list, encode_list, usize_to_capnp_len, CapnprotoPayloadDecode,
        CapnprotoPayloadEncode,
    },
    durable_requests::ObjectIdFrom,
};

super::define_do_binding! {
    const BINDING = "AGGREGATE_JOB_RESULT_STORE";
    enum Command {
        Get  = "/get",
        Put = "/put",
    }

    fn name(
        (version, task_id, agg_job_id):
        (DapVersion, &'n TaskId, &'n AggregationJobId)
    ) -> ObjectIdFrom {
        ObjectIdFrom::Name(format!("{version}/task/{task_id}/agg_job/{agg_job_id}"))
    }
}

impl CapnprotoPayloadEncode for ReadyAggregationJobResp {
    type Builder<'a> = aggregation_job_response::Builder<'a>;

    fn encode_to_builder(&self, builder: Self::Builder<'_>) {
        let Self { transitions } = self;
        encode_list(
            transitions,
            builder.init_transitions(usize_to_capnp_len(transitions.len())),
        );
    }
}

impl CapnprotoPayloadEncode for Transition {
    type Builder<'a> = aggregation_job_response::transition::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let Self { report_id, var } = self;
        report_id.encode_to_builder(builder.reborrow().init_report_id());
        let mut builder = builder.init_var();
        match var {
            TransitionVar::Continued(vec) => builder.set_continued(vec),
            TransitionVar::Failed(report_error) => builder.set_failed((*report_error).into()),
        }
    }
}

impl CapnprotoPayloadDecode for Transition {
    type Reader<'a> = aggregation_job_response::transition::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            report_id: <_>::decode_from_reader(reader.get_report_id()?)?,
            var: match reader.get_var()?.which()? {
                aggregation_job_response::transition_var::Which::Continued(data) => {
                    TransitionVar::Continued(data?.to_vec())
                }
                aggregation_job_response::transition_var::Which::Failed(report_error) => {
                    TransitionVar::Failed(report_error?.into())
                }
            },
        })
    }
}

impl CapnprotoPayloadDecode for ReadyAggregationJobResp {
    type Reader<'a> = aggregation_job_response::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            transitions: decode_list::<Transition, _, _>(reader.get_transitions()?)?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::capnproto::{CapnprotoPayloadDecodeExt as _, CapnprotoPayloadEncodeExt as _};
    use daphne::messages::ReportId;
    use rand::{thread_rng, Rng};

    fn gen_agg_job_resp() -> ReadyAggregationJobResp {
        ReadyAggregationJobResp {
            transitions: vec![
                Transition {
                    report_id: ReportId(thread_rng().gen()),
                    var: TransitionVar::Continued(vec![1, 2, 3]),
                },
                Transition {
                    report_id: ReportId(thread_rng().gen()),
                    var: TransitionVar::Failed(daphne::messages::ReportError::InvalidMessage),
                },
            ],
        }
    }

    #[test]
    fn serialization_deserialization_round_trip() {
        let this = gen_agg_job_resp();
        let other = ReadyAggregationJobResp::decode_from_bytes(&this.encode_to_bytes()).unwrap();
        assert_eq!(this, other);
    }
}
