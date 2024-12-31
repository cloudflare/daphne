// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::{
    messages::{AggregationJobId, PrepareResp, PrepareRespVar, TaskId},
    protocol::ReadyAggregationJobResp,
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
        let Self { prep_resps } = self;
        encode_list(
            prep_resps,
            builder.init_prep_resps(usize_to_capnp_len(prep_resps.len())),
        );
    }
}

impl CapnprotoPayloadEncode for PrepareResp {
    type Builder<'a> = aggregation_job_response::prepare_resp::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let Self { report_id, var } = self;
        report_id.encode_to_builder(builder.reborrow().init_report_id());
        let mut builder = builder.init_var();
        match var {
            PrepareRespVar::Continue(vec) => builder.set_continue(vec),
            PrepareRespVar::Reject(report_error) => builder.set_reject((*report_error).into()),
        }
    }
}

impl CapnprotoPayloadDecode for PrepareResp {
    type Reader<'a> = aggregation_job_response::prepare_resp::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            report_id: <_>::decode_from_reader(reader.get_report_id()?)?,
            var: match reader.get_var()?.which()? {
                aggregation_job_response::prepare_resp_var::Which::Continue(data) => {
                    PrepareRespVar::Continue(data?.to_vec())
                }
                aggregation_job_response::prepare_resp_var::Which::Reject(report_error) => {
                    PrepareRespVar::Reject(report_error?.into())
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
            prep_resps: decode_list::<PrepareResp, _, _>(reader.get_prep_resps()?)?,
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
            prep_resps: vec![
                PrepareResp {
                    report_id: ReportId(thread_rng().gen()),
                    var: PrepareRespVar::Continue(vec![1, 2, 3]),
                },
                PrepareResp {
                    report_id: ReportId(thread_rng().gen()),
                    var: PrepareRespVar::Reject(daphne::messages::ReportError::InvalidMessage),
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
