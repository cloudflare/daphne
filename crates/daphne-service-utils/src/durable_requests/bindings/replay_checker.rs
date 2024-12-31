// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    capnproto::{
        decode_list, encode_list, usize_to_capnp_len, CapnprotoPayloadDecode,
        CapnprotoPayloadEncode,
    },
    durable_requests::ObjectIdFrom,
    replay_checker_capnp::check_replays_for,
};
use daphne::messages::{AggregationJobId, ReportId, TaskId, Time};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet};

super::define_do_binding! {
    const BINDING = "REPLAY_CHECK_STORE";

    enum Command {
        Check = "/check",
    }

    fn name((task_id, epoch, shard): (&'n TaskId, Time, usize)) -> ObjectIdFrom {
        ObjectIdFrom::Name(format!("replay-checker/{task_id}/epoch/{epoch}/shard/{shard}"))
    }
}

pub struct Request<'s> {
    pub report_ids: Cow<'s, [ReportId]>,
    pub agg_job_id: AggregationJobId,
}

impl CapnprotoPayloadEncode for Request<'_> {
    type Builder<'a> = check_replays_for::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let Self {
            report_ids,
            agg_job_id,
        } = self;
        encode_list(
            report_ids.iter(),
            builder
                .reborrow()
                .init_reports(usize_to_capnp_len(report_ids.len())),
        );
        agg_job_id.encode_to_builder(builder.init_agg_job_id());
    }
}

impl CapnprotoPayloadDecode for Request<'static> {
    type Reader<'a> = check_replays_for::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            report_ids: decode_list::<ReportId, _, _>(reader.get_reports()?)?,
            agg_job_id: <_>::decode_from_reader(reader.get_agg_job_id()?)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub duplicates: HashSet<ReportId>,
}
