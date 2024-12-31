// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::{
    messages::{AggregationJobId, TaskId},
    DapAggregateShare, DapBatchBucket, DapVersion,
};

use crate::{
    aggregate_store_v2_capnp,
    capnproto::{CapnprotoPayloadDecode, CapnprotoPayloadEncode},
    durable_requests::ObjectIdFrom,
};

super::define_do_binding! {
    const BINDING = "AGGREGATE_STORE";
    enum Command {
        Get = "/get",
        Put = "/put",
        MarkCollected = "/mark-collected",
        CheckCollected = "/check-collected",
        AggregateShareCount = "/aggregate-share-count",
    }

    fn name(
        (version, task_id, bucket):
        (DapVersion, &'n TaskId, &'n DapBatchBucket)
    ) -> ObjectIdFrom {
        ObjectIdFrom::Name(format!("{version}/task/{task_id}/batch_bucket/{bucket}"))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PutRequest {
    pub agg_share_delta: DapAggregateShare,
    pub agg_job_id: AggregationJobId,
}

impl CapnprotoPayloadEncode for PutRequest {
    type Builder<'a> = aggregate_store_v2_capnp::put_request::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        let Self {
            agg_share_delta,
            agg_job_id,
        } = self;
        agg_share_delta.encode_to_builder(builder.reborrow().init_agg_share_delta());
        agg_job_id.encode_to_builder(builder.reborrow().init_agg_job_id());
    }
}

impl CapnprotoPayloadDecode for PutRequest {
    type Reader<'a> = aggregate_store_v2_capnp::put_request::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self> {
        Ok(Self {
            agg_share_delta: <_>::decode_from_reader(reader.get_agg_share_delta()?)?,
            agg_job_id: <_>::decode_from_reader(reader.get_agg_job_id()?)?,
        })
    }
}

#[cfg(test)]
mod test {
    use prio::{
        codec::Decode,
        field::{Field128, Field64, FieldElement, FieldPrio2},
        vdaf::AggregateShare,
    };
    use prio_draft09::vdaf::AggregateShare as AggregateShareDraft09;
    use rand::{thread_rng, Rng};

    use crate::capnproto::{CapnprotoPayloadDecodeExt as _, CapnprotoPayloadEncodeExt as _};

    use super::*;
    use daphne::vdaf::VdafAggregateShare;

    #[test]
    fn serialization_deserialization_round_trip_draft09() {
        let mut rng = thread_rng();
        for len in 0..20 {
            let test_data = [
                VdafAggregateShare::Field64Draft09(AggregateShareDraft09::from(
                    prio_draft09::field::random_vector(len).unwrap(),
                )),
                VdafAggregateShare::Field128Draft09(AggregateShareDraft09::from(
                    prio_draft09::field::random_vector(len).unwrap(),
                )),
                VdafAggregateShare::Field32Draft09(AggregateShareDraft09::from(
                    prio_draft09::field::random_vector(len).unwrap(),
                )),
            ]
            .map(Some)
            .into_iter()
            .chain([None]);
            for data in test_data {
                let this = PutRequest {
                    agg_job_id: AggregationJobId(rng.gen()),
                    agg_share_delta: DapAggregateShare {
                        report_count: rng.gen(),
                        min_time: rng.gen(),
                        max_time: rng.gen(),
                        checksum: rng.gen(),
                        data,
                    },
                };
                let other = PutRequest::decode_from_bytes(&this.encode_to_bytes()).unwrap();
                assert_eq!(this, other);
            }
        }
    }

    #[test]
    fn serialization_deserialization_round_trip() {
        let mut rng = thread_rng();
        for len in 0..20 {
            let test_data = [
                VdafAggregateShare::Field64(AggregateShare::from(
                    (0..len)
                        .map(|_| {
                            Field64::get_decoded(&rng.gen::<[_; Field64::ENCODED_SIZE]>()).unwrap()
                        })
                        .collect::<Vec<_>>(),
                )),
                VdafAggregateShare::Field128(AggregateShare::from(
                    (0..len)
                        .map(|_| {
                            Field128::get_decoded(&rng.gen::<[_; Field128::ENCODED_SIZE]>())
                                .unwrap()
                        })
                        .collect::<Vec<_>>(),
                )),
                VdafAggregateShare::Field32(AggregateShare::from(
                    (0..len)
                        .map(|_| {
                            // idk how to consistently generate a valid FieldPrio2 value, so I just
                            // retry until I hit a valid one. Doesn't usualy take too long.
                            (0..)
                                .find_map(|_| FieldPrio2::get_decoded(&rng.gen::<[_; 4]>()).ok())
                                .unwrap()
                        })
                        .collect::<Vec<_>>(),
                )),
            ]
            .map(Some)
            .into_iter()
            .chain([None]);
            for data in test_data {
                let this = PutRequest {
                    agg_job_id: AggregationJobId(rng.gen()),
                    agg_share_delta: DapAggregateShare {
                        report_count: rng.gen(),
                        min_time: rng.gen(),
                        max_time: rng.gen(),
                        checksum: rng.gen(),
                        data,
                    },
                };
                let other = PutRequest::decode_from_bytes(&this.encode_to_bytes()).unwrap();
                assert_eq!(this, other);
            }
        }
    }
}
