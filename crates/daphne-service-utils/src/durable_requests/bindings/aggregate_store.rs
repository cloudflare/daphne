// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashSet;

use daphne::{
    messages::ReportId, vdaf::VdafAggregateShare, DapAggregateShare, DapBatchBucket, DapVersion,
};
use serde::{Deserialize, Serialize};

use crate::{
    durable_request_capnp::{aggregate_store_merge_req, dap_aggregate_share},
    durable_requests::ObjectIdFrom,
};

use super::DurableRequestPayload;

super::define_do_binding! {
    const BINDING = "DAP_AGGREGATE_STORE";
    enum AggregateStore {
        GetMerged = "/internal/do/aggregate_store/get_merged",
        Get = "/internal/do/aggregate_store/get",
        Merge = "/internal/do/aggregate_store/merge",
        MarkCollected = "/internal/do/aggregate_store/mark_collected",
        CheckCollected = "/internal/do/aggregate_store/check_collected",
    }

    fn name((version, task_id_hex, bucket): (DapVersion, &'n str, &'n DapBatchBucket)) -> ObjectIdFrom {
        fn durable_name_bucket(bucket: &DapBatchBucket) -> String {
            format!("{bucket}")
        }
        ObjectIdFrom::Name(format!(
            "{}/{}",
            durable_name_task(version, task_id_hex),
            durable_name_bucket(bucket),
        ))
    }
}

fn durable_name_task(version: DapVersion, task_id_hex: &str) -> String {
    format!("{}/task/{}", version.as_ref(), task_id_hex)
}

#[derive(Debug, PartialEq, Eq)]
// TODO(mendess): delete. Only here to suport deserialization with bincode for backwards
// compatibility.
#[derive(serde::Deserialize)]
pub struct AggregateStoreMergeReq {
    pub contained_reports: Vec<ReportId>,
    pub agg_share_delta: DapAggregateShare,
    pub options: AggregateStoreMergeOptions,
}

#[derive(Debug, PartialEq, Eq)]
// TODO(mendess): delete. Only here to suport deserialization with bincode for backwards
// compatibility.
#[derive(serde::Deserialize)]
pub struct AggregateStoreMergeOptions {
    /// Note:
    /// - privacy is degraded when this is enabled.
    /// - it's intended to be used in an incident and needs to be re-enabled after the incident is
    ///   mitigated.
    pub skip_replay_protection: bool,
}

impl DurableRequestPayload for AggregateStoreMergeReq {
    fn encode_to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let Self {
            contained_reports,
            agg_share_delta,
            options,
        } = self;
        let mut message = capnp::message::Builder::new_default();
        let mut request = message.init_root::<aggregate_store_merge_req::Builder>();
        {
            let mut contained_reports = request.reborrow().init_contained_reports(
                contained_reports
                    .len()
                    .try_into()
                    .expect("can't serialize more than u32::MAX reports"),
            );
            for (i, r) in self.contained_reports.iter().enumerate() {
                let mut report = contained_reports.reborrow().get(i.try_into().unwrap());
                let bytes: &[u8; 16] = r.as_ref();
                let low = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                report.set_low(low);
                let high = u64::from_le_bytes(bytes[8..].try_into().unwrap());
                report.set_high(high);
            }
        }
        {
            let mut agg_share_delta_packet = request.reborrow().init_agg_share_delta();
            agg_share_delta_packet.set_report_count(agg_share_delta.report_count);
            agg_share_delta_packet.set_min_time(agg_share_delta.min_time);
            agg_share_delta_packet.set_max_time(agg_share_delta.max_time);
            {
                let checksum = agg_share_delta_packet
                    .reborrow()
                    .init_checksum(agg_share_delta.checksum.len().try_into().unwrap());
                checksum.copy_from_slice(&agg_share_delta.checksum);
            }
            {
                fn encode<'b, F, B, const ENCODED_SIZE: usize>(
                    field: &prio::vdaf::AggregateShare<F>,
                    get_bytes: B,
                ) where
                    F: prio::field::FieldElement + Into<[u8; ENCODED_SIZE]>,
                    B: FnOnce(u32) -> &'b mut [u8],
                {
                    let mut bytes = get_bytes(
                        (F::ENCODED_SIZE * field.as_ref().len())
                            .try_into()
                            .expect("trying to encode a buffer longer than u32::MAX"),
                    );
                    for f in field.as_ref() {
                        let f: [u8; ENCODED_SIZE] = (*f).into();
                        bytes[..ENCODED_SIZE].copy_from_slice(&f);
                        bytes = &mut bytes[ENCODED_SIZE..];
                    }
                }
                let mut data = agg_share_delta_packet.init_data();
                match &self.agg_share_delta.data {
                    Some(VdafAggregateShare::Field64(field)) => {
                        encode(field, |len| data.init_field64(len));
                    }
                    Some(VdafAggregateShare::Field128(field)) => {
                        encode(field, |len| data.init_field128(len));
                    }
                    Some(VdafAggregateShare::Field32(field)) => {
                        encode(field, |len| data.init_field_prio2(len));
                    }
                    None => data.set_none(()),
                };
            }
        }
        {
            let AggregateStoreMergeOptions {
                skip_replay_protection,
            } = options;
            let mut options_packet = request.init_options();
            options_packet.set_skip_replay_protection(*skip_replay_protection);
        }
        message
    }

    fn decode_from_reader(
        reader: capnp::message::Reader<capnp::serialize::OwnedSegments>,
    ) -> capnp::Result<Self> {
        let request = reader.get_root::<aggregate_store_merge_req::Reader>()?;
        let agg_share_delta = {
            let agg_share_delta = request.get_agg_share_delta()?;
            let data = {
                fn decode<F>(fields: &[u8]) -> capnp::Result<prio::vdaf::AggregateShare<F>>
                where
                    F: prio::field::FieldElement
                        + for<'s> TryFrom<&'s [u8], Error = prio::field::FieldError>,
                {
                    let iter = fields.chunks_exact(F::ENCODED_SIZE);
                    if let length @ 1.. = iter.remainder().len() {
                        return Err(capnp::Error {
                            kind: capnp::ErrorKind::Failed,
                            extra: format!("leftover bytes still present in buffer: {length}"),
                        });
                    }
                    Ok(prio::vdaf::AggregateShare::from(
                        iter.map(|f| f.try_into().unwrap()).collect::<Vec<_>>(),
                    ))
                }
                match agg_share_delta.get_data().which()? {
                    dap_aggregate_share::data::Which::Field64(field) => {
                        Some(VdafAggregateShare::Field64(decode(field?)?))
                    }
                    dap_aggregate_share::data::Which::Field128(field) => {
                        Some(VdafAggregateShare::Field128(decode(field?)?))
                    }
                    dap_aggregate_share::data::Which::FieldPrio2(field) => {
                        Some(VdafAggregateShare::Field32(decode(field?)?))
                    }
                    dap_aggregate_share::data::Which::None(()) => None,
                }
            };
            DapAggregateShare {
                report_count: agg_share_delta.get_report_count(),
                min_time: agg_share_delta.get_min_time(),
                max_time: agg_share_delta.get_max_time(),
                checksum: agg_share_delta
                    .get_checksum()?
                    .try_into()
                    .map_err(|_| capnp::Error {
                        kind: capnp::ErrorKind::Failed,
                        extra: "checksum had unexpected size".into(),
                    })?,
                data,
            }
        };
        let contained_reports = {
            request
                .reborrow()
                .get_contained_reports()?
                .into_iter()
                .map(|report| {
                    let low = report.get_low();
                    let high = report.get_high();

                    let mut buffer = [0; 16];
                    buffer[..8].copy_from_slice(&low.to_le_bytes());
                    buffer[8..].copy_from_slice(&high.to_le_bytes());
                    ReportId(buffer)
                })
                .collect()
        };
        Ok(Self {
            contained_reports,
            agg_share_delta,
            options: AggregateStoreMergeOptions {
                skip_replay_protection: request.get_options()?.get_skip_replay_protection(),
            },
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AggregateStoreMergeResp {
    Ok,
    ReplaysDetected(HashSet<ReportId>),
    AlreadyCollected,
}

#[cfg(test)]
mod test {
    use prio::{
        codec::Decode,
        field::{Field128, Field64, FieldElement, FieldPrio2},
        vdaf::AggregateShare,
    };
    use rand::{thread_rng, Rng};

    use crate::durable_requests::bindings::DurableRequestPayloadExt;

    use super::*;

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
            for (i, data) in test_data.enumerate() {
                let this = AggregateStoreMergeReq {
                    contained_reports: (0..len)
                        .map(|_| ReportId::get_decoded(&rng.gen::<[_; 16]>()).unwrap())
                        .collect(),
                    agg_share_delta: DapAggregateShare {
                        report_count: rng.gen(),
                        min_time: rng.gen(),
                        max_time: rng.gen(),
                        checksum: rng.gen(),
                        data,
                    },
                    options: AggregateStoreMergeOptions {
                        skip_replay_protection: i % 2 == 0,
                    },
                };
                let other =
                    AggregateStoreMergeReq::decode_from_bytes(&this.encode_to_bytes().unwrap())
                        .unwrap();
                assert_eq!(this, other);
            }
        }
    }
}
