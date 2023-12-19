// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This module defines the durable objects' binding and methods as implementors of the
//! [`DurableMethod`] trait.
//!
//! It also defines types that are used as the body of requests sent to these objects.

use std::collections::HashSet;

use daphne::{
    messages::{BatchId, CollectionJobId, CollectionReq, Duration, ReportId, TaskId, Time},
    DapAggregateShare, DapBatchBucket, DapTaskConfig, DapVersion, MetaAggregationJobId,
};
use serde::{Deserialize, Serialize};

use super::ObjectIdFrom;

/// A durable object method.
pub trait DurableMethod {
    /// The binding of the object this method belongs to as configured in the wrangler.toml
    const BINDING: &'static str;

    type NameParameters<'n>;

    /// Try to parse a uri into one of methods of this object.
    fn try_from_uri(s: &str) -> Option<Self>
    where
        Self: Sized;

    /// Convert this method into a uri.
    fn to_uri(&self) -> &'static str;

    /// Generate the durable object name
    fn name(params: Self::NameParameters<'_>) -> ObjectIdFrom;
}

macro_rules! define_do_binding {
    (
        const BINDING = $binding:literal;
        enum $name:ident {
            $($op:ident = $route:literal),*$(,)?
        }

        fn name($params:tt : $params_ty:ty) -> ObjectIdFrom $name_impl:block

    ) => {
        #[derive(
            serde::Serialize,
            serde::Deserialize,
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash
        )]
        pub enum $name {
            $($op),*
        }

        impl DurableMethod for $name {
            const BINDING: &'static str = $binding;

            type NameParameters<'n> = $params_ty;

            fn try_from_uri(s: &str) -> Option<Self> {
                match (s) {
                    $($route => Some(Self::$op),)*
                    _ => return None,
                }
            }

            fn to_uri(&self) -> &'static str {
                match self {
                    $(Self::$op => $route,)*
                }
            }

            fn name($params: Self::NameParameters<'_>) -> ObjectIdFrom {
                $name_impl
            }
        }
    };
}

define_do_binding! {
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
            match bucket {
                DapBatchBucket::TimeInterval { batch_window } => {
                    format!("window/{batch_window}")
                }
                DapBatchBucket::FixedSize { batch_id } => {
                    format!("batch/{}", batch_id.to_hex())
                }
            }
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

#[derive(Serialize, Deserialize, Debug)]
pub struct AggregateStoreMergeReq {
    pub contained_reports: Vec<ReportId>,
    pub agg_share_delta: DapAggregateShare,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AggregateStoreMergeResp {
    Ok,
    ReplaysDetected(HashSet<ReportId>),
    AlreadyCollected,
}

define_do_binding! {
    const BINDING = "DAP_GARBAGE_COLLECTOR";
    enum GarbageCollector {
        Put = "/internal/do/garbage_collector/put",
        DeleteAll = "/internal/do/delete_all",
    }

    fn name(_: ()) -> ObjectIdFrom {
        ObjectIdFrom::Name(Self::NAME_STR.into())
    }
}

impl GarbageCollector {
    pub const NAME_STR: &'static str = "garbage_collector";
}

define_do_binding! {
    const BINDING = "DAP_HELPER_STATE_STORE";
    enum HelperState {
        PutIfNotExists = "/internal/do/helper_state/put_if_not_exists",
        Get = "/internal/do/helper_state/get",
    }

    fn name((version, task_id, agg_job_id): (DapVersion, &'n TaskId, &'n MetaAggregationJobId)) -> ObjectIdFrom {
        ObjectIdFrom::Name(format!(
            "{}/task/{}/agg_job/{}",
            version.as_ref(),
            task_id.to_hex(),
            agg_job_id.to_hex()
        ))
    }

}

define_do_binding! {
    const BINDING = "DAP_LEADER_AGG_JOB_QUEUE";
    enum LeaderAggJobQueue {
        Put = "/internal/do/agg_job_queue/put",
        Get = "/internal/do/agg_job_queue/get",
        Finish = "/internal/do/agg_job_queue/finish",
    }

    fn name(shard: u64) -> ObjectIdFrom {
        ObjectIdFrom::Name(format!("queue/{shard}"))
    }
}

define_do_binding! {
    const BINDING = "DAP_LEADER_BATCH_QUEUE";
    enum LeaderBatchQueue {
        Assign = "/internal/do/leader_batch_queue/assign",
        Current = "/internal/do/leader_batch_queue/current",
        Remove = "/internal/do/leader_batch_queue/remove",
    }

    fn name((version, task_id_hex): (DapVersion, &'n str)) -> ObjectIdFrom {
        ObjectIdFrom::Name(format!("{}/task/{}", version.as_ref(), task_id_hex))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderBatchQueueResult {
    Ok(BatchId),
    EmptyQueue,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct BatchCount {
    pub batch_id: BatchId,
    pub report_count: usize,
}

define_do_binding! {
    const BINDING = "DAP_LEADER_COL_JOB_QUEUE";
    enum LeaderColJobQueue {
        Put = "/internal/do/leader_col_job_queue/put",
        Get = "/internal/do/leader_col_job_queue/get",
        Finish = "/internal/do/leader_col_job_queue/finish",
        GetResult = "/internal/do/leader_col_job_queue/get_result",
    }

    fn name(shard: u64) -> ObjectIdFrom {
        LeaderAggJobQueue::name(shard)
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct CollectQueueRequest {
    pub collect_req: CollectionReq,
    pub task_id: TaskId,
    pub collect_job_id: Option<CollectionJobId>,
}

define_do_binding! {
    const BINDING = "DAP_REPORTS_PENDING";
    enum ReportsPending {
        Get = "/internal/do/reports_pending/get",
        Put = "/internal/do/reports_pending/put",
    }

    fn name(
        (
            task_config,
            task_id_hex,
            report_id,
            report_time,
            report_shard_key,
            report_shard_count,
            report_storage_epoch_duration,
        ): (
            &'n DapTaskConfig,
            &'n str,
            &'n ReportId,
            Time,
            &'n [u8; 32],
            u64,
            Duration,
        )
    ) -> ObjectIdFrom {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, report_shard_key);
        let tag = ring::hmac::sign(&key, report_id.as_ref());
        let shard = u64::from_be_bytes(
            tag.as_ref()[..std::mem::size_of::<u64>()]
                .try_into()
                .unwrap(),
        ) % report_shard_count;
        let epoch = report_time - (report_time % report_storage_epoch_duration);
        durable_name_report_store(task_config.version, task_id_hex, epoch, shard)
    }
}

pub fn durable_name_report_store(
    version: DapVersion,
    task_id_hex: &str,
    epoch: u64,
    shard: u64,
) -> ObjectIdFrom {
    ObjectIdFrom::Name(format!(
        "{}/epoch/{:020}/shard/{}",
        durable_name_task(version, task_id_hex),
        epoch,
        shard
    ))
}

pub fn durable_name_queue(shard: u64) -> String {
    format!("queue/{shard}")
}

impl ReportsPending {}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PendingReport {
    pub task_id: TaskId,
    pub version: DapVersion,

    /// Hex-encdoed, serialized report.
    //
    // TODO(cjpatton) Consider changing the type to `Report`. If I recall correctly, this triggers
    // the serde-wasm-bindgen bug we saw in workers-rs 0.0.12, which should be fixed as of 0.0.15.
    pub report_hex: String,
}

impl PendingReport {
    pub fn report_id_hex(&self) -> Option<&str> {
        match self.version {
            DapVersion::Draft02 if self.report_hex.len() >= 96 => Some(&self.report_hex[64..96]),
            DapVersion::DraftLatest if self.report_hex.len() >= 32 => Some(&self.report_hex[..32]),
            _ => None,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportsPendingResult {
    Ok,
    ErrReportExists,
}

#[cfg(test)]
mod test {
    use super::{durable_name_queue, durable_name_report_store, AggregateStore, DurableMethod};
    use crate::durable_requests::ObjectIdFrom;
    use daphne::{
        messages::{BatchId, TaskId},
        DapBatchBucket, DapVersion,
    };

    #[test]
    fn durable_name() {
        let time = 1_664_850_074;
        let id1 = TaskId([17; 32]);
        let id2 = BatchId([34; 32]);
        let shard = 1234;

        assert_eq!(durable_name_queue(shard), "queue/1234");

        assert_eq!(
            durable_name_report_store(DapVersion::Draft02, &id1.to_hex(), time, shard),
            ObjectIdFrom::Name(
                "v02/task/1111111111111111111111111111111111111111111111111111111111111111/epoch/00000000001664850074/shard/1234".into(),
            )
        );

        assert_eq!(
            AggregateStore::name((DapVersion::Draft02, &id1.to_hex(), &DapBatchBucket::FixedSize{ batch_id: id2 })),
            ObjectIdFrom::Name(
                "v02/task/1111111111111111111111111111111111111111111111111111111111111111/batch/2222222222222222222222222222222222222222222222222222222222222222".into(),
            )
        );

        assert_eq!(
            AggregateStore::name((DapVersion::Draft02, &id1.to_hex(), &DapBatchBucket::TimeInterval{ batch_window: time })),
            ObjectIdFrom::Name(
                "v02/task/1111111111111111111111111111111111111111111111111111111111111111/window/1664850074".into(),
            )
        );
    }
}
