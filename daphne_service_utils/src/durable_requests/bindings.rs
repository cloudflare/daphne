// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This module defines the durable objects' binding and methods as implementors of the
//! [`DurableMethod`] trait.
//!
//! It also defines types that are used as the body of requests sent to these objects.

use std::collections::HashSet;

use daphne::{
    messages::{ReportId, TaskId},
    DapAggregateShare, DapBatchBucket, DapVersion, MetaAggregationJobId,
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

    fn name((): ()) -> ObjectIdFrom {
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

#[cfg(test)]
mod tests {
    use daphne::{messages::BatchId, DapBatchBucket};

    // We use `std::fmt::Display` for `DapBatchBucket` to format names for DO instances. Ensure
    // that they are formatted the way we expect.
    #[test]
    fn bucket_display() {
        assert_eq!(
            "batch/1111111111111111111111111111111111111111111111111111111111111111",
            format!(
                "{}",
                DapBatchBucket::FixedSize {
                    batch_id: BatchId([17; 32])
                }
            )
        );
        assert_eq!(
            "window/1337",
            format!("{}", DapBatchBucket::TimeInterval { batch_window: 1337 })
        );
    }
}
