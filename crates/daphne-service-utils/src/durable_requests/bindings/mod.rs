// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This module defines the durable objects' binding and methods as implementors of the
//! [`DurableMethod`] trait.
//!
//! It also defines types that are used as the body of requests sent to these objects.

mod aggregate_store;
pub mod aggregation_job_store;
#[cfg(feature = "test-utils")]
mod test_state_cleaner;

use super::ObjectIdFrom;

pub use aggregate_store::{
    AggregateStore, AggregateStoreMergeOptions, AggregateStoreMergeReq, AggregateStoreMergeResp,
};
#[cfg(feature = "test-utils")]
pub use test_state_cleaner::TestStateCleaner;

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

        impl $crate::durable_requests::bindings::DurableMethod for $name {
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

            fn name($params: Self::NameParameters<'_>) -> $crate::durable_requests::bindings::ObjectIdFrom {
                $name_impl
            }
        }
    };
}

pub(crate) use define_do_binding;

#[cfg(test)]
mod tests {
    use daphne::{messages::BatchId, DapBatchBucket};

    // We use `std::fmt::Display` for `DapBatchBucket` to format names for DO instances. Ensure
    // that they are formatted the way we expect.
    #[test]
    fn bucket_display() {
        assert_eq!(
            "batch/IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
            format!(
                "{}",
                DapBatchBucket::LeaderSelected {
                    batch_id: BatchId([34; 32]),
                    shard: 0,
                }
            )
        );
        assert_eq!(
            "window/1337",
            format!(
                "{}",
                DapBatchBucket::TimeInterval {
                    batch_window: 1337,
                    shard: 0,
                }
            )
        );
        assert_eq!(
            "batch/IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI/shard/2323",
            format!(
                "{}",
                DapBatchBucket::LeaderSelected {
                    batch_id: BatchId([34; 32]),
                    shard: 2323,
                }
            )
        );
        assert_eq!(
            "window/1337/shard/99",
            format!(
                "{}",
                DapBatchBucket::TimeInterval {
                    batch_window: 1337,
                    shard: 99,
                }
            )
        );
    }
}
