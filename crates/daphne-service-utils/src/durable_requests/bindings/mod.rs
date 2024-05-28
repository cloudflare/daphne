// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This module defines the durable objects' binding and methods as implementors of the
//! [`DurableMethod`] trait.
//!
//! It also defines types that are used as the body of requests sent to these objects.

mod aggregate_store;
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

pub trait DurableRequestPayload {
    fn decode_from_reader(
        reader: capnp::message::Reader<capnp::serialize::OwnedSegments>,
    ) -> capnp::Result<Self>
    where
        Self: Sized;

    fn encode_to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator>;
}

pub trait DurableRequestPayloadExt {
    fn decode_from_bytes(bytes: &[u8]) -> capnp::Result<Self>
    where
        Self: Sized;
    fn encode_to_bytes(&self) -> capnp::Result<Vec<u8>>;
}

impl<T> DurableRequestPayloadExt for T
where
    T: DurableRequestPayload,
{
    fn encode_to_bytes(&self) -> capnp::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let message = self.encode_to_builder();
        capnp::serialize_packed::write_message(&mut buf, &message)?;
        Ok(buf)
    }

    fn decode_from_bytes(bytes: &[u8]) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let mut cursor = std::io::Cursor::new(bytes);
        let reader = capnp::serialize_packed::read_message(
            &mut cursor,
            capnp::message::ReaderOptions::new(),
        )?;

        T::decode_from_reader(reader)
    }
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
            "batch/1111111111111111111111111111111111111111111111111111111111111111",
            format!(
                "{}",
                DapBatchBucket::FixedSize {
                    batch_id: BatchId([17; 32]),
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
            "batch/1111111111111111111111111111111111111111111111111111111111111111/shard/2323",
            format!(
                "{}",
                DapBatchBucket::FixedSize {
                    batch_id: BatchId([17; 32]),
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
