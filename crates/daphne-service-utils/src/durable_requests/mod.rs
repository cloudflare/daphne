// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This module implements the communication between the daphne service and the storage proxy.
//!
//! Communication with the storage proxy happens through HTTP. The URI of the request is the URI
//! to use when talking to the durable object, prefixed by [`DO_PATH_PREFIX`]. The body of this
//! request will contain the metadata necessary for the storage proxy to locate the appropriate
//! durable object, followed by the opaque body that should be forwarded to the durable object
//! itself.
//!
//! # Metadata encoding
//!
//! The metadata is encoded using capnproto as the binary protocol, it contains:
//! - The `binding` which identifies the durable object implementation to target.
//! - The `id` which identifies the specific instance of the durable object.
//! - A `retry` flag which tells the proxy whether it should retry durable object requests that fail.
//!
//! # Body encoding
//!
//! The body that follows this piece of metadata is opaque and to be understood by the Durable
//! Object itself. So the proxy simply forwards it along without any processing.
//!
//! # The response
//!
//! The HTTP response is simply forwarded back from the Durable Object to the daphne service.
//!
//!```text
//! +----------------+                 +---------------+            +----------------+
//! | Native Service |                 | Storage Proxy |            | Durable Object |
//! +----------------+                 +---------------+            +----------------+
//!    | Http Request:                         |                            |
//!    | POST /v1/`DO_PATH_PREFIX`/path/to/call|                            |
//!    | DurableRequest:                       |                            |
//!    |   {binding, id, retry}[body]          |                            |
//!    |-------------------------------------->| use `binding` and `id`     |
//!    |                                       | to locate the durable      |
//!    |                                       | object.                    |
//!    |                                       |--------+                   |
//!    |                                       |        |                   |
//!    |                                       |        |                   |
//!    |                                       |<-------+                   |
//!    |                                       |                            |
//!    |                                       |                            |
//!    |                                       | Http Request:              |
//!    |                                       | POST `/path/to/call`       | do some
//!    |                                       | `body`                     | storage work
//!    |                                       |--------------------------> |---------+
//!    |                                       | retry this request if      |         |
//!    |                                       | `retry` was set            |         |
//!    |                                       |                            |         |
//!    |                                       |              Http Response |         |
//!    |<--------------------------------------|<---------------------------|<--------+
//!```

pub mod bindings;

use std::io;

use bindings::DurableMethod;
use daphne::messages::constant_time_eq;
use durable_request_capnp::durable_request;
use serde::{Deserialize, Serialize};

use crate::durable_request_capnp;

/// The base of a request path that points to a key in KV.
pub const KV_PATH_PREFIX: &str = "/v1/kv";
/// The base of a request path that points to a durable object.
pub const DO_PATH_PREFIX: &str = "/v1/do";
#[cfg(feature = "test-utils")]
/// The path of the purge request, which wipes all storage. This is meant for tests only.
pub const PURGE_STORAGE: &str = "/v1/purge";
#[cfg(feature = "test-utils")]
/// The path used to check for readyness
pub const STORAGE_READY: &str = "/v1/ready";

/// The way the target object's id will be obtained.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectIdFrom {
    /// Derive a unique id from a name string.
    ///
    /// [see also](https://docs.rs/worker/latest/worker/durable/struct.ObjectNamespace.html#method.id_from_name)
    Name(String),

    /// Parse a previously stringified id from a hex string.
    ///
    /// [see also](https://docs.rs/worker/latest/worker/durable/struct.ObjectNamespace.html#method.id_from_string)
    Hex(String),
}

impl ObjectIdFrom {
    /// Assert that the object is being referenced by name.
    ///
    /// # Note
    /// This is here for convenience of the `daphne-worker` and can be removed in the future.
    pub fn unwrap_from_name(self) -> String {
        let Self::Name(name) = self else {
            panic!("unwraped a {self:?} when a Name was expected");
        };
        name
    }

    /// Assert that the object is being referenced by id.
    ///
    /// # Note
    /// This is here for convenience of the `daphne-worker` and can be removed in the future.
    pub fn unwrap_from_hex(self) -> String {
        let Self::Hex(name) = self else {
            panic!("unwraped a {self:?} when a Hex was expected");
        };
        name
    }
}

/// A durable object request meant for the storage proxy.
///
/// It's generic over the payload which can be any type that implements [`AsRef]`<[u8]>. This payload
/// is what is ultimately passed to the durable object.
#[derive(Debug, Clone)]
pub struct DurableRequest<P: AsRef<[u8]>> {
    /// A binding name, as configured in the wrangler.toml.
    ///
    /// [see also](https://developers.cloudflare.com/durable-objects/get-started/#5-configure-durable-object-bindings)
    pub binding: String,

    /// The method by which the object id will be obtained in the storage proxy.
    ///
    /// [see also](https://developers.cloudflare.com/durable-objects/get-started/#4-instantiate-and-communicate-with-a-durable-object)
    pub id: ObjectIdFrom,

    /// Whether this request should be retried if the Durable Object crashes when resolving the
    /// request.
    pub retry: bool,

    /// The body of the request.
    body: P,
}

// This needs to be very general to facilitate tests.
impl<T, U> PartialEq<DurableRequest<U>> for DurableRequest<T>
where
    T: AsRef<[u8]>,
    U: AsRef<[u8]>,
{
    fn eq(&self, other: &DurableRequest<U>) -> bool {
        let Self {
            binding,
            id,
            retry,
            body,
        } = self;
        *binding == other.binding
            && *id == other.id
            && *retry == other.retry
            && constant_time_eq(body.as_ref(), other.body.as_ref())
    }
}

impl DurableRequest<[u8; 0]> {
    /// Create a new [`DurableRequest`] with an empty body.
    pub fn new<B: DurableMethod>(
        durable_method: B,
        params: B::NameParameters<'_>,
    ) -> (Self, &'static str) {
        (
            Self {
                binding: B::BINDING.to_owned(),
                id: B::name(params),
                retry: false,
                body: [],
            },
            durable_method.to_uri(),
        )
    }

    /// Create a new [`DurableRequest`] with a specific id.
    pub fn new_with_id<B: DurableMethod>(
        durable_method: B,
        obj_id_from: ObjectIdFrom,
    ) -> (Self, &'static str) {
        (
            Self {
                binding: B::BINDING.to_owned(),
                id: obj_id_from,
                retry: false,
                body: [],
            },
            durable_method.to_uri(),
        )
    }

    /// Add a body to the request.
    pub fn with_body<T: AsRef<[u8]>>(self, body: T) -> DurableRequest<T> {
        DurableRequest {
            binding: self.binding,
            id: self.id,
            retry: self.retry,
            body,
        }
    }
}

impl<'s> TryFrom<&'s Vec<u8>> for DurableRequest<&'s [u8]> {
    type Error = capnp::Error;

    fn try_from(bytes: &'s Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<'s> TryFrom<&'s [u8]> for DurableRequest<&'s [u8]> {
    type Error = capnp::Error;

    fn try_from(bytes: &'s [u8]) -> Result<Self, Self::Error> {
        let mut cursor = io::Cursor::new(bytes);
        let (binding, id, retry) = {
            let message_reader = capnp::serialize_packed::read_message(
                &mut cursor,
                capnp::message::ReaderOptions::new(),
            )?;

            let request = message_reader.get_root::<durable_request::Reader>()?;

            let binding = request.get_binding()?.to_string()?;
            let id = match request.get_id().which()? {
                durable_request::id::Which::Name(name) => ObjectIdFrom::Name(name?.to_string()?),
                durable_request::id::Which::Hex(hex) => ObjectIdFrom::Hex(hex?.to_string()?),
            };
            let retry = request.get_retry();
            (binding, id, retry)
        };

        Ok(Self {
            binding,
            id,
            retry,
            body: &bytes[cursor.position().try_into().unwrap_or(usize::MAX)..],
        })
    }
}

impl<P> DurableRequest<P>
where
    P: AsRef<[u8]>,
{
    #[must_use]
    pub fn with_retry(self) -> Self {
        Self {
            retry: true,
            ..self
        }
    }

    /// Return a reference to the body.
    pub fn body(&self) -> &[u8] {
        self.body.as_ref()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let Self {
            binding,
            id,
            retry,
            body,
        } = self;
        let mut message = capnp::message::Builder::new_default();
        {
            let mut request = message.init_root::<durable_request::Builder>();
            request.set_binding(binding.as_str().into());
            request.set_retry(retry);
            {
                let mut id_builder = request.init_id();
                match id {
                    ObjectIdFrom::Name(n) => id_builder.set_name(n.as_str().into()),
                    ObjectIdFrom::Hex(h) => id_builder.set_hex(h.as_str().into()),
                }
            }
        }
        let mut vec = Vec::new();
        capnp::serialize_packed::write_message(&mut vec, &message).unwrap();
        vec.extend_from_slice(body.as_ref());
        vec
    }
}

impl<P> DurableRequest<P>
where
    P: Default + AsRef<[u8]>,
{
    pub fn take_body(&mut self) -> P {
        std::mem::take(&mut self.body)
    }
}

#[cfg(test)]
mod test {
    use daphne::{DapBatchBucket, DapVersion};

    use crate::durable_requests::bindings::AggregateStore;

    use super::{bindings, DurableRequest};

    #[test]
    fn roundrip_without_body() {
        let (want, _) = DurableRequest::new(
            AggregateStore::Merge,
            (
                DapVersion::Draft09,
                "some-task-id-hex",
                &DapBatchBucket::TimeInterval {
                    batch_window: 0,
                    shard: 17,
                },
            ),
        );

        let req_bytes = want.clone().into_bytes();
        let got = DurableRequest::try_from(&req_bytes).unwrap();
        assert_eq!(want, got);
    }

    #[test]
    fn roundrip_with_body() {
        let binary_body = b"really cool body".to_vec();
        let (want, _) = DurableRequest::new(
            bindings::AggregateStore::Merge,
            (
                DapVersion::Draft09,
                "some-task-id-hex",
                &DapBatchBucket::TimeInterval {
                    batch_window: 0,
                    shard: 16,
                },
            ),
        );

        let want = want.with_body(binary_body);

        let req_bytes = want.clone().into_bytes();
        let got = DurableRequest::try_from(&req_bytes).unwrap();
        assert_eq!(want, got);
    }
}
