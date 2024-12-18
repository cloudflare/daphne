// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub trait CapnprotoPayload {
    fn decode_from_reader(
        reader: capnp::message::Reader<capnp::serialize::OwnedSegments>,
    ) -> capnp::Result<Self>
    where
        Self: Sized;

    fn encode_to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator>;
}

pub trait CapnprotoPayloadExt {
    fn decode_from_bytes(bytes: &[u8]) -> capnp::Result<Self>
    where
        Self: Sized;
    fn encode_to_bytes(&self) -> capnp::Result<Vec<u8>>;
}

impl<T> CapnprotoPayloadExt for T
where
    T: CapnprotoPayload,
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
