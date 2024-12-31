// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use capnp::traits::{FromPointerBuilder, FromPointerReader};

pub trait CapnprotoPayloadEncode {
    type Builder<'a>: FromPointerBuilder<'a>;

    fn encode_to_builder(&self, builder: Self::Builder<'_>);
}

pub trait CapnprotoPayloadEncodeExt {
    fn encode_to_bytes(&self) -> Vec<u8>;
}

pub trait CapnprotoPayloadDecode {
    type Reader<'a>: FromPointerReader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized;
}

pub trait CapnprotoPayloadDecodeExt {
    fn decode_from_bytes(bytes: &[u8]) -> capnp::Result<Self>
    where
        Self: Sized;
}

impl<T> CapnprotoPayloadEncodeExt for T
where
    T: CapnprotoPayloadEncode,
{
    fn encode_to_bytes(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        self.encode_to_builder(message.init_root::<T::Builder<'_>>());
        let mut buf = Vec::new();
        capnp::serialize_packed::write_message(&mut buf, &message).expect("infalible");
        buf
    }
}

impl<T> CapnprotoPayloadDecodeExt for T
where
    T: CapnprotoPayloadDecode,
{
    fn decode_from_bytes(bytes: &[u8]) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let mut cursor = std::io::Cursor::new(bytes);
        let reader = capnp::serialize_packed::read_message(
            &mut cursor,
            capnp::message::ReaderOptions::new(),
        )?;

        let reader = reader.get_root::<T::Reader<'_>>()?;
        T::decode_from_reader(reader)
    }
}
