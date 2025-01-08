// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::base_capnp::{self, partial_batch_selector, u8_l16, u8_l32};
use capnp::struct_list;
use capnp::traits::{FromPointerBuilder, FromPointerReader};
use daphne::{
    messages::{AggregationJobId, BatchId, PartialBatchSelector, ReportId, TaskId},
    DapVersion,
};

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

impl<T> CapnprotoPayloadEncode for &'_ T
where
    T: CapnprotoPayloadEncode,
{
    type Builder<'a> = T::Builder<'a>;

    fn encode_to_builder(&self, builder: Self::Builder<'_>) {
        T::encode_to_builder(self, builder);
    }
}

impl From<base_capnp::DapVersion> for DapVersion {
    fn from(val: base_capnp::DapVersion) -> Self {
        match val {
            base_capnp::DapVersion::Draft09 => DapVersion::Draft09,
            base_capnp::DapVersion::DraftLatest => DapVersion::Latest,
        }
    }
}

impl From<DapVersion> for base_capnp::DapVersion {
    fn from(value: DapVersion) -> Self {
        match value {
            DapVersion::Draft09 => base_capnp::DapVersion::Draft09,
            DapVersion::Latest => base_capnp::DapVersion::DraftLatest,
        }
    }
}

impl CapnprotoPayloadEncode for [u8; 32] {
    type Builder<'a> = u8_l32::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        builder.set_fst(u64::from_le_bytes(self[0..8].try_into().unwrap()));
        builder.set_snd(u64::from_le_bytes(self[8..16].try_into().unwrap()));
        builder.set_thr(u64::from_le_bytes(self[16..24].try_into().unwrap()));
        builder.set_frh(u64::from_le_bytes(self[24..32].try_into().unwrap()));
    }
}

impl CapnprotoPayloadDecode for [u8; 32] {
    type Reader<'a> = u8_l32::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let mut array = [0; 32];
        array[0..8].copy_from_slice(&reader.get_fst().to_le_bytes());
        array[8..16].copy_from_slice(&reader.get_snd().to_le_bytes());
        array[16..24].copy_from_slice(&reader.get_thr().to_le_bytes());
        array[24..32].copy_from_slice(&reader.get_frh().to_le_bytes());
        Ok(array)
    }
}

impl CapnprotoPayloadEncode for [u8; 16] {
    type Builder<'a> = u8_l16::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        builder.set_fst(u64::from_le_bytes(self[0..8].try_into().unwrap()));
        builder.set_snd(u64::from_le_bytes(self[8..16].try_into().unwrap()));
    }
}

impl CapnprotoPayloadDecode for [u8; 16] {
    type Reader<'a> = u8_l16::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
    where
        Self: Sized,
    {
        let mut array = [0; 16];
        array[0..8].copy_from_slice(&reader.get_fst().to_le_bytes());
        array[8..16].copy_from_slice(&reader.get_snd().to_le_bytes());
        Ok(array)
    }
}

macro_rules! capnp_encode_ids {
    ($($id:ident => $inner:ident),*$(,)?) => {
        $(
        impl CapnprotoPayloadEncode for $id {
            type Builder<'a> = $inner::Builder<'a>;

            fn encode_to_builder(&self, builder: Self::Builder<'_>) {
                self.0.encode_to_builder(builder)
            }
        }

        impl CapnprotoPayloadDecode for $id {
            type Reader<'a> = $inner::Reader<'a>;

            fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self>
            where
                Self: Sized,
            {
               <_>::decode_from_reader(reader).map(Self)
            }
        }
        )*
    };
}

capnp_encode_ids! {
    TaskId => u8_l32,
    ReportId => u8_l16,
    BatchId => u8_l32,
    AggregationJobId => u8_l16,
}

impl CapnprotoPayloadEncode for PartialBatchSelector {
    type Builder<'a> = partial_batch_selector::Builder<'a>;

    fn encode_to_builder(&self, mut builder: Self::Builder<'_>) {
        match self {
            PartialBatchSelector::TimeInterval => builder.set_time_interval(()),
            PartialBatchSelector::LeaderSelectedByBatchId { batch_id } => {
                batch_id.encode_to_builder(builder.init_leader_selected_by_batch_id());
            }
        }
    }
}

impl CapnprotoPayloadDecode for PartialBatchSelector {
    type Reader<'a> = partial_batch_selector::Reader<'a>;

    fn decode_from_reader(reader: Self::Reader<'_>) -> capnp::Result<Self> {
        match reader.which()? {
            partial_batch_selector::Which::TimeInterval(()) => Ok(Self::TimeInterval),
            partial_batch_selector::Which::LeaderSelectedByBatchId(reader) => {
                Ok(Self::LeaderSelectedByBatchId {
                    batch_id: <_>::decode_from_reader(reader?)?,
                })
            }
        }
    }
}

pub fn encode_list<I, O>(list: I, mut builder: struct_list::Builder<'_, O>)
where
    I: IntoIterator<Item: CapnprotoPayloadEncode>,
    O: for<'b> capnp::traits::OwnedStruct<
        Builder<'b> = <I::Item as CapnprotoPayloadEncode>::Builder<'b>,
    >,
{
    for (i, item) in list.into_iter().enumerate() {
        item.encode_to_builder(builder.reborrow().get(i.try_into().unwrap()));
    }
}

pub fn decode_list<T, O, C>(reader: struct_list::Reader<'_, O>) -> capnp::Result<C>
where
    T: CapnprotoPayloadDecode,
    C: FromIterator<T>,
    O: for<'b> capnp::traits::OwnedStruct<Reader<'b> = T::Reader<'b>>,
{
    reader.into_iter().map(T::decode_from_reader).collect()
}

pub fn usize_to_capnp_len(u: usize) -> u32 {
    u.try_into()
        .expect("capnp can't encode more that u32::MAX of something")
}
