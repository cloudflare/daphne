// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod async_aggregator;

pub use async_aggregator::{async_aggregate_batch, AsyncAggregationMessage};
use daphne_service_utils::capnproto::{CapnprotoPayloadEncode, CapnprotoPayloadEncodeExt as _};
use std::marker::PhantomData;
use worker::RawMessageBuilder;

pub struct Queue<T> {
    queue: worker::Queue,
    _message_type: PhantomData<T>,
}

impl<T: CapnprotoPayloadEncode> Queue<T> {
    #[tracing::instrument(skip_all, fields(message = std::any::type_name::<T>()))]
    pub async fn send(&self, message: &T) -> worker::Result<()> {
        tracing::info!("submiting queue message");
        let bytes = worker::js_sys::Uint8Array::from(message.encode_to_bytes().as_slice());
        self.queue
            .send_raw(
                RawMessageBuilder::new(bytes.into())
                    .build_with_content_type(worker::QueueContentType::V8),
            )
            .await?;

        Ok(())
    }
}

impl<T> From<worker::Queue> for Queue<T> {
    fn from(queue: worker::Queue) -> Self {
        Self {
            queue,
            _message_type: PhantomData,
        }
    }
}
