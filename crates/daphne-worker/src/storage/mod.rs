// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub(crate) mod kv;

use crate::storage_proxy;
use axum::http::StatusCode;
use daphne_service_utils::{
    capnproto::{CapnprotoPayloadEncode, CapnprotoPayloadEncodeExt},
    durable_requests::{bindings::DurableMethod, DurableRequest, ObjectIdFrom},
};
pub(crate) use kv::Kv;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use worker::Env;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("worker error: {0}")]
    Worker(#[from] worker::Error),
    #[error("http error. request returned status code {status} with the body {body}")]
    Http { status: StatusCode, body: String },
}

#[derive(Clone, Copy)]
pub(crate) struct Do<'h> {
    env: &'h Env,
    retry: bool,
}

impl<'h> Do<'h> {
    pub fn new(env: &'h Env) -> Self {
        Self { env, retry: false }
    }

    pub fn with_retry(self) -> Self {
        Self {
            retry: true,
            ..self
        }
    }
}

pub struct RequestBuilder<'d, B: DurableMethod, P: AsRef<[u8]>> {
    durable: &'d Do<'d>,
    path: B,
    request: DurableRequest<P>,
}

impl<'d, B: DurableMethod + Debug, P: AsRef<[u8]>> RequestBuilder<'d, B, P> {
    #[tracing::instrument(skip_all, fields(path = ?self.path))]
    pub async fn send<R>(self) -> Result<R, Error>
    where
        R: DeserializeOwned,
    {
        tracing::debug!(
            obj = std::any::type_name::<B>().split("::").last().unwrap(),
            path = ?self.path,
            "requesting DO",
        );
        let resp = storage_proxy::handle_do_request(
            self.durable.env,
            Default::default(),
            self.path.to_uri(),
            self.request,
            |_, _, _| {},
        )
        .await?;

        use http_body_util::BodyExt;
        let (resp, body) = resp.into_parts();
        let body = body.collect().await?.to_bytes();
        if resp.status.is_success() {
            Ok(serde_json::from_slice(&body)?)
        } else {
            Err(Error::Http {
                status: resp.status,
                body: String::from_utf8_lossy(&body).into_owned(),
            })
        }
    }
}

impl<'d, B: DurableMethod> RequestBuilder<'d, B, [u8; 0]> {
    pub fn encode<T: CapnprotoPayloadEncode>(self, payload: &T) -> RequestBuilder<'d, B, Vec<u8>> {
        self.with_body(payload.encode_to_bytes())
    }

    pub fn with_body<T: AsRef<[u8]>>(self, payload: T) -> RequestBuilder<'d, B, T> {
        RequestBuilder {
            durable: self.durable,
            path: self.path,
            request: self.request.with_body(payload),
        }
    }
}

impl Do<'_> {
    pub fn request<B: DurableMethod + Copy>(
        &self,
        path: B,
        params: B::NameParameters<'_>,
    ) -> RequestBuilder<'_, B, [u8; 0]> {
        let (request, _) = DurableRequest::new(path, params);
        RequestBuilder {
            durable: self,
            path,
            request: if self.retry {
                request.with_retry()
            } else {
                request
            },
        }
    }

    #[allow(dead_code)]
    pub fn request_with_id<B: DurableMethod + Copy>(
        &self,
        path: B,
        object_id: ObjectIdFrom,
    ) -> RequestBuilder<'_, B, [u8; 0]> {
        let (request, _) = DurableRequest::new_with_id(path, object_id);
        RequestBuilder {
            durable: self,
            path,
            request: if self.retry {
                request.with_retry()
            } else {
                request
            },
        }
    }
}
