// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub(crate) mod kv;

use std::fmt::Debug;

use axum::http::StatusCode;
use daphne_service_utils::durable_requests::{
    bindings::{DurableMethod, DurableRequestPayload, DurableRequestPayloadExt},
    DurableRequest, ObjectIdFrom, DO_PATH_PREFIX,
};
use serde::de::DeserializeOwned;

pub(crate) use kv::Kv;

use crate::StorageProxyConfig;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("network error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("http error. request returned status code {status} with the body {body}")]
    Http { status: StatusCode, body: String },
}

#[derive(Clone, Copy)]
pub(crate) struct Do<'h> {
    config: &'h StorageProxyConfig,
    http: &'h reqwest::Client,
    retry: bool,
}

impl<'h> Do<'h> {
    pub fn new(config: &'h StorageProxyConfig, client: &'h reqwest::Client) -> Self {
        Self {
            config,
            http: client,
            retry: false,
        }
    }

    #[allow(dead_code)]
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
        let url = self
            .durable
            .config
            .url
            .join(&format!("{DO_PATH_PREFIX}{}", self.path.to_uri()))
            .unwrap();
        let resp = self
            .durable
            .http
            .post(url)
            .body(self.request.into_bytes())
            .bearer_auth(self.durable.config.auth_token.as_str())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            Err(Error::Http {
                status: resp.status(),
                body: resp.text().await?,
            })
        }
    }
}

impl<'d, B: DurableMethod> RequestBuilder<'d, B, [u8; 0]> {
    pub fn encode<T: DurableRequestPayload>(self, payload: &T) -> RequestBuilder<'d, B, Vec<u8>> {
        self.with_body(payload.encode_to_bytes().unwrap())
    }

    pub fn with_body<T: AsRef<[u8]>>(self, payload: T) -> RequestBuilder<'d, B, T> {
        RequestBuilder {
            durable: self.durable,
            path: self.path,
            request: self.request.with_body(payload),
        }
    }
}

impl<'w> Do<'w> {
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
