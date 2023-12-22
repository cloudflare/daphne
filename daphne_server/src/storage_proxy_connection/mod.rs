// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(unused_variables)]
#![allow(clippy::unused_async)]
#![allow(dead_code)]

pub(crate) mod kv;

use std::fmt::Debug;

use axum::http::{Method, StatusCode};
use daphne_service_utils::durable_requests::{
    bindings::DurableMethod, DurableRequest, ObjectIdFrom, DO_PATH_PREFIX,
};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

pub(crate) use kv::Kv;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("network error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("http error. request returned status code was {status} with the body {body}")]
    HttpError { status: StatusCode, body: String },
}

#[derive(Clone, Copy)]
pub(crate) struct Do<'h> {
    url: &'h Url,
    http: &'h reqwest::Client,
    retry: bool,
}

impl<'h> Do<'h> {
    pub fn new(url: &'h Url, client: &'h reqwest::Client) -> Self {
        Self {
            url,
            http: client,
            retry: false,
        }
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
            .url
            .join(&format!("{DO_PATH_PREFIX}{}", self.path.to_uri()))
            .unwrap();
        let resp = self
            .durable
            .http
            .request(reqwest::Method::POST, url)
            .body(self.request.into_bytes())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            Err(Error::HttpError {
                status: status_reqwest_0_11_to_http_1_0(resp.status()),
                body: resp.text().await?,
            })
        }
    }
}

impl<'d, B: DurableMethod> RequestBuilder<'d, B, [u8; 0]> {
    pub fn encode_bincode<T: Serialize>(self, payload: T) -> RequestBuilder<'d, B, Vec<u8>> {
        self.with_body(bincode::serialize(&payload).unwrap())
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

/// this is needed while [reqwest#2039](https://github.com/seanmonstar/reqwest/issues/2039) isn't
/// completed.
///
/// This is because axum is using http 1.0 and reqwest is still in http 0.2
pub fn method_http_1_0_to_reqwest_0_11(method: Method) -> reqwest::Method {
    match method {
        Method::GET => reqwest::Method::GET,
        Method::POST => reqwest::Method::POST,
        Method::PUT => reqwest::Method::PUT,
        Method::PATCH => reqwest::Method::PATCH,
        Method::HEAD => reqwest::Method::HEAD,
        Method::TRACE => reqwest::Method::TRACE,
        Method::OPTIONS => reqwest::Method::OPTIONS,
        Method::CONNECT => reqwest::Method::CONNECT,
        Method::DELETE => reqwest::Method::DELETE,
        _ => unreachable!(),
    }
}

/// this is needed while [reqwest#2039](https://github.com/seanmonstar/reqwest/issues/2039) isn't
/// completed.
///
/// This is because axum is using http 1.0 and reqwest is still in http 0.2
pub fn status_http_1_0_to_reqwest_0_11(status: StatusCode) -> reqwest::StatusCode {
    reqwest::StatusCode::from_u16(status.as_u16()).unwrap()
}

/// this is needed while [reqwest#2039](https://github.com/seanmonstar/reqwest/issues/2039) isn't
/// completed.
///
/// This is because axum is using http 1.0 and reqwest is still in http 0.2
pub fn status_reqwest_0_11_to_http_1_0(status: reqwest::StatusCode) -> StatusCode {
    StatusCode::from_u16(status.as_u16()).unwrap()
}
