// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{any::Any, fmt::Display};

use axum::http::StatusCode;
use daphne_service_utils::durable_requests::KV_PATH_PREFIX;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::RwLock;
use url::Url;

use super::{
    cache::{self, Cache},
    status_http_1_0_to_reqwest_0_11, Error,
};

pub(crate) struct Kv<'h> {
    url: &'h Url,
    http: &'h reqwest::Client,
    cache: &'h RwLock<Cache>,
}

pub trait KvPrefix {
    const PREFIX: &'static str;

    type Key: Display;
    type Value: Any + Send + Sync + Serialize + DeserializeOwned;
}

pub mod prefix {
    use daphne::{auth::BearerToken, messages::TaskId, DapTaskConfig, DapVersion};
    use daphne_service_utils::config::HpkeRecieverConfigList;

    use super::KvPrefix;

    pub struct TaskConfig();
    impl KvPrefix for TaskConfig {
        const PREFIX: &'static str = "config/task";

        type Key = TaskId;
        type Value = DapTaskConfig;
    }

    pub struct HpkeReceiverConfigSet();
    impl KvPrefix for HpkeReceiverConfigSet {
        const PREFIX: &'static str = "hpke_receiver_config_set";

        type Key = DapVersion;
        type Value = HpkeRecieverConfigList;
    }

    pub struct LeaderBearerToken();
    impl KvPrefix for LeaderBearerToken {
        const PREFIX: &'static str = "bearer_token/leader/task";

        type Key = TaskId;
        type Value = BearerToken;
    }

    pub struct CollectorBearerToken();
    impl KvPrefix for CollectorBearerToken {
        const PREFIX: &'static str = "bearer_token/collector/task";

        type Key = TaskId;
        type Value = BearerToken;
    }
}

impl<'h> Kv<'h> {
    pub fn new(url: &'h Url, client: &'h reqwest::Client, cache: &'h RwLock<Cache>) -> Self {
        Self {
            url,
            http: client,
            cache,
        }
    }

    pub async fn get<P>(&self, key: &P::Key) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Value: Clone,
    {
        self.get_mapped::<P, _, _>(key, |t: &P::Value| Some(t.clone()))
            .await
    }

    pub async fn get_mapped<P, R, F>(&self, key: &P::Key, mapper: F) -> Result<Option<R>, Error>
    where
        P: KvPrefix,
        F: FnOnce(&P::Value) -> Option<R>,
    {
        let key = Self::to_key::<P>(key);
        tracing::debug!(key, "GET");
        match self.cache.read().await.kv_get::<P>(&key) {
            cache::GetResult::NoFound => {}
            cache::GetResult::Found(t) => return Ok(mapper(t)),
            cache::GetResult::MismatchedType => {
                tracing::warn!(
                    "cache mismatched type, wanted {}",
                    std::any::type_name::<P::Value>()
                );
            }
        }
        let resp = self.http.get(self.url.join(&key).unwrap()).send().await?;
        if resp.status() == status_http_1_0_to_reqwest_0_11(StatusCode::NOT_FOUND) {
            Ok(None)
        } else {
            let resp = resp.error_for_status()?;
            let t = resp.json().await?;
            let r = mapper(&t);
            self.cache.write().await.kv_put::<P>(key, t);
            Ok(r)
        }
    }

    pub async fn put<P>(&self, key: &P::Key, value: P::Value) -> Result<(), Error>
    where
        P: KvPrefix,
    {
        let key = Self::to_key::<P>(key);
        tracing::debug!(key, "PUT");
        self.http
            .post(self.url.join(&key).unwrap())
            .body(serde_json::to_vec(&value).unwrap())
            .send()
            .await?
            .error_for_status()?;
        self.cache.write().await.kv_put::<P>(key, value);
        Ok(())
    }

    /// Stores a value in kv if it doesn't already exist.
    ///
    /// If the value already exists, returns the passed in value inside the Ok variant.
    pub async fn put_if_not_exists<P>(
        &self,
        key: &P::Key,
        value: P::Value,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
    {
        let key = Self::to_key::<P>(key);

        tracing::debug!(key, "PUT if not exists");
        let response = self
            .http
            .put(self.url.join(&key).unwrap())
            .body(serde_json::to_vec(&value).unwrap())
            .send()
            .await?;

        if response.status() == status_http_1_0_to_reqwest_0_11(StatusCode::CONFLICT) {
            Ok(Some(value))
        } else {
            response.error_for_status()?;
            self.cache.write().await.kv_put::<P>(key, value);
            Ok(None)
        }
    }

    pub async fn only_cache_put<P>(&self, key: &P::Key, value: P::Value)
    where
        P: KvPrefix,
    {
        let key = Self::to_key::<P>(key);
        self.cache.write().await.kv_put::<P>(key, value);
    }

    fn to_key<P: KvPrefix>(key: &P::Key) -> String {
        format!("{KV_PATH_PREFIX}/{}/{key}", P::PREFIX)
    }
}
