// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub(super) mod cache;

use std::{any::Any, fmt::Display};

use axum::http::StatusCode;
use daphne_service_utils::durable_requests::KV_PATH_PREFIX;
use mappable_rc::Marc;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::RwLock;
use tracing::{info_span, Instrument};

use crate::StorageProxyConfig;

use super::{status_http_1_0_to_reqwest_0_11, Error};
pub(crate) use cache::Cache;

pub(crate) struct Kv<'h> {
    config: &'h StorageProxyConfig,
    http: &'h reqwest::Client,
    cache: &'h RwLock<Cache>,
}

pub trait KvPrefix {
    const PREFIX: &'static str;

    type Key: Display;
    type Value: Any + Send + Sync + Serialize + DeserializeOwned;
}

pub mod prefix {
    use std::{fmt::Display, marker::PhantomData};

    use daphne::{auth::BearerToken, messages::TaskId, taskprov, DapTaskConfig, DapVersion};
    use daphne_service_utils::config::HpkeRecieverConfigList;
    use serde::{de::DeserializeOwned, Serialize};

    use super::KvPrefix;

    #[derive(Debug)]
    pub struct GlobalConfigOverride<V>(PhantomData<V>);

    /// List of global overrides stored in kv.
    #[derive(Debug)]
    #[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
    pub enum GlobalOverrides {
        /// A `bool` describing whether to skip replay protection.
        SkipReplayProtection,
        /// The default number of aggregate span shards to use in new tasks.
        DefaultNumAggSpanShards,
    }

    impl Display for GlobalOverrides {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let key = match self {
                Self::SkipReplayProtection => "skip_replay_protection",
                Self::DefaultNumAggSpanShards => "default_num_agg_span_shards",
            };
            f.write_str(key)
        }
    }

    impl<V> KvPrefix for GlobalConfigOverride<V>
    where
        V: Send + Sync + Serialize + DeserializeOwned + 'static,
    {
        const PREFIX: &'static str = "global_config/override";

        type Key = GlobalOverrides;
        type Value = V;
    }

    pub struct TaskConfig();
    impl KvPrefix for TaskConfig {
        const PREFIX: &'static str = "config/task";

        type Key = TaskId;
        type Value = DapTaskConfig;
    }

    pub struct TaskprovOptInParam();
    impl KvPrefix for TaskprovOptInParam {
        const PREFIX: &'static str = "taskprov/opt_in_param";

        type Key = TaskId;
        type Value = taskprov::OptInParam;
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

/// Options for getting items from KV.
#[derive(Default, Debug)]
pub(crate) struct KvGetOptions {
    /// Cache the response from KV regardless of whether a value was found. If the value was not
    /// found, then [`Kv::get`] and its cousins will return `None` until the cache line expires.
    ///
    /// In most cases we want this option to be disabled. This option is useful in situations where
    /// we don't expect the value to be in KV and the user is not latency-sensitive. For example,
    /// we store overrides for [`DapGlobalConfig`] in KV, but we can wait a few minutes for these
    /// overrides to take effect. Setting this option prevents us from hitting KV harder than we
    /// need to.
    pub(crate) cache_not_found: bool,
}

impl<'h> Kv<'h> {
    pub fn new(
        config: &'h StorageProxyConfig,
        client: &'h reqwest::Client,
        cache: &'h RwLock<Cache>,
    ) -> Self {
        Self {
            config,
            http: client,
            cache,
        }
    }

    pub async fn get<P>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
    ) -> Result<Option<Marc<P::Value>>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        self.get_mapped::<P, _, _>(key, opt, |t| Some(t)).await
    }

    pub async fn get_cloned<P>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Clone,
    {
        Ok(self.get::<P>(key, opt).await?.map(|t| t.as_ref().clone()))
    }

    pub async fn get_mapped<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        mapper: F,
    ) -> Result<Option<Marc<R>>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: for<'s> FnOnce(&'s P::Value) -> Option<&'s R>,
        R: 'static,
    {
        Ok(self
            .get_impl::<P, _, _>(key, opt, |marc| Marc::try_map(marc, mapper).ok())
            .await?
            .flatten())
    }

    pub async fn peek<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        peeker: F,
    ) -> Result<Option<R>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: FnOnce(&P::Value) -> R,
    {
        self.get_impl::<P, _, _>(key, opt, |marc| peeker(&marc))
            .await
    }

    async fn get_impl<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        mapper: F,
    ) -> Result<Option<R>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: for<'s> FnOnce(Marc<P::Value>) -> R,
    {
        let key = Self::to_key::<P>(key);
        tracing::debug!(key, "GET");
        match self.cache.read().await.get::<P>(&key) {
            cache::GetResult::NotFound { read_through } => {
                if !read_through {
                    return Ok(None);
                }
            }
            cache::GetResult::Found(t) => return Ok(Some(mapper(t))),
            cache::GetResult::MismatchedType => {
                tracing::warn!(
                    "cache mismatched type, wanted {}",
                    std::any::type_name::<P::Value>()
                );
            }
        }
        let span = info_span!(
            "uncached kv_get",
            ?key,
            ?opt,
            prefix = std::any::type_name::<P>()
        );
        async {
            let resp = self
                .http
                .get(self.config.url.join(&key).unwrap())
                .bearer_auth(&self.config.auth_token)
                .send()
                .await?;
            if resp.status() == status_http_1_0_to_reqwest_0_11(StatusCode::NOT_FOUND) {
                if opt.cache_not_found {
                    self.cache.write().await.put::<P>(key, None);
                }
                Ok(None)
            } else {
                let resp = resp.error_for_status()?;
                let t = Marc::new(resp.json::<P::Value>().await?);
                let r = mapper(t.clone());
                self.cache.write().await.put::<P>(key, Some(t));
                Ok(Some(r))
            }
        }
        .instrument(span)
        .await
    }

    #[tracing::instrument(
        name = "kv_put",
        skip_all,
        fields(key, prefix = std::any::type_name::<P>()),
    )]
    pub async fn put<P>(&self, key: &P::Key, value: P::Value) -> Result<(), Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        let key = Self::to_key::<P>(key);
        tracing::debug!(key, "PUT");
        self.http
            .post(self.config.url.join(&key).unwrap())
            .bearer_auth(&self.config.auth_token)
            .body(serde_json::to_vec(&value).unwrap())
            .send()
            .await?
            .error_for_status()?;
        self.cache.write().await.put::<P>(key, Some(value.into()));
        Ok(())
    }

    /// Stores a value in kv if it doesn't already exist.
    ///
    /// If the value already exists, returns the passed in value inside the Ok variant.
    #[tracing::instrument(
        name = "kv_put_if_not_exists",
        skip_all,
        fields(key, prefix = std::any::type_name::<P>()),
    )]
    pub async fn put_if_not_exists<P>(
        &self,
        key: &P::Key,
        value: P::Value,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        let key = Self::to_key::<P>(key);

        tracing::debug!(key, "PUT if not exists");
        let response = self
            .http
            .put(self.config.url.join(&key).unwrap())
            .bearer_auth(&self.config.auth_token)
            .body(serde_json::to_vec(&value).unwrap())
            .send()
            .await?;

        if response.status() == status_http_1_0_to_reqwest_0_11(StatusCode::CONFLICT) {
            Ok(Some(value))
        } else {
            response.error_for_status()?;
            self.cache.write().await.put::<P>(key, Some(value.into()));
            Ok(None)
        }
    }

    #[tracing::instrument(skip_all, fields(key, prefix = std::any::type_name::<P>()))]
    pub async fn only_cache_put<P>(&self, key: &P::Key, value: P::Value)
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        let key = Self::to_key::<P>(key);
        self.cache.write().await.put::<P>(key, Some(value.into()));
    }

    fn to_key<P: KvPrefix>(key: &P::Key) -> String {
        format!("{KV_PATH_PREFIX}/{}/{key}", P::PREFIX)
    }
}
