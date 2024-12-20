// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod cache;
mod request_coalescer;

use std::{any::Any, fmt::Display, future::Future};

use axum::http::StatusCode;
use daphne_service_utils::durable_requests::KV_PATH_PREFIX;
use mappable_rc::Marc;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::RwLock;
use tracing::{info_span, Instrument};

use crate::StorageProxyConfig;

use super::Error;
use cache::Cache;
use daphne::messages::Time;
use daphne_service_utils::http_headers::STORAGE_PROXY_PUT_KV_EXPIRATION;

#[derive(Default)]
pub struct State {
    cache: RwLock<Cache>,
    coalescer: request_coalescer::RequestCoalescer,
}

impl State {
    #[cfg(feature = "test-utils")]
    pub async fn reset(&self) {
        let Self { cache, coalescer } = self;

        let clear_cache = async {
            *cache.write().await = Default::default();
        };
        tokio::join!(clear_cache, coalescer.reset());
    }
}

pub(crate) struct Kv<'h> {
    config: &'h StorageProxyConfig,
    http: &'h reqwest::Client,
    state: &'h State,
}

pub trait KvPrefix {
    const PREFIX: &'static str;

    type Key: Display;
    type Value: Any + Send + Sync + Serialize + DeserializeOwned;
}

pub mod prefix {
    use std::{
        fmt::{self, Display},
        marker::PhantomData,
    };

    use daphne::{
        constants::DapRole,
        messages::{Base64Encode, TaskId},
        taskprov, DapTaskConfig, DapVersion,
    };
    use daphne_service_utils::bearer_token::BearerToken;
    use serde::{de::DeserializeOwned, Serialize};

    use crate::config::HpkeRecieverConfigList;

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

    pub struct KvBearerToken();
    impl KvPrefix for KvBearerToken {
        const PREFIX: &'static str = "bearer_token";

        type Key = KvBearerTokenKey;
        type Value = BearerToken;
    }

    #[derive(Debug)]
    pub struct KvBearerTokenKey(DapRole, TaskId);
    impl From<(DapRole, TaskId)> for KvBearerTokenKey {
        fn from((s, t): (DapRole, TaskId)) -> Self {
            Self(s, t)
        }
    }
    impl fmt::Display for KvBearerTokenKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let Self(sender, task_id) = self;
            let task_id = task_id.to_base64url();
            match sender {
                DapRole::Client => write!(f, "client/task/{task_id}"),
                DapRole::Collector => write!(f, "collector/task/{task_id}"),
                DapRole::Helper => write!(f, "helper/task/{task_id}"),
                DapRole::Leader => write!(f, "leader/task/{task_id}"),
            }
        }
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

pub(crate) enum GetOrInsertError<E> {
    StorageProxy(Error),
    Other(E),
}

impl<E> From<Error> for GetOrInsertError<E> {
    fn from(error: Error) -> Self {
        Self::StorageProxy(error)
    }
}

impl<'h> Kv<'h> {
    pub fn new(
        config: &'h StorageProxyConfig,
        client: &'h reqwest::Client,
        state: &'h State,
    ) -> Self {
        Self {
            config,
            http: client,
            state,
        }
    }

    pub async fn get<P>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
    ) -> Result<Option<Marc<P::Value>>, Marc<Error>>
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
    ) -> Result<Option<P::Value>, Marc<Error>>
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
    ) -> Result<Option<Marc<R>>, Marc<Error>>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: for<'s> FnOnce(&'s P::Value) -> Option<&'s R>,
        R: Send + Sync + 'static,
    {
        self.get_coalesced::<P, _, _>(key, opt, |marc| Marc::try_map(marc, mapper).ok())
            .await
            .map(Option::flatten)
    }

    pub async fn get_or_insert_with<P, Fut, E>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        default: impl FnOnce() -> Fut,
        expiration: Option<Time>,
    ) -> Result<Marc<P::Value>, Marc<GetOrInsertError<E>>>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        E: Send + Sync + 'static,
        Fut: Future<Output = Result<P::Value, E>>,
    {
        self.state
            .coalescer
            .coalesce(Self::to_key::<P>(key), || async {
                if let Some(v) = self.get_internal::<P, _, _>(key, opt, |marc| marc).await? {
                    return Ok(Some(v));
                }
                let default = default().await.map_err(GetOrInsertError::Other)?;
                let cached = self.put_internal::<P>(key, default, expiration).await?;
                Ok(Some(cached))
            })
            .await
            .map(|v| v.unwrap()) // all paths of the previous closure return Some
    }

    pub async fn peek<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        peeker: F,
    ) -> Result<Option<R>, Marc<Error>>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: FnOnce(&P::Value) -> R,
    {
        self.get_coalesced::<P, _, _>(key, opt, |marc| peeker(&marc))
            .await
    }

    async fn get_coalesced<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        mapper: F,
    ) -> Result<Option<R>, Marc<Error>>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: FnOnce(Marc<P::Value>) -> R,
    {
        self.state
            .coalescer
            .coalesce(Self::to_key::<P>(key), || async {
                self.get_internal::<P, _, _>(key, opt, Some)
                    .await
                    .map(Option::flatten)
            })
            .await
            .map(|opt_v| opt_v.map(mapper))
    }

    async fn get_internal<P, R, F>(
        &self,
        key: &P::Key,
        opt: &KvGetOptions,
        mapper: F,
    ) -> Result<Option<R>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        F: FnOnce(Marc<P::Value>) -> R,
    {
        let key = Self::to_key::<P>(key);
        tracing::debug!(key, "GET");
        match self.state.cache.read().await.get::<P>(&key) {
            cache::CacheResult::Miss => {}
            cache::CacheResult::Hit(t) => return Ok(t.map(mapper)),
            cache::CacheResult::MismatchedType => {
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
                .bearer_auth(self.config.auth_token.as_str())
                .send()
                .await?;
            if resp.status() == StatusCode::NOT_FOUND {
                if opt.cache_not_found {
                    self.state.cache.write().await.put::<P>(key, None);
                }
                Ok(None)
            } else {
                let resp = resp.error_for_status()?;
                let t = Marc::new(resp.json::<P::Value>().await?);
                let r = mapper(t.clone());
                self.state.cache.write().await.put::<P>(key, Some(t));
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
    pub async fn put_internal<P>(
        &self,
        key: &P::Key,
        value: P::Value,
        expiration: Option<Time>,
    ) -> Result<Marc<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        let key = Self::to_key::<P>(key);
        tracing::debug!(key, "PUT");

        let mut request = self
            .http
            .post(self.config.url.join(&key).unwrap())
            .bearer_auth(self.config.auth_token.as_str())
            .body(serde_json::to_vec(&value).unwrap());

        if let Some(expiration) = expiration {
            request = request.header(STORAGE_PROXY_PUT_KV_EXPIRATION, expiration);
        }

        request.send().await?.error_for_status()?;

        let value = Marc::new(value);
        self.state
            .cache
            .write()
            .await
            .put::<P>(key, Some(value.clone()));
        Ok(value)
    }

    pub async fn put_with_expiration<P>(
        &self,
        key: &P::Key,
        value: P::Value,
        expiration: Time,
    ) -> Result<Marc<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        self.put_internal::<P>(key, value, Some(expiration)).await
    }

    pub async fn put<P>(&self, key: &P::Key, value: P::Value) -> Result<Marc<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        self.put_internal::<P>(key, value, None).await
    }

    /// Stores a value in kv if it doesn't already exist.
    ///
    /// If the value already exists, returns the passed in value inside the Ok variant.
    #[tracing::instrument(
        name = "kv_put_if_not_exists",
        skip_all,
        fields(key, prefix = std::any::type_name::<P>()),
    )]
    pub async fn put_if_not_exists_internal<P>(
        &self,
        key: &P::Key,
        value: P::Value,
        expiration: Option<Time>,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        let key = Self::to_key::<P>(key);

        tracing::debug!(key, "PUT if not exists");

        let mut request = self
            .http
            .put(self.config.url.join(&key).unwrap())
            .bearer_auth(self.config.auth_token.as_str())
            .body(serde_json::to_vec(&value).unwrap());

        if let Some(expiration) = expiration {
            request = request.header(STORAGE_PROXY_PUT_KV_EXPIRATION, expiration);
        }

        let response = request.send().await?;

        if response.status() == StatusCode::CONFLICT {
            Ok(Some(value))
        } else {
            response.error_for_status()?;
            self.state
                .cache
                .write()
                .await
                .put::<P>(key, Some(value.into()));
            Ok(None)
        }
    }

    pub async fn put_if_not_exists_with_expiration<P>(
        &self,
        key: &P::Key,
        value: P::Value,
        expiration: Time,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        self.put_if_not_exists_internal::<P>(key, value, Some(expiration))
            .await
    }

    pub async fn put_if_not_exists<P>(
        &self,
        key: &P::Key,
        value: P::Value,
    ) -> Result<Option<P::Value>, Error>
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
        P::Value: Serialize,
    {
        self.put_if_not_exists_internal::<P>(key, value, None).await
    }

    #[tracing::instrument(skip_all, fields(key, prefix = std::any::type_name::<P>()))]
    pub async fn only_cache_put<P>(&self, key: &P::Key, value: P::Value)
    where
        P: KvPrefix,
        P::Key: std::fmt::Debug,
    {
        let key = Self::to_key::<P>(key);
        self.state
            .cache
            .write()
            .await
            .put::<P>(key, Some(value.into()));
    }

    fn to_key<P: KvPrefix>(key: &P::Key) -> String {
        format!("{KV_PATH_PREFIX}/{}/{key}", P::PREFIX)
    }
}
